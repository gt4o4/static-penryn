#!/usr/bin/env python3
"""Structural and end-to-end regression checks for the experimental patcher.

Run with the patcher's Python dependencies, cc/ld and qemu-x86_64 on PATH:
    python test_patch.py
These fixtures execute under a Penryn CPU model without an emulator preload.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder

import patch
from elfcheck import validate_elf


HERE = Path(__file__).resolve().parent


class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Negative controls deliberately SIGILL. Set a per-process limit here
        # so every compiler, patcher and QEMU descendant inherits it, including
        # failures before the guest CPU begins executing.
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        for command in ("cc", "ld", "qemu-x86_64"):
            if not shutil.which(command):
                raise RuntimeError(f"required test dependency missing: {command}")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test-static-penryn-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)

    def fixture(self, body, *, pie=False, extra="", link_extra=()):
        source = self.work / "fixture.S"
        source.write_text(
            ".intel_syntax noprefix\n.text\n.global _start\n_start:\n"
            + body
            + "\nmov eax,60\nxor edi,edi\nsyscall\n"
            + ".Lfail:\nmov eax,60\nmov edi,1\nsyscall\n"
            + extra
            + '\n.section .note.GNU-stack,"",@progbits\n'
        )
        binary = self.work / "input"
        # These syscall-only fixtures need no dynamic loader. In particular,
        # this keeps system-wide preload libraries out of the negative control.
        link_flags = ["-pie", "-Wl,--no-dynamic-linker"] if pie else ["-no-pie"]
        subprocess.run(
            ["cc", "-nostdlib", "-Wl,--build-id=none", *link_flags, *link_extra,
             "-o", str(binary), str(source)],
            check=True, capture_output=True,
        )
        return binary

    def elf(self, binary):
        return ELFFile(io.BytesIO(binary.read_bytes()))

    def mutate(self, binary, fmt, offset, *values):
        data = bytearray(binary.read_bytes())
        struct.pack_into(fmt, data, offset, *values)
        binary.write_bytes(data)

    def section_header(self, binary, name):
        elf = self.elf(binary)
        return elf['e_shoff'] + elf.get_section_index(name) * 64

    def check_elf(self, binary):
        data = binary.read_bytes()
        return validate_elf(data, ELFFile(io.BytesIO(data)))

    def invoke(self, binary, *flags, success=True):
        before = binary.read_bytes()
        output = self.work / "output"
        result = subprocess.run(
            [sys.executable, str(HERE / "patch.py"), str(binary), str(output), *flags],
            capture_output=True, text=True,
        )
        self.assertEqual(binary.read_bytes(), before, "source ELF changed")
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return output
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(output.exists(), "failed patch unexpectedly wrote an output")
        return result

    def penryn(self, binary, *, success=True):
        env = os.environ.copy()
        env.pop('LD_PRELOAD', None)
        env.pop('LD_LIBRARY_PATH', None)
        result = subprocess.run(
            ["qemu-x86_64", "-cpu", "Penryn", "-U", "LD_PRELOAD",
             "-U", "LD_LIBRARY_PATH", str(binary)],
            capture_output=True, text=True, timeout=10, env=env,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertEqual(result.returncode, -signal.SIGILL,
                             "negative control must specifically die of SIGILL: " + result.stderr)

    def test_exec_and_pie_program_headers(self):
        for pie in (False, True):
            with self.subTest(pie=pie):
                # A five-byte site needs no stolen instruction or padding cave.
                binary = self.fixture("mov ebx,255\npopcnt rax,rbx\ncmp eax,8\njne .Lfail", pie=pie)
                original = binary.read_bytes()
                self.penryn(binary, success=False)
                output = self.invoke(binary)
                result = output.read_bytes()
                self.penryn(output)
                old = ELFFile(io.BytesIO(original))
                new = ELFFile(io.BytesIO(result))
                old_loads = [dict(s.header) for s in old.iter_segments() if s['p_type'] == 'PT_LOAD']
                new_loads = [dict(s.header) for s in new.iter_segments() if s['p_type'] == 'PT_LOAD']
                self.assertEqual(new_loads[:-1], old_loads)
                added = new_loads[-1]
                self.assertEqual(added['p_flags'], 5)
                self.assertEqual(new['e_phnum'], old['e_phnum'] + 1)
                self.assertEqual(new['e_phoff'], added['p_offset'])
                for seg in new.iter_segments():
                    if seg['p_type'] == 'PT_PHDR':
                        self.assertEqual(seg['p_vaddr'], added['p_vaddr'])
                        self.assertEqual(seg['p_filesz'], new['e_phnum'] * 56)
                code = new.get_section_by_name('.penryn')
                self.assertIsNotNone(code)
                self.assertEqual(code['sh_flags'], 6)
                self.assertEqual(patch.scan(new)[0], [])
                report = json.loads(Path(str(output) + '.json').read_text())
                self.assertEqual(report['input_sha256'], hashlib.sha256(original).hexdigest())
                self.assertEqual(report['output_sha256'], hashlib.sha256(result).hexdigest())
                output.unlink()
                Path(str(output) + '.json').unlink()

    def test_short_site_requires_explicit_relocation(self):
        binary = self.fixture("mov ebx,255\npopcnt eax,ebx\ncmp eax,8\njne .Lfail")
        result = self.invoke(binary, success=False)
        self.assertIn("four-byte site", result.stderr)

    def test_short_sites_reserve_distinct_caves(self):
        binary = self.fixture(
            "mov ebx,255\njmp .Lbody\n.fill 20,1,0xcc\n.Lbody:\n"
            "popcnt eax,ebx\ncmp eax,8\njne .Lfail\n"
            "popcnt ecx,ebx\ncmp ecx,8\njne .Lfail"
        )
        output = self.invoke(binary)
        self.penryn(output)
        report = json.loads(Path(str(output) + '.json').read_text())
        self.assertEqual(report['short_jumps'], 2)
        caves = [int(item['cave'], 16) for item in report['patches']]
        self.assertGreaterEqual(abs(caves[0] - caves[1]), 5)

    def test_entry_earlier_in_padding_protects_whole_cave(self):
        binary = self.fixture(
            "jmp .Lbody\n.global padding_entry\npadding_entry:\n"
            ".fill 160,1,0x90\n.Lbody:\npopcnt eax,ebx\nmov edi,eax"
        )
        result = self.invoke(binary, success=False)
        self.assertIn("four-byte site", result.stderr)

    def test_resumable_int3_fallthrough_is_not_a_cave(self):
        # A SIGTRAP handler may return to the NOPs after INT3. They are live
        # fall-through bytes, unlike padding after an unconditional branch.
        binary = self.fixture('int3\n.fill 24,1,0x90\npopcnt eax,ebx\nmov edi,eax')
        _, _, caves = patch.scan(self.elf(binary))
        self.assertEqual(caves, [])
        result = self.invoke(binary, success=False)
        self.assertIn('four-byte site', result.stderr)

    def test_rip_relative_following_instruction_relocated(self):
        binary = self.fixture(
            "mov ebx,255\npopcnt eax,ebx\nmov edi,DWORD PTR [rip + expected]\n"
            "cmp eax,edi\njne .Lfail",
            pie=True, extra="\n.section .rodata\nexpected:\n.long 8\n",
        )
        output = self.invoke(binary, "--allow-relocate")
        self.penryn(output)
        report = json.loads(Path(str(output) + '.json').read_text())
        self.assertEqual(report['relocated_following'], 1)
        self.assertIn('mov', report['patches'][0]['tail'])

    def test_far_rip_relative_tail_cannot_become_eip_relative(self):
        # iced can make this encodable with address-size 32. That silently
        # truncates a PIE's runtime load bias, even though both static targets
        # print as 0x1000. Refuse it rather than publishing an invalid PIE.
        instruction = Decoder(64, bytes.fromhex('8b3dfafffeff'), ip=0x11000).decode()
        self.assertEqual(instruction.ip_rel_memory_address, 0x1000)
        with self.assertRaises(ValueError):
            patch._relocate_tail(instruction, 0x80010000)

    def test_original_eip_relative_tail_refused(self):
        instruction = Decoder(64, bytes.fromhex('678b3d00000000'), ip=0x11000).decode()
        self.assertTrue(instruction.is_ip_rel_memory_operand)
        with self.assertRaises(ValueError):
            patch._relocate_tail(instruction, 0x12000)

    def test_helper_alignment_cannot_shift_requested_payload_address(self):
        # The C string core brings 32-byte-aligned rodata. An implicit output
        # section address let ld shift every stub by 16 bytes when the ELF's
        # program-header count placed the payload only on a 16-byte boundary.
        ins = Decoder(64, bytes.fromhex('66 0f 3a 61 c1 00'), ip=0x402000).decode()
        site = patch.Site([ins], 0, ins.next_ip)
        address = 0x401010
        work = self.work / 'helpers'
        work.mkdir()
        core = HERE.parent / 'opemu-linux/core'
        blob, symbols = patch.build_stubs([site], address, work, core)
        self.assertEqual(symbols['site_0'], address)
        elf = ELFFile(io.BytesIO((work / 'stubs.elf').read_bytes()))
        section = elf.get_section_by_name('.patch')
        self.assertEqual(section['sh_addr'], address)
        self.assertEqual(section.data(), blob)

    def test_string_helper_executes_on_penryn(self):
        binary = self.fixture(
            "movdqu xmm0,[rip + needle]\nmovdqu xmm1,[rip + hay]\n"
            "mov eax,1\nmov edx,3\npcmpestri xmm0,xmm1,0\n"
            "cmp ecx,1\njne .Lfail",
            pie=True,
            extra='\n.section .rodata\n.p2align 4\nneedle:\n.ascii "b"\n'
                  '.zero 15\nhay:\n.ascii "abc"\n.zero 13\n',
        )
        self.penryn(binary, success=False)
        output = self.invoke(binary)
        self.penryn(output)

    def test_following_instruction_direct_entry_refused(self):
        binary = self.fixture("jmp .Lentry\npopcnt eax,ebx\n.Lentry:\nmov edi,eax")
        result = self.invoke(binary, "--allow-relocate", success=False)
        self.assertIn("entry point", result.stderr)

    def test_following_conditional_branch_relocated(self):
        binary = self.fixture(
            "xor ebx,ebx\npopcnt eax,ebx\njz .Lsuccess\njmp .Lfail\n.Lsuccess:"
        )
        output = self.invoke(binary, "--allow-relocate")
        self.penryn(output)
        report = json.loads(Path(str(output) + '.json').read_text())
        self.assertEqual(report['relocated_following'], 1)

    def test_following_instruction_symbol_entry_refused(self):
        binary = self.fixture("popcnt eax,ebx\n.global following\nfollowing:\nmov edi,eax")
        result = self.invoke(binary, "--allow-relocate", success=False)
        self.assertIn("entry point", result.stderr)

    def test_entry_inside_replaced_instruction_refused(self):
        binary = self.fixture(
            "jmp .Loverlap\n.byte 0xf3\n.Loverlap:\n.byte 0x48,0x0f,0xb8,0xc3"
        )
        result = self.invoke(binary, success=False)
        self.assertIn('overlapping instruction entry', result.stderr)

    def test_following_call_refused(self):
        binary = self.fixture("popcnt eax,ebx\ncall .Lcallee", extra="\n.text\n.Lcallee:\nret\n")
        result = self.invoke(binary, "--allow-relocate", success=False)
        self.assertIn("call", result.stderr)

    def test_report_cannot_replace_input(self):
        binary = self.fixture("popcnt rax,rbx")
        self.invoke(binary, "--report", str(binary), success=False)

    def test_report_symlink_cannot_replace_input(self):
        binary = self.fixture("popcnt rax,rbx")
        report = self.work / 'report.json'
        report.symlink_to(binary)
        self.invoke(binary, "--report", str(report), success=False)

    def test_existing_output_refused(self):
        binary = self.fixture("popcnt rax,rbx")
        output = self.work / 'output'
        output.write_bytes(b'keep existing output')
        result = subprocess.run(
            [sys.executable, str(HERE / 'patch.py'), str(binary), str(output)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b'keep existing output')

    def test_mismatched_executable_file_mapping_refused(self):
        binary = self.fixture('popcnt rax,rbx')
        text = self.elf(binary).get_section_by_name('.text')
        self.mutate(binary, '<Q', self.section_header(binary, '.text') + 24,
                    text['sh_offset'] + 1)
        with self.assertRaisesRegex(ValueError, 'file mapping'):
            self.check_elf(binary)
        self.invoke(binary, success=False)

    def test_executable_section_outside_rx_load_refused(self):
        binary = self.fixture('popcnt rax,rbx')
        elf = self.elf(binary)
        index = next(i for i, s in enumerate(elf.iter_segments())
                     if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1)
        self.mutate(binary, '<I', elf['e_phoff'] + index * 56 + 4, 4)
        with self.assertRaisesRegex(ValueError, 'executable PT_LOAD'):
            self.check_elf(binary)
        self.invoke(binary, success=False)

    def test_unallocated_executable_section_refused(self):
        binary = self.fixture('popcnt rax,rbx')
        self.mutate(binary, '<Q', self.section_header(binary, '.text') + 8, 4)
        with self.assertRaisesRegex(ValueError, 'allocated'):
            self.check_elf(binary)

    def test_truncated_section_header_table_refused(self):
        binary = self.fixture('popcnt rax,rbx')
        binary.write_bytes(binary.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, 'section-header table'):
            self.check_elf(binary)

    def test_load_filesz_cannot_exceed_memsz(self):
        binary = self.fixture('popcnt rax,rbx')
        elf = self.elf(binary)
        index = next(i for i, s in enumerate(elf.iter_segments()) if s['p_type'] == 'PT_LOAD')
        self.mutate(binary, '<Q', elf['e_phoff'] + index * 56 + 40, 0)
        with self.assertRaisesRegex(ValueError, 'file size exceeds'):
            self.check_elf(binary)

    def test_code_file_bytes_cannot_have_another_load_alias(self):
        binary = self.fixture('popcnt rax,rbx', extra='\n.section .rodata\n.fill 32,1,0\n')
        elf = self.elf(binary)
        code = elf.get_section_by_name('.text')
        index, segment = next((i, s) for i, s in enumerate(elf.iter_segments())
                              if s['p_type'] == 'PT_LOAD' and not s['p_flags'] & 1
                              and s['p_vaddr'] > code['sh_addr'])
        # Preserve distinct virtual ranges and page congruence, but make a
        # second read-only mapping alias the first instruction's file bytes.
        self.mutate(binary, '<Q', elf['e_phoff'] + index * 56 + 8, code['sh_offset'])
        self.mutate(binary, '<Q', elf['e_phoff'] + index * 56 + 32,
                    min(code['sh_size'], segment['p_memsz']))
        with self.assertRaisesRegex(ValueError, 'aliased PT_LOAD file bytes'):
            self.check_elf(binary)
        result = self.invoke(binary, success=False)
        self.assertIn('aliased PT_LOAD file bytes', result.stderr)

    def test_stripped_exec_and_pie_still_patch(self):
        for pie in (False, True):
            with self.subTest(pie=pie):
                binary = self.fixture('mov ebx,255\npopcnt rax,rbx\ncmp eax,8\njne .Lfail', pie=pie)
                subprocess.run(['strip', '--strip-all', str(binary)], check=True)
                self.assertIsNone(self.elf(binary).get_section_by_name('.symtab'))
                output = self.invoke(binary)
                self.penryn(output)
                output.unlink()
                Path(str(output) + '.json').unlink()

    def test_stripped_static_pointer_protects_following_entry(self):
        binary = self.fixture('popcnt eax,ebx\n.Lentry:\nmov edi,eax',
                              extra='\n.data\n.p2align 3\n.quad .Lentry\n')
        subprocess.run(['strip', '--strip-all', str(binary)], check=True)
        entry = self.elf(binary).get_section_by_name('.text')['sh_addr'] + 4
        self.assertIn(entry, self.check_elf(binary)['pointer_targets'])
        result = self.invoke(binary, '--allow-relocate', success=False)
        self.assertIn('entry point', result.stderr)

    def test_stripped_immediate_pointer_protects_following_entry(self):
        for instruction in ('movabs rdi, OFFSET FLAT:.Lentry', 'push OFFSET FLAT:.Lentry'):
            with self.subTest(instruction=instruction):
                binary = self.fixture(instruction + '\npopcnt eax,ebx\n.Lentry:\nmov edi,eax')
                subprocess.run(['strip', '--strip-all', str(binary)], check=True)
                result = self.invoke(binary, '--allow-relocate', success=False)
                self.assertIn('entry point', result.stderr)

    def test_dynamic_relocation_cannot_overwrite_patched_instruction(self):
        binary = self.fixture('popcnt rax,rbx', pie=True,
                              extra='\n.data\n.p2align 3\n.quad _start\n')
        elf = self.elf(binary)
        relocations = elf.get_section_by_name('.rela.dyn')
        entry = elf['e_entry']
        self.mutate(binary, '<Q', relocations['sh_offset'], entry)
        # Loader relocations come from PT_DYNAMIC even if the section table
        # conceals the relocation section from a section-only scanner.
        self.mutate(binary, '<I', self.section_header(binary, '.rela.dyn') + 4, 1)
        self.assertIn((entry, entry + 8), self.check_elf(binary)['relocation_ranges'])
        result = self.invoke(binary, success=False)
        self.assertIn('relocation', result.stderr.lower())

    def test_relr_recovers_stripped_pointer_entries(self):
        binary = self.fixture('popcnt eax,ebx\n.Lentry:\nmov edi,eax', pie=True,
                              extra='\n.data\n.p2align 3\n.quad .Lentry\n.quad _start\n.quad .Lentry\n',
                              link_extra=('-Wl,-z,pack-relative-relocs',))
        subprocess.run(['strip', '--strip-all', str(binary)], check=True)
        elf = self.elf(binary)
        relr = elf.get_section_by_name('.relr.dyn')
        self.assertIsNotNone(relr, 'binutils must support DT_RELR for this regression')
        self.assertGreater(relr['sh_size'], 8, 'fixture must exercise a RELR bitmap')
        metadata = self.check_elf(binary)
        self.assertIn(elf['e_entry'] + 4, metadata['pointer_targets'])
        data = elf.get_section_by_name('.data')
        self.assertIn((data['sh_addr'], data['sh_addr'] + 24), metadata['relocation_ranges'])
        result = self.invoke(binary, '--allow-relocate', success=False)
        self.assertIn('entry point', result.stderr)

    def test_exec_load_gaps_reported_without_decoding_data(self):
        binary = self.fixture('popcnt rax,rbx', link_extra=('-Wl,-z,noseparate-code',))
        metadata = self.check_elf(binary)
        self.assertTrue(metadata['uncovered_executable_ranges'])
        output = self.invoke(binary)
        self.penryn(output)

    def test_erased_executable_section_flag_refused(self):
        binary = self.fixture('popcnt rax,rbx')
        self.mutate(binary, '<Q', self.section_header(binary, '.text') + 8, 2)
        with self.assertRaisesRegex(ValueError, 'no file-backed executable sections'):
            self.check_elf(binary)
        self.invoke(binary, success=False)

    def test_sectionless_input_refused_clearly(self):
        binary = self.fixture('popcnt rax,rbx')
        self.mutate(binary, '<Q', 40, 0)
        self.mutate(binary, '<HHH', 58, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, 'section headers'):
            self.check_elf(binary)
        result = self.invoke(binary, success=False)
        self.assertIn('section headers', result.stderr)

    def test_dataflow_and_full_preservation_both_execute(self):
        binary = self.fixture(
            'mov ebx,255\npopcnt rax,rbx\nmov edx,123\n'
            'cmp eax,8\njne .Lfail\ncmp edx,123\njne .Lfail'
        )
        reports = []
        for enabled in (True, False):
            with self.subTest(dataflow=enabled):
                output = self.invoke(binary, *(() if enabled else ('--no-dataflow',)))
                self.penryn(output)
                report = json.loads(Path(str(output) + '.json').read_text())
                self.assertEqual(report['dataflow_enabled'], enabled)
                if enabled:
                    self.assertGreater(report['flags_proven_dead'], 0)
                    self.assertGreater(report['sites_with_dead_gprs'], 0)
                else:
                    self.assertEqual(report['flags_proven_dead'], 0)
                    self.assertEqual(report['sites_with_dead_gprs'], 0)
                reports.append(report)
                output.unlink()
                Path(str(output) + '.json').unlink()
        self.assertLess(reports[0]['added_code_bytes'], reports[1]['added_code_bytes'])

    def test_crc_table_is_noncode_and_runs_on_penryn(self):
        binary = self.fixture(
            'mov eax,-1\ncrc32 rax,QWORD PTR [rip + payload]\n'
            'crc32 eax,BYTE PTR [rip + payload + 8]\nnot eax\n'
            'cmp eax,0xe3069283\njne .Lfail', pie=True,
            extra='\n.section .rodata\npayload:\n.ascii "123456789"\n',
        )
        self.penryn(binary, success=False)
        output = self.invoke(binary)
        self.penryn(output)
        elf = self.elf(output)
        table = elf.get_section_by_name('.penryn.rodata')
        self.assertIsNotNone(table)
        self.assertEqual(table['sh_flags'], 2)
        self.assertGreater(table['sh_size'], 0)
        self.assertEqual(patch.scan(elf, inventory_only=True)[0], [])
        # A supported opcode stored as table data must not become a false
        # residual-instruction failure. Execute the unmodified table above.
        data = bytearray(output.read_bytes())
        data[table['sh_offset']:table['sh_offset'] + 5] = bytes.fromhex('f3480fb8c3')
        self.assertEqual(patch.scan(ELFFile(io.BytesIO(data)), inventory_only=True)[0], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
