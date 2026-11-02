#!/usr/bin/env python3
"""Profiler counter, PIE/interpreter, identity and perf mapping regressions."""
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from static_penryn import profile as profiler
from static_penryn import workloads
from static_penryn.checked import as_list, as_object, as_str, load_json


def segment(*, p_vaddr: int, p_offset: int, p_filesz: int, p_flags: int) -> profiler.Load:
    """A complete PT_LOAD header. mmap_bias reads p_flags & 1, p_vaddr, p_offset
    and p_filesz; the other fields are those of a plain file mapping."""
    return profiler.Load(p_type='PT_LOAD', p_flags=p_flags, p_offset=p_offset, p_vaddr=p_vaddr,
                         p_paddr=p_vaddr, p_filesz=p_filesz, p_memsz=p_filesz, p_align=0x1000)


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix='penryn-profile-test-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def fixture(self, pie: bool = False) -> tuple[Path, Path]:
        source = self.work / 'input.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov ecx, 1000
    xor edi, edi
    jmp probe
.section .penryn,"ax",@progbits
.global probe, increment_end, probe_end
probe:
    add edi, 1
increment_end:
    dec ecx
    jnz probe
probe_end:
    cmp edi, 1000
    jne failed
    xor edi, edi
    mov eax, 60
    syscall
failed:
    mov edi, 1
    mov eax, 60
    syscall
.section .note.GNU-stack,"",@progbits
''')
        binary = self.work / 'input'
        # Keep the compiler's matching libc in DT_NEEDED/RUNPATH: this host's
        # /etc/ld.so.preload otherwise pulls a different libc into empty PIEs.
        subprocess.run(['cc', '-nostdlib', '-pie' if pie else '-no-pie',
                        *(['-Wl,--no-as-needed', '-lc'] if pie else []),
                        '-o', str(binary), str(source)], capture_output=True, check=True)
        data = binary.read_bytes()
        elf = ELFFile(io.BytesIO(data))
        symtab = elf.get_section_by_name('.symtab')
        assert isinstance(symtab, SymbolTableSection)
        symbols = {s.name: s['st_value'] for s in symtab.iter_symbols()}
        report = dict(input_sha256='0' * 64, output_sha256=hashlib.sha256(data).hexdigest(),
                      patches=[dict(address=hex(elf['e_entry']), stub=hex(symbols['probe']),
                                    stub_end=hex(symbols['probe_end']), instructions=['fixture add'],
                                    instruction_ranges=[dict(original_address=hex(elf['e_entry']),
                                                             start=hex(symbols['probe']),
                                                             end=hex(symbols['increment_end']), mnemonic='ADD')])])
        report_path = self.work / 'input.json'
        report_path.write_text(json.dumps(report))
        return binary, report_path

    def test_exact_instruction_and_region_counts_exec(self) -> None:
        binary, report = self.fixture()
        model = profiler.load_model(binary, report)
        result = profiler.count(model, [], self.work / 'count')
        site = next(r for r in result['rows'] if r['kind'] == 'site')
        instruction = next(r for r in result['rows'] if r['kind'] == 'instruction')
        self.assertEqual((site['entries'], site['generated_instructions']), (1000, 3000))
        self.assertEqual((instruction['entries'], instruction['generated_instructions']), (1000, 1000))
        self.assertEqual(result['load_bias'], '0x0')

    def test_pie_interpreter_does_not_determine_main_load_bias(self) -> None:
        binary, report = self.fixture(pie=True)
        elf = ELFFile(io.BytesIO(binary.read_bytes()))
        self.assertTrue(any(s['p_type'] == 'PT_INTERP' for s in elf.iter_segments()))
        result = profiler.count(profiler.load_model(binary, report), [], self.work / 'count')
        self.assertEqual(result['site_counts'][0]['executions'], 1000)
        self.assertNotEqual(result['load_bias'], '0x0')

    def test_grouped_four_instruction_counts_remain_stable(self) -> None:
        source = self.work / 'four.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov ecx, 37
    mov rdi, -1
again:
    popcnt rax, rdi
    mov r10, rax
    popcnt rbx, rdi
    add r10, rbx
    popcnt r8, rdi
    mov r11, r8
    popcnt r9, rdi
    sub r11, r9
    dec ecx
    jnz again
    xor edi, edi
    mov eax, 60
    syscall
.section .note.GNU-stack,"",@progbits
''')
        binary = self.work / 'four'
        subprocess.run(['cc', '-nostdlib', '-no-pie', '-o', str(binary), str(source)],
                       capture_output=True, check=True)
        profiles: list[dict[str, int]] = []
        addresses: set[str] | None = None
        for grouped in (False, True):
            output = self.work / ('grouped' if grouped else 'separate')
            rewritten = subprocess.run([sys.executable, '-m', 'static_penryn.patch', str(binary), str(output),
                                        *(['--regions', '--allow-relocate'] if grouped else [])], capture_output=True)
            self.assertEqual(rewritten.returncode, 0, (rewritten.stdout + rewritten.stderr).decode(errors='replace'))
            report = as_object(load_json(Path(str(output) + '.json').read_text()), 'patch report')
            patches = as_list(report['patches'], 'patch report patches')
            if grouped:
                self.assertEqual(len(patches), 1, 'fixture must exercise a real fused region')
            else:
                self.assertEqual(len(patches), 4)
                addresses = {as_str(as_object(p, 'patch report patch')['address'], 'patch address') for p in patches}
            profile = profiler.count(profiler.load_model(output, str(output) + '.json'), [],
                                     self.work / ('count-grouped' if grouped else 'count-separate'))
            assert addresses is not None  # the separate pass, first, sets it
            weights = {r['address']: r['executions'] for r in profile['site_counts'] if r['address'] in addresses}
            self.assertEqual(len(weights), 4)
            executions: set[int] = set(weights.values())
            iterations: set[int] = {37}
            self.assertEqual(executions, iterations)
            self.assertEqual(len(profile['site_counts']), len({r['address'] for r in profile['site_counts']}))
            profiles.append(weights)
        self.assertEqual(profiles[0], profiles[1])

    def test_loader_preinit_before_entry_is_counted(self) -> None:
        # The loader runs PREINIT_ARRAY before _start. entry_seen is an
        # identity check, not a condition for arming counters.
        source=self.work/'preinit.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov edi, 1
    cmp dword ptr [rip + ready], 1
    jne done
    xor edi, edi
done:
    mov eax, 60
    syscall
.section .penryn,"ax",@progbits
.global preinit, preinit_end
preinit:
    mov dword ptr [rip + ready], 1
    ret
preinit_end:
.section .preinit_array,"aw",@preinit_array
    .quad preinit
.bss
ready:
    .zero 4
.section .note.GNU-stack,"",@progbits
''')
        binary=self.work/'preinit'
        subprocess.run(['cc','-nostdlib','-pie','-Wl,--no-as-needed','-lc',
                        '-o',str(binary),str(source)],check=True,capture_output=True)
        data=binary.read_bytes();elf=ELFFile(io.BytesIO(data))
        symtab=elf.get_section_by_name('.symtab');assert isinstance(symtab,SymbolTableSection)
        symbols={s.name:s['st_value'] for s in symtab.iter_symbols()}
        report=dict(input_sha256='0'*64,output_sha256=hashlib.sha256(data).hexdigest(),patches=[],
                    helpers=[dict(name='preinit',start=symbols['preinit'],end=symbols['preinit_end'])])
        path=self.work/'preinit.json';path.write_text(json.dumps(report))
        result=profiler.count(profiler.load_model(binary,path),[],self.work/'count-preinit')
        self.assertEqual((result['rows'][0]['entries'],result['rows'][0]['generated_instructions']),(1,2))

    def test_wrong_binary_rejected_before_execution(self) -> None:
        binary, report = self.fixture()
        with binary.open('ab') as f:
            f.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            profiler.load_model(binary, report)

    def test_inplace_code_counts_without_inventing_instruction_weights(self) -> None:
        binary, path = self.fixture()
        report = as_object(load_json(path.read_text()), 'patch report')
        first = as_object(as_list(report['patches'], 'patch report patches')[0], 'patch report patch')
        start = int(as_str(first['stub'], 'patch stub'), 16)
        end = int(as_str(first['stub_end'], 'patch stub_end'), 16)
        report['patches'] = []
        report['inplace_patches'] = [dict(address=start, evidence=dict(function='counter', code_bytes=end-start))]
        path.write_text(json.dumps(report))
        result = profiler.count(profiler.load_model(binary, path), [], self.work/'count-inplace')
        no_sites: list[profiler.SiteCount] = []
        self.assertEqual(result['site_counts'], no_sites)
        helper = next(row for row in result['rows'] if row['kind'] == 'helper')
        self.assertTrue(helper['inplace'])
        self.assertEqual((helper['entries'], helper['generated_instructions']), (1000, 3000))

    def test_wrong_runtime_bias_does_not_silently_report_zero(self) -> None:
        binary, report = self.fixture()
        model = profiler.load_model(binary, report)
        model['code_start'] -= 4096
        with self.assertRaisesRegex(RuntimeError, 'load-bias'):
            profiler.count(model, [], self.work / 'count')

    def test_reject_overlapping_ranges(self) -> None:
        binary, report_path = self.fixture()
        report = as_object(load_json(report_path.read_text()), 'patch report')
        patches = as_list(report['patches'], 'patch report patches')
        patches.append(patches[0])
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            profiler.load_model(binary, report_path)

    def test_environment_does_not_inherit_credentials(self) -> None:
        unwanted: dict[str, str] = {'ANTHROPIC_API_KEY': 'do-not-copy', 'LD_PRELOAD': 'do-not-copy'}
        with patch.dict(os.environ, unwanted):
            env = profiler.environment(self.work / 'home')
        self.assertNotIn('ANTHROPIC_API_KEY', env)
        self.assertNotIn('LD_PRELOAD', env)
        self.assertEqual(env['SIMDUTF_FORCE_IMPLEMENTATION'], 'westmere')

    def test_perf_overlapping_mappings_preserve_surviving_intervals(self) -> None:
        # Samples are attributed by a row's kind, start and end; offset (here through
        # the LOAD the row's samples arrive by) is only carried along.
        model: profiler.PerfModel = dict(
            binary='/tmp/patched', loads=[segment(p_vaddr=0, p_offset=0, p_filesz=0x4000, p_flags=5),
                                          segment(p_vaddr=0x3000, p_offset=0x5000, p_filesz=0x1000, p_flags=5)],
            rows=[dict(kind='site', start=0x1000, end=0x1010, offset=0x1000, original_address='0x400'),
                  dict(kind='helper', start=0x3000, end=0x3010, offset=0x5000, name='shared')])
        script = '''
 10/10 1.0: cpu-clock:u: 601001
 10/10 2.0: PERF_RECORD_MMAP2 10/10: [0x600000(0x4000) @ 0 <abcd>]: r-xp /tmp/patched
 10/10 2.1: PERF_RECORD_MMAP2 10/10: [0x603000(0x1000) @ 0x5000 <abcd>]: r-xp /tmp/patched
 10/10 3.0: cpu-clock:u: 601001
 10/11 3.1: cpu-clock:u: 603001
 10/10 3.2: cpu-clock:u: 602001
 10/10 3.3: cpu-clock:u: 700001
 10/10 4.0: PERF_RECORD_MMAP2 10/10: [0x601000(0x1000) @ 0 <dcba>]: r-xp /tmp/unrelated
 10/10 4.1: cpu-clock:u: 601001
'''
        result = profiler.parse_perf(model, script)
        self.assertEqual(result['total_samples'], 5)
        self.assertEqual(result['executable_outside_patch_samples'], 1)
        self.assertEqual(result['other_mapping_samples'], 2)
        samples: list[int] = [r['samples'] for r in result['rows']]
        one_each: list[int] = [1, 1]
        self.assertEqual(samples, one_each)
        # A different file with the same basename (or a case variation) must
        # remove an overwritten mapping without being attributed to this ELF.
        for other in ('/another/patched', '/tmp/Patched'):
            self.assertEqual(profiler.parse_perf(model, script.replace('/tmp/unrelated', other)), result)

    def test_perf_bad_format_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, 'sample format'):
            profiler.parse_perf(dict(binary='/tmp/b', rows=[], loads=[]), 'unrecognized cpu-clock:u sample')
        with self.assertRaisesRegex(ValueError, 'no matching executable'):
            profiler.parse_perf(dict(binary='/tmp/b', rows=[], loads=[]), '10/10 1.0: cpu-clock:u: 4000')

    def test_perf_shared_file_page_resolves_only_executable_segment(self) -> None:
        # Claude's read-only and executable LOADs share a file page while
        # having different virtual addresses; MMAP records are executable.
        model: profiler.Layout = dict(loads=[segment(p_vaddr=0x200000, p_offset=0x1000, p_filesz=0x1721a0c, p_flags=4),
                                            segment(p_vaddr=0x1922c00, p_offset=0x1722c00, p_filesz=0x3ae5200, p_flags=5)])
        self.assertEqual(profiler.mmap_bias(model, 0x1922000, 0x1722000), 0)

    def test_fixture_determinism_and_independent_search_output(self) -> None:
        first, expected1 = workloads.fixture(self.work / 'one', files=9, lines=17)
        second, expected2 = workloads.fixture(self.work / 'two', files=9, lines=17)
        self.assertEqual(first, second)
        self.assertEqual(expected1['rg-search'].count(b'\n'), first['matching_lines'])
        self.assertEqual(expected1['rg-files'].count(b'\n'), 9)
        self.assertEqual(expected1['rg-utf8'].count(b':17\n'), 9)
        self.assertEqual(expected1['rg-search'].replace(b'/one/', b'/two/'), expected2['rg-search'])


if __name__ == '__main__':
    unittest.main()
