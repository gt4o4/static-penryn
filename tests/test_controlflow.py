#!/usr/bin/env python3
"""Recovery evidence and its counterexamples, using linked ELF fixtures."""
import io
from array import array
from bisect import bisect_right
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import iced_x86 as ix
from elftools.elf.elffile import ELFFile
from static_penryn import regions
from static_penryn.controlflow import CFGReport, Recovery
from static_penryn.dataflow import Hints
from static_penryn.patch import Site


def present[T](value: T | None) -> T:
    """A value the test relies on: None fails it, as using None would."""
    if value is None:
        raise AssertionError('expected a value, got None')
    return value


BODY = '''
.intel_syntax noprefix
.text
.global _start
.type _start,@function
_start:
.cfi_startproc
cmp edi, 2
ja default_case
lea rdx, [rip + table]
movsxd rax, DWORD PTR [rdx + rdi*4]
add rax, rdx
jmp rax
default_case: ret
case0: nop; ret
case1: mov eax, 1; ret
case2: mov eax, 2; ret
.cfi_endproc
.size _start, .-_start
.section .rodata
table:
.long case0 - table, case1 - table, case2 - table
.section .note.GNU-stack,"",@progbits
'''


class ControlflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which('gcc'):
            raise unittest.SkipTest('gcc is required for linked ELF fixtures')

    def recover(self, source: str = BODY, *, stripped: bool = False,
                max_table_entries: int = 4096) -> tuple[ELFFile, Recovery, CFGReport]:
        with tempfile.TemporaryDirectory(prefix='penryn-cfg-') as temporary:
            path = Path(temporary)
            (path / 'fixture.S').write_text(source)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--build-id=none',
                            '-o', str(path / 'fixture'), str(path / 'fixture.S')],
                           check=True, capture_output=True)
            if stripped:
                subprocess.run(['strip', '--strip-all', str(path / 'fixture')], check=True)
            elf = ELFFile(io.BytesIO((path / 'fixture').read_bytes()))
        recovery = Recovery(elf, max_table_entries=max_table_entries)
        for section in elf.iter_sections():
            if section['sh_flags'] & 4:
                for ins in ix.Decoder(64, section.data(), ip=section['sh_addr']):
                    recovery.feed(ins)
        report = recovery.finish()
        return elf, recovery, report

    def test_guarded_relative_table(self) -> None:
        _, recovery, report = self.recover()
        self.assertEqual(len(report['relative_tables']), 1)
        table = report['relative_tables'][0]
        self.assertEqual(table['entries'], 3)
        self.assertEqual(len(table['targets']), 3)
        self.assertTrue(set(table['targets']) <= recovery.targets)
        # Bound first: in assertEqual's Any context a display infers list[Any].
        ranges = [(table['table'], table['table'] + 12)]
        self.assertEqual(recovery.table_ranges, ranges)
        self.assertFalse(report['indirect_recovery_complete'])
        for address in table['targets']:
            self.assertIsNotNone(recovery.lookup(address))

    def test_exclusive_unsigned_guard(self) -> None:
        _, _, report = self.recover(BODY.replace('cmp edi, 2\nja', 'cmp edi, 3\njae'))
        self.assertEqual(report['relative_tables'][0]['entries'], 3)

    def test_no_guard_signed_guard_or_unbounded_count(self) -> None:
        for source in (BODY.replace('ja default_case', 'nop; nop'),
                       BODY.replace('ja default_case', 'jg default_case'),
                       BODY.replace('cmp edi, 2', 'cmp edi, -1'),
                       BODY.replace('cmp edi, 2', 'cmp edi, 100000')):
            with self.subTest(source=source):
                _, _, report = self.recover(source)
                self.assertFalse(report['relative_tables'])

    def test_index_clobber_and_conditional_entry_are_rejected(self) -> None:
        for instruction in ('mov edi, 100', 'inc edi', 'cmove edi, esi', 'jmp default_case'):
            source = BODY.replace('lea rdx,', instruction + '\nlea rdx,')
            _, _, report = self.recover(source)
            self.assertFalse(report['relative_tables'])

    def test_out_of_range_path_must_leave_dispatch(self) -> None:
        source = BODY.replace('ja default_case', 'ja dispatch').replace('lea rdx,', 'dispatch: lea rdx,')
        _, _, report = self.recover(source)
        self.assertFalse(report['relative_tables'])

    def test_writable_truncated_or_invalid_table_is_not_evidence(self) -> None:
        sources = (BODY.replace('.section .rodata', '.data'),
                   BODY.replace(', case2 - table', ''),
                   BODY.replace('case2 - table', '0x12345678'))
        for source in sources:
            _, _, report = self.recover(source)
            self.assertFalse(report['relative_tables'])

    def test_table_budget_is_enforced(self) -> None:
        _, _, report = self.recover(max_table_entries=2)
        self.assertFalse(report['relative_tables'])

    def test_executable_tables_are_returned_as_protected_data(self) -> None:
        _, recovery, report = self.recover(BODY.replace('.section .rodata', '.text'))
        table = report['relative_tables'][0]
        self.assertTrue(recovery.is_code(table['table']))
        ranges = [(table['table'], table['table'] + 12)]
        self.assertEqual(recovery.table_ranges, ranges)

    def test_section_flag_does_not_override_writable_load(self) -> None:
        elf, _, report = self.recover()
        address = report['relative_tables'][0]['table']
        # recover() parses an in-memory copy; ELFFile types its stream as read/seek/tell.
        assert isinstance(elf.stream, io.BytesIO)
        raw = bytearray(elf.stream.getvalue())
        for index, seg in enumerate(elf.iter_segments()):
            if (seg['p_type'] == 'PT_LOAD'
                    and seg['p_vaddr'] <= address < seg['p_vaddr'] + seg['p_filesz']):
                offset = elf['e_phoff'] + index * elf['e_phentsize'] + 4
                struct.pack_into('<I', raw, offset, seg['p_flags'] | 2)
        elf = ELFFile(io.BytesIO(raw))
        recovery = Recovery(elf)
        for section in elf.iter_sections():
            if section['sh_flags'] & 4:
                for ins in ix.Decoder(64, section.data(), ip=section['sh_addr']):
                    recovery.feed(ins)
        self.assertFalse(recovery.finish()['relative_tables'])

    def test_fde_bounds_survive_stripping(self) -> None:
        elf, recovery, report = self.recover(stripped=True)
        start = elf['e_entry']
        sources = {'eh_frame': 1}
        self.assertEqual(report['function_sources'], sources)
        self.assertEqual(present(recovery.bounds(start))[0], start)
        self.assertIn(start, recovery.targets)
        self.assertNotIn(present(recovery.bounds(start))[1], recovery.targets)

    def test_zero_sized_symbol_protects_entry_without_inventing_bounds(self) -> None:
        source = BODY.replace('.cfi_startproc', '').replace('.cfi_endproc', '')
        source = source.replace('.size _start, .-_start', '')
        elf, recovery, _ = self.recover(source)
        self.assertIn(elf['e_entry'], recovery.targets)
        self.assertIsNone(recovery.bounds(elf['e_entry']))
        self.assertIsNotNone(recovery.block_bounds(elf['e_entry']))

    def test_block_bounds_work_without_symbols_or_fdes(self) -> None:
        source = BODY.replace('.cfi_startproc', '').replace('.cfi_endproc', '')
        elf, recovery, _ = self.recover(source, stripped=True)
        start = elf['e_entry']
        self.assertIsNone(recovery.bounds(start))
        first = present(recovery.lookup(start))
        branch = present(recovery.lookup(first.next_ip))
        self.assertEqual(recovery.block_bounds(start), (start, branch.next_ip))
        self.assertEqual(present(recovery.block_bounds(branch.next_ip))[0], branch.next_ip)

    def test_direct_targets_and_call_returns_bound_blocks(self) -> None:
        source = BODY.replace('cmp edi, 2', 'call local_helper\ncmp edi, 2')
        source = source.replace('default_case: ret', 'local_helper: ret\ndefault_case: ret')
        elf, recovery, _ = self.recover(source)
        first = present(recovery.lookup(elf['e_entry']))
        self.assertEqual(recovery.block_bounds(first.ip), (first.ip, first.next_ip))
        self.assertEqual(present(recovery.block_bounds(first.near_branch_target))[0], first.near_branch_target)

    def test_block_lookup_never_admits_unknown_instruction_starts(self) -> None:
        elf, recovery, _ = self.recover()
        self.assertIsNone(recovery.block_bounds(elf['e_entry'] + 1))
        self.assertIsNone(recovery.block_bounds(0))

    def test_terminator_runs_keep_explicit_entries_and_grouping_results(self) -> None:
        source = '''.intel_syntax noprefix
.text
.global _start
_start:
cmp eax,0
je .Linside
jmp .Lhot
.fill 64,1,0xcc
.Linside:
.fill 64,1,0xcc
.Lhot:
mov esi,1
popcnt rax,rbx
mov rcx,rax
popcnt r8,rcx
ret
.section .note.GNU-stack,"",@progbits
'''
        elf, recovery, report = self.recover(source, stripped=True)
        section = present(elf.get_section_by_name('.text'))
        instructions = list(ix.Decoder(64, section.data(), ip=section['sh_addr']))
        conditional = next(i for i in instructions if i.flow_control == ix.FlowControl.CONDITIONAL_BRANCH)
        jump = next(i for i in instructions if i.flow_control == ix.FlowControl.UNCONDITIONAL_BRANCH)
        inside, hot = conditional.near_branch_target, jump.near_branch_target
        self.assertLess(report['block_leaders'], 10)
        self.assertIsInstance(recovery._ordered_leaders, array)
        self.assertEqual(recovery._ordered_leaders.itemsize, 8)
        self.assertFalse(recovery._leaders, 'mutable leader integers should be released after freezing')
        self.assertIn(inside, recovery._ordered_leaders)
        self.assertEqual(recovery.block_bounds(inside + 7), (inside, hot))
        self.assertEqual(present(recovery.lookup(inside + 7)).mnemonic, ix.Mnemonic.INT3)
        self.assertEqual(present(recovery.block_bounds(hot))[0], hot)

        # Compare grouping with the former dense per-terminator leader set.
        # Coalescing affects padding only; original instruction boundaries and
        # explicit direct targets still prevent crossing a real interior entry.
        sites = [Site([i], i.ip - section['sh_addr'], i.next_ip, hints=[Hints()])
                 for i in instructions if i.mnemonic == ix.Mnemonic.POPCNT]
        targets = {conditional.near_branch_target, jump.near_branch_target}
        dense = sorted(set(recovery._ordered_leaders) |
                       {i.next_ip for i in instructions if i.flow_control != ix.FlowControl.NEXT})

        class DenseRecovery:
            bounds = recovery.bounds
            lookup = recovery.lookup

            def block_bounds(self, address: int) -> tuple[int, int]:
                index = bisect_right(dense, address) - 1
                return dense[index], dense[index + 1]

        for protected in (targets, targets | {sites[1].ip}):
            old = regions.group(sites, protected, [], DenseRecovery())
            new = regions.group(sites, protected, [], recovery)
            new_spans, old_spans = [(s.ip, s.end) for s in new], [(s.ip, s.end) for s in old]
            self.assertEqual(new_spans, old_spans)
        self.assertEqual(len(regions.group(sites, targets, [], recovery)), 1)

    def test_frozen_leaders_can_accept_later_function_metadata(self) -> None:
        elf, recovery, _ = self.recover()
        original = list(recovery._ordered_leaders)
        start = elf['e_entry']
        first = present(recovery.lookup(start))
        recovery.add_functions([(first.next_ip, present(recovery.bounds(start))[1], 'late')], source='test')
        recovery.finish()
        leaders, expected = list(recovery._ordered_leaders), sorted(set(original) | {first.next_ip})
        self.assertEqual(leaders, expected)
        self.assertFalse(recovery._leaders)

    def test_overlapping_metadata_uses_intersection(self) -> None:
        elf, recovery, _ = self.recover()
        start = elf['e_entry']
        _, end = present(recovery.bounds(start))
        recovery.add_functions([(start + 2, end - 1, 'inner')], source='test')
        self.assertEqual(recovery.bounds(start + 3), (start + 2, end - 1))
        self.assertIsNone(recovery.bounds(end))

    def test_verified_starts_do_not_admit_middle_of_instruction(self) -> None:
        elf, recovery, report = self.recover()
        start = elf['e_entry']
        self.assertIsNotNone(recovery.lookup(start))
        self.assertIsNone(recovery.lookup(start + 1))
        self.assertIsNone(recovery.lookup(0))
        text = present(elf.get_section_by_name('.text'))
        self.assertEqual(report['instruction_boundary_bytes'], (text['sh_size'] + 7) // 8)

    def test_scan_must_finish_before_lookup(self) -> None:
        elf, _, _ = self.recover()
        recovery = Recovery(elf)
        with self.assertRaisesRegex(ValueError, 'finish'):
            recovery.lookup(elf['e_entry'])

    def test_malformed_fde_is_not_silently_ignored(self) -> None:
        elf, _, _ = self.recover()
        frame = present(elf.get_section_by_name('.eh_frame'))
        assert isinstance(elf.stream, io.BytesIO)
        raw = bytearray(elf.stream.getvalue())
        offset = frame['sh_offset']
        raw[offset:offset + 12] = b'\xff' * 12
        with self.assertRaisesRegex(ValueError, '.eh_frame'):
            Recovery(ELFFile(io.BytesIO(raw)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
