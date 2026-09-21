#!/usr/bin/env python3
"""Native frame proofs and counterexamples from linked, decoded CFG fixtures."""
import io
import json
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import iced_x86 as ix
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import controlflow
from native_frames import Gap, Recovery


# Claude 2.1.278 input SHA256 b03ee84fce76643c414d868815ad3b74bfa856dda17bc0eb0da39d982213c1f7.
# Exact 825-byte native routine at 0x3a2d8e0, including every predecessor and
# epilogue of the four profile-hot POPCNTs. Internal relative branches retain
# their destinations when this fixture is linked at a different address.
CLAUDE_HOT = bytes.fromhex(
    '554889e5534839d6731c4989d14929f14983f90f77174983f904734731c04889f1e9ca00000031c0e9090300004889f14883'
    'e1f04883c1104c8d56014c39d14c0f47d1660f6ec7660fefc94929f24983fa040f83b10000004531c04889f0e93d01000045'
    '89c84183e00c4a8d0c06400fb6c7660f6ec8660f60c9660fefc031c0660f6f1d48bc91fc660fefd20f1f4000440fb7140666'
    '410f6ee2440fb754060266410f6eea660f74e1660f3832e4660fdbe3660fd4d4660f74e9660f3832e5660fdbe3660fd4c448'
    '83c0044939c075c0660fd4c2660f70c8ee660fd4c866480f7ec84d39c10f844b0200000f1f44000031f6403839400f94c648'
    '01f048ffc14839d175ece92d0200004d89d34983e3fc4a8d041e440fb6c766410f6ed8660f60db660fefd24531c0660f6f2d'
    'a0bb91fc660fefe4662e0f1f8400000000006690420fb71c06660f6ef3420fb75c0602660f6efb660f74f3660f3832f6660f'
    'dbf5660fd4e6660f74fb660f3832f7660fdbf5660fd4d64983c0044d39c375c2660fd4d4660f70daee660fd4da66490f7ed8'
    '4d39da741f662e0f1f8400000000009031f6403838400f94c64901f048ffc04839c872ec660f3800c14983f940400f93c648'
    '8d42c04839c1410f96c14120f14180f9017568662e0f1f84000000000090660f6f09660f74c8660fd7f1f30fb8f64c01c666'
    '0f6f4910660f74c866440fd7c1f3450fb8c0660f6f4920660f74c866440fd7c9f3450fb8c94d01c14901f1660f6f4930660f'
    '74c8660fd7f1f3440fb8c64d01c84883c1404839c176a3488d42f04839c17726662e0f1f840000000000f30f6f09660f74c8'
    '660fd7f1f30fb8f64901f04883c1104839c176e44839d173164989d14929c94983f904731131c04889cee99900000031c0e9'
    'a50000004d89ca4983e2fc4a8d3411400fb6c7660f6ec8660f60c9660fefc031c0660f6f1d1dba91fc660fefd2660f1f8400'
    '00000000440fb71c0166410f6ee3440fb75c010266410f6eeb660f74e1660f3832e4660fdbe3660fd4d4660f74e9660f3832'
    'e5660fdbe3660fd4c44883c0044939c275c0660fd4c2660f70c8ee660fd4c866480f7ec84d39d1741c660f1f840000000000'
    '31c940383e0f94c14801c848ffc64839d675ed4c01c05b5dc3'
)


class NativeFramesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('gcc is required for ELF fixtures')

    def recover(self, body, *, extra='', stripped=False, caller='call target; ret',
                addresses=(), **options):
        source = f'''.intel_syntax noprefix
.text
.global _start
.type _start,@function
_start: {caller}
.size _start, .-_start
.type target,@function
target:
{body}
.size target, .-target
{extra}
.section .note.GNU-stack,"",@progbits
'''
        with tempfile.TemporaryDirectory(prefix='penryn-native-frames-') as temporary:
            path = Path(temporary)
            (path / 'fixture.S').write_text(source)
            subprocess.run(['gcc', '-nostdlib', '-no-pie', '-Wl,--build-id=none',
                            '-o', str(path / 'fixture'), str(path / 'fixture.S')],
                           check=True, capture_output=True)
            elf = ELFFile(io.BytesIO((path / 'fixture').read_bytes()))
            symbols = {symbol.name: symbol['st_value'] for section in elf.iter_sections()
                       if isinstance(section, SymbolTableSection)
                       for symbol in section.iter_symbols()}
            if stripped:
                subprocess.run(['strip', '--strip-all', str(path / 'fixture')], check=True)
            elf = ELFFile(io.BytesIO((path / 'fixture').read_bytes()))
        decoded = controlflow.Recovery(elf)
        recovery = Recovery(elf, decoded, **options)
        for section in elf.iter_sections():
            if section['sh_flags'] & 4:
                for ins in ix.Decoder(64, section.data(), ip=section['sh_addr']):
                    decoded.feed(ins)
                    recovery.feed(ins)
        decoded.finish()
        recovery.finish(address_taken=[symbols[name] for name in addresses])
        return recovery, symbols

    def rule(self, row, register):
        return row[register].type, row[register].arg

    def test_exact_claude_hot_routine_whole_cfg(self):
        body = '.byte ' + ','.join(hex(byte) for byte in CLAUDE_HOT)
        recovery, symbols = self.recover(body, stripped=True)
        for original_pc in (0x3a2dacc, 0x3a2dae1, 0x3a2daf4, 0x3a2db0c):
            pc = symbols['target'] + original_pc - 0x3a2d8e0
            with self.subTest(original_pc=hex(original_pc)):
                row = recovery.row(pc)
                self.assertEqual((row['cfa'].reg, row['cfa'].offset), (6, 16))
                self.assertEqual(self.rule(row, 6), ('OFFSET', -16))
                self.assertEqual(self.rule(row, 3), ('OFFSET', -24))
                self.assertGreater(recovery.evidence(pc)['reachable_instructions'], 200)

    def test_conventional_frame_and_every_epilogue_transition(self):
        recovery, symbols = self.recover('''
push rbp
set_frame: mov rbp, rsp
save_rbx: push rbx
body: xor ebx, ebx
pop_bx: pop rbx
pop_bp: pop rbp
done: ret
''')
        rows = {name: recovery.row(symbols[name]) for name in
                ('target', 'set_frame', 'save_rbx', 'body', 'pop_bx', 'pop_bp', 'done')}
        self.assertEqual((rows['target']['cfa'].reg, rows['target']['cfa'].offset), (7, 8))
        self.assertEqual((rows['set_frame']['cfa'].reg, rows['set_frame']['cfa'].offset), (7, 16))
        self.assertEqual((rows['body']['cfa'].reg, rows['body']['cfa'].offset), (6, 16))
        self.assertEqual(self.rule(rows['body'], 6), ('OFFSET', -16))
        self.assertEqual(self.rule(rows['pop_bx'], 3), ('OFFSET', -24))
        self.assertEqual(self.rule(rows['pop_bp'], 3), ('SAME_VALUE', None))
        self.assertEqual((rows['done']['cfa'].reg, rows['done']['cfa'].offset), (7, 8))

    def test_frameless_stack_save_restore(self):
        recovery, symbols = self.recover('''
sub rsp, 24
mov [rsp+8], rbx
xor ebx, ebx
body: popcnt rax, rdi
mov rbx, [rsp+8]
add rsp, 24
ret
''')
        row = recovery.row(symbols['body'])
        self.assertEqual((row['cfa'].reg, row['cfa'].offset), (7, 32))
        self.assertEqual(self.rule(row, 3), ('OFFSET', -24))

    def test_leave_restores_incoming_rbp(self):
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; sub rsp,32; body: nop; leave; done: ret')
        self.assertEqual(recovery.row(symbols['body'])['cfa'].reg, 6)
        self.assertEqual(self.rule(recovery.row(symbols['done']), 6), ('SAME_VALUE', None))

    def test_stripped_direct_call_is_entry_evidence(self):
        recovery, symbols = self.recover('body: popcnt rax,rdi; ret', stripped=True)
        row = recovery.row(symbols['body'])
        self.assertEqual((row['cfa'].reg, row['cfa'].offset), (7, 8))
        evidence = recovery.evidence(symbols['body'])
        self.assertEqual(evidence['entry_sources'], ['direct-call'])
        self.assertFalse(evidence['compiler_authored'])
        self.assertFalse(evidence['unknown_indirect_entries_excluded'])

    def dispatcher(self, body, *, extra='', addresses=()):
        return self.recover(body, stripped=True,
            caller='mov rcx,[rip+slot]; mov edi,1; call rcx; ret',
            extra='''leaf: hot: popcnt rax,rdi; ret
other_leaf: popcnt rax,rsi; ret
''' + extra + '\n.data\nslot: .quad target', addresses=addresses)

    def test_indirect_call_slot_and_constant_tail_dispatch_prove_entry(self):
        recovery, symbols = self.dispatcher('''
mov ecx, OFFSET FLAT: leaf
test edi,edi
jz joined
mov ecx, OFFSET FLAT: other_leaf
joined: mov [rip+slot],rcx
jmp rcx
''')
        row = recovery.row(symbols['hot'])
        self.assertEqual((row['cfa'].reg, row['cfa'].offset), (7, 8))
        self.assertEqual(recovery.evidence(symbols['hot'])['entry_sources'], ['verified-dispatch-tail'])
        evidence = next(item for item in recovery.dispatchers if item['slot'] == symbols['slot'])
        self.assertTrue(evidence['accepted'])
        self.assertEqual(evidence['tail_targets'], [symbols['leaf'], symbols['other_leaf']])

    def test_dispatcher_rejects_external_or_partial_slot_changes(self):
        for change in ('mov QWORD PTR [rip+slot],0', 'mov byte ptr [rip+slot+7],0'):
            with self.subTest(change=change):
                recovery, symbols = self.dispatcher('mov ecx, OFFSET FLAT: leaf; mov [rip+slot],rcx; jmp rcx',
                                                     extra='outside: ' + change + '; ret')
                with self.assertRaises(Gap):
                    recovery.row(symbols['hot'])
                self.assertIn('written outside', recovery.dispatchers[0]['reason'])

    def test_dispatcher_rejects_bad_frame_or_unresolved_constant_join(self):
        bodies = ('push rbp; mov ecx, OFFSET FLAT: leaf; jmp rcx',
                  'mov ecx, OFFSET FLAT: leaf; test edi,edi; jz joined; mov ecx,eax; joined: jmp rcx',
                  'test edi,edi; jz alternate; mov ecx, OFFSET FLAT: leaf; jmp joined; '
                  'alternate: mov edx, OFFSET FLAT: other_leaf; joined: jmp rcx')
        for body in bodies:
            with self.subTest(body=body):
                recovery, symbols = self.dispatcher(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['hot'])
                self.assertFalse(recovery.dispatchers[0]['accepted'])

    def test_dispatcher_rejects_interior_entries_and_changed_load_register(self):
        recovery, symbols = self.dispatcher('mov ecx, OFFSET FLAT: leaf; interior: jmp rcx',
                                             addresses=('interior',))
        with self.assertRaises(Gap):
            recovery.row(symbols['hot'])
        recovery, symbols = self.recover('mov ecx, OFFSET FLAT: leaf; jmp rcx', stripped=True,
            caller='mov rcx,[rip+slot]; xor ecx,ecx; call rcx; ret',
            extra='leaf: hot: nop; ret\n.data\nslot: .quad target')
        self.assertFalse(recovery.dispatchers)
        with self.assertRaises(Gap):
            recovery.row(symbols['hot'])

    def test_previous_function_prologue_never_supplies_next_frame(self):
        extra = '''.p2align 4
.type next_function,@function
next_function: body: popcnt rax,rdi; ret
.size next_function, .-next_function'''
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; pop rbp; ret',
                                         extra=extra, stripped=True,
                                         caller='call target; call next_function; ret')
        row = recovery.row(symbols['body'])
        self.assertEqual(recovery.evidence(symbols['body'])['entry'], symbols['next_function'])
        self.assertEqual((row['cfa'].reg, row['cfa'].offset), (7, 8))
        self.assertEqual(self.rule(row, 6), ('SAME_VALUE', None))

    def test_nearby_prologue_without_entry_is_rejected(self):
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; pop rbp; ret', stripped=True,
                                         extra='int3; int3; body: popcnt rax,rdi; ret')
        with self.assertRaisesRegex(Gap, 'not reachable'):
            recovery.row(symbols['body'])

    def test_unknown_entry_never_uses_a_prologue_guess(self):
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; body: nop; pop rbp; ret',
                                         stripped=True, caller='ret')
        with self.assertRaisesRegex(Gap, 'no trusted'):
            recovery.row(symbols['body'])

    def test_diamond_intersects_frame_aliases_from_both_predecessors(self):
        recovery, symbols = self.recover('''
push rbp
test edi,edi
jz alternate
mov rbp,rsp
jmp joined
alternate: xor ebp,ebp
joined: popcnt rax,rdi
pop rbp
ret
''')
        row = recovery.row(symbols['joined'])
        self.assertEqual((row['cfa'].reg, row['cfa'].offset), (7, 16))
        self.assertEqual(self.rule(row, 6), ('OFFSET', -16))

    def test_diamond_missing_prologue_dominance_rejects(self):
        recovery, symbols = self.recover('''
test edi,edi
jz joined
push rbp
mov rbp,rsp
joined: popcnt rax,rdi
pop rbp
ret
''')
        with self.assertRaises(Gap):
            recovery.row(symbols['joined'])

    def test_balanced_loop_converges_but_growing_stack_rejects(self):
        recovery, symbols = self.recover('loop_body: push rax; pop rax; dec edi; jnz loop_body; ret')
        self.assertEqual(recovery.row(symbols['loop_body'])['cfa'].offset, 8)
        recovery, symbols = self.recover('loop_body: push rax; dec edi; jnz loop_body; pop rax; ret')
        with self.assertRaisesRegex(Gap, 'disagree about stack depth'):
            recovery.row(symbols['loop_body'])

    def test_external_branch_and_address_taken_interior_reject(self):
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; body: nop; pop rbp; ret',
                                         extra='outside: jmp body')
        with self.assertRaisesRegex(Gap, 'external direct branch'):
            recovery.row(symbols['body'])
        recovery, symbols = self.recover('body: nop; interior: nop; ret', addresses=('interior',))
        with self.assertRaisesRegex(Gap, 'address-taken interior'):
            recovery.row(symbols['body'])

    def test_unknown_edges_pivots_and_unbalanced_returns_reject(self):
        for body in ('body: jmp rax', 'body: and rsp,-16; ret',
                     'body: mov esp,eax; ret', 'body: push rax; ret',
                     'body: xor ebx,ebx; ret', 'body: ret 8'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_partial_overwrite_of_saved_value_and_return_address_reject(self):
        for body in ('push rbx; mov byte ptr [rsp+7],0; xor ebx,ebx; body: nop; pop rbx; ret',
                     'body: mov byte ptr [rsp+3],0; ret'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_repeated_segmented_or_truncated_stack_writes_reject(self):
        for body in ('mov rdi,rsp; body: rep stosq; ret',
                     'body: mov fs:[rsp],rax; ret',
                     'body: mov [esp],eax; ret'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_call_discards_red_zone_saves_and_caller_saved_aliases(self):
        recovery, symbols = self.recover('''
mov [rsp-8],rbx
xor ebx,ebx
call helper
body: mov rbx,[rsp-8]
ret''', extra='helper: ret')
        with self.assertRaisesRegex(Gap, 'no recoverable incoming value'):
            recovery.row(symbols['body'])

    def test_ordinary_calls_preserve_allocated_saves(self):
        recovery, symbols = self.recover('push rbx; xor ebx,ebx; call helper; body: nop; pop rbx; ret',
                                         extra='helper: ret')
        self.assertEqual(self.rule(recovery.row(symbols['body']), 3), ('OFFSET', -16))

    def test_balanced_direct_tail_call_is_an_exit(self):
        recovery, symbols = self.recover('body: jmp helper', extra='.type helper,@function\nhelper: ret')
        self.assertEqual(recovery.row(symbols['body'])['cfa'].offset, 8)

    def test_instruction_budget_and_lifecycle_are_explicit_gaps(self):
        recovery, symbols = self.recover('body: nop; nop; nop; ret', max_instructions=2)
        with self.assertRaisesRegex(Gap, 'budget'):
            recovery.row(symbols['body'])
        self.assertEqual(recovery.report()['rejected'], 1)
        with self.assertRaisesRegex(ValueError, 'already finished'):
            recovery.feed(ix.Decoder(64, b'\x90').decode())


class NativeUnwindIntegrationTests(unittest.TestCase):
    def test_strict_cli_infers_missing_fde_and_unwinds_native_timer(self):
        # Reuse the existing real libgcc signal oracle. Only exercise's CFI is
        # removed; its caller and the C harness retain compiler-authored CFI.
        import test_runtime as fixtures
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        assembly = fixtures.ASM_FIXTURE.replace('BODY', 'popcnt rbx,rax\ncrc32 rdx,rax')
        caller, exercise = assembly.split('.global exercise', 1)
        assembly = caller + '.global exercise' + '\n'.join(
            line for line in exercise.splitlines() if not line.lstrip().startswith('.cfi_'))
        with tempfile.TemporaryDirectory(prefix='penryn-inferred-unwind-') as temporary:
            work = Path(temporary)
            (work / 'fixture.c').write_text(fixtures.C_FIXTURE)
            (work / 'fixture.S').write_text(assembly)
            original, output = work / 'original', work / 'patched'
            subprocess.run(['cc', '-O2', '-fomit-frame-pointer', '-fasynchronous-unwind-tables',
                            '-no-pie', str(work / 'fixture.c'), str(work / 'fixture.S'),
                            '-o', str(original)], check=True, capture_output=True)
            command = [sys.executable, str(fixtures.HERE / 'patch.py'), str(original),
                       str(output), '--allow-relocate', '--require-unwind', '--no-dataflow']
            rejected = subprocess.run(command, capture_output=True, text=True, timeout=90)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(output.exists())
            accepted = subprocess.run(command + ['--infer-unwind'], capture_output=True,
                                      text=True, timeout=90)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            report = json.loads(Path(str(output) + '.json').read_text())
            self.assertTrue(report['unwind']['native_coverage_complete'])
            self.assertGreaterEqual(report['unwind']['inferred_ranges'], 2)
            self.assertFalse(report['unwind']['frame_recovery']['compiler_authored'])
            with output.open('rb') as stream:
                section = ELFFile(stream).get_section_by_name('.penryn')
                limits = [hex(section['sh_addr']), hex(section['sh_addr'] + section['sh_size'])]
            result = subprocess.run([str(output), *limits, 'timer'], capture_output=True,
                                    text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('failures=0', result.stdout)
            print('inferred native timer:', result.stdout.strip())


class NativeFDEIndexTests(unittest.TestCase):
    def index(self):
        import unwind

        class Frame(dict):
            def __init__(self, start, end, marker):
                super().__init__(initial_location=start, address_range=end-start)
                self.cie = {'return_address_register': 16, 'augmentation': b'zR'}
                self.rows = [{'pc': start, 'marker': marker}]

            def get_decoded(self):
                return SimpleNamespace(table=self.rows)

        frames = [Frame(100, 200, 'outer'), Frame(120, 140, 'inner'),
                  Frame(300, 320, 'unrelated')]
        dwarf = SimpleNamespace(has_EH_CFI=lambda: True, EH_CFI_entries=lambda: frames)
        elf = SimpleNamespace(get_section_by_name=lambda name: {'sh_addr': 4096},
                              get_dwarf_info=lambda **kwargs: dwarf)
        fallback = Mock()
        with patch.object(unwind, 'FDE', Frame):
            index = unwind.Index(elf, frame_recovery=fallback)
        return index, fallback

    def test_earlier_covering_fde_survives_later_finished_overlap(self):
        index, fallback = self.index()
        self.assertEqual(index.row(150)['marker'], 'outer')
        self.assertEqual(index.row(310)['marker'], 'unrelated')
        fallback.row.assert_not_called()

    def test_ambiguous_overlap_rejects_without_inference(self):
        import unwind
        index, fallback = self.index()
        with self.assertRaisesRegex(unwind.Unsupported, 'multiple original FDEs'):
            index.row(130)
        fallback.row.assert_not_called()

    def test_only_a_real_coverage_gap_invokes_inference(self):
        index, fallback = self.index()
        fallback.row.return_value = {'pc': 200, 'marker': 'inferred'}
        self.assertEqual(index.row(200)['marker'], 'inferred')
        fallback.row.assert_called_once_with(200)


if __name__ == '__main__':
    unittest.main()
