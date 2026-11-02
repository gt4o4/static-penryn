#!/usr/bin/env python3
"""Native frame proofs and counterexamples from linked, decoded CFG fixtures."""
import io
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING
import unittest

import iced_x86 as ix
from elftools.dwarf.callframe import CIE, FDE, ZERO, DecodedCallFrameTable
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection

from static_penryn import checked, controlflow, unwind
from static_penryn.native_frames import Gap, Recovery, RowEvidence, row_cfa, row_rule
from . import test_runtime as fixtures

if TYPE_CHECKING:
    from elftools.dwarf.callframe import CFIRow


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
    def setUpClass(cls) -> None:
        if not shutil.which('gcc'):
            raise unittest.SkipTest('gcc is required for ELF fixtures')

    def recover(self, body: str, *, extra: str = '', stripped: bool = False, caller: str = 'call target; ret',
                addresses: tuple[str, ...] = (), **options: int) -> tuple[Recovery, dict[str, int]]:
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

    def rule(self, row: 'CFIRow', register: int) -> tuple[str, int | list[int] | None]:
        rule = row_rule(row, register)
        assert rule is not None, f'no rule for DWARF register {register}'
        return rule.type, rule.arg

    def evidence(self, recovery: Recovery, pc: int) -> RowEvidence:
        evidence = recovery.evidence(pc)
        assert evidence is not None, f'no decision recorded for {pc:#x}'
        return evidence

    def test_exact_claude_hot_routine_whole_cfg(self) -> None:
        body = '.byte ' + ','.join(hex(byte) for byte in CLAUDE_HOT)
        recovery, symbols = self.recover(body, stripped=True)
        for original_pc in (0x3a2dacc, 0x3a2dae1, 0x3a2daf4, 0x3a2db0c):
            pc = symbols['target'] + original_pc - 0x3a2d8e0
            with self.subTest(original_pc=hex(original_pc)):
                row = recovery.row(pc)
                self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (6, 16))
                self.assertEqual(self.rule(row, 6), ('OFFSET', -16))
                self.assertEqual(self.rule(row, 3), ('OFFSET', -24))
                self.assertGreater(self.evidence(recovery, pc)['reachable_instructions'], 200)

    def test_conventional_frame_and_every_epilogue_transition(self) -> None:
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
        self.assertEqual((row_cfa(rows['target']).reg, row_cfa(rows['target']).offset), (7, 8))
        self.assertEqual((row_cfa(rows['set_frame']).reg, row_cfa(rows['set_frame']).offset), (7, 16))
        self.assertEqual((row_cfa(rows['body']).reg, row_cfa(rows['body']).offset), (6, 16))
        self.assertEqual(self.rule(rows['body'], 6), ('OFFSET', -16))
        self.assertEqual(self.rule(rows['pop_bx'], 3), ('OFFSET', -24))
        self.assertEqual(self.rule(rows['pop_bp'], 3), ('SAME_VALUE', None))
        self.assertEqual((row_cfa(rows['done']).reg, row_cfa(rows['done']).offset), (7, 8))

    def test_frameless_stack_save_restore(self) -> None:
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
        self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (7, 32))
        self.assertEqual(self.rule(row, 3), ('OFFSET', -24))

    def test_leave_restores_incoming_rbp(self) -> None:
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; sub rsp,32; body: nop; leave; done: ret')
        self.assertEqual(row_cfa(recovery.row(symbols['body'])).reg, 6)
        self.assertEqual(self.rule(recovery.row(symbols['done']), 6), ('SAME_VALUE', None))

    def test_stripped_direct_call_is_entry_evidence(self) -> None:
        recovery, symbols = self.recover('body: popcnt rax,rdi; ret', stripped=True)
        row = recovery.row(symbols['body'])
        self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (7, 8))
        evidence = self.evidence(recovery, symbols['body'])
        direct: list[str] = ['direct-call']
        self.assertEqual(evidence['entry_sources'], direct)
        self.assertFalse(evidence['compiler_authored'])
        self.assertFalse(evidence['unknown_indirect_entries_excluded'])

    def dispatcher(self, body: str, *, extra: str = '',
                   addresses: tuple[str, ...] = ()) -> tuple[Recovery, dict[str, int]]:
        return self.recover(body, stripped=True,
            caller='mov rcx,[rip+slot]; mov edi,1; call rcx; ret',
            extra='''leaf: hot: popcnt rax,rdi; ret
other_leaf: popcnt rax,rsi; ret
''' + extra + '\n.data\nslot: .quad target', addresses=addresses)

    def test_indirect_call_slot_and_constant_tail_dispatch_prove_entry(self) -> None:
        recovery, symbols = self.dispatcher('''
mov ecx, OFFSET FLAT: leaf
test edi,edi
jz joined
mov ecx, OFFSET FLAT: other_leaf
joined: mov [rip+slot],rcx
jmp rcx
''')
        row = recovery.row(symbols['hot'])
        self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (7, 8))
        dispatched: list[str] = ['verified-dispatch-tail']
        self.assertEqual(self.evidence(recovery, symbols['hot'])['entry_sources'], dispatched)
        evidence = next(item for item in recovery.dispatchers if item['slot'] == symbols['slot'])
        self.assertTrue(evidence['accepted'])
        targets: list[int] = [symbols['leaf'], symbols['other_leaf']]
        self.assertEqual(evidence['tail_targets'], targets)

    def test_dispatcher_rejects_external_or_partial_slot_changes(self) -> None:
        for change in ('mov QWORD PTR [rip+slot],0', 'mov byte ptr [rip+slot+7],0'):
            with self.subTest(change=change):
                recovery, symbols = self.dispatcher('mov ecx, OFFSET FLAT: leaf; mov [rip+slot],rcx; jmp rcx',
                                                     extra='outside: ' + change + '; ret')
                with self.assertRaises(Gap):
                    recovery.row(symbols['hot'])
                self.assertIn('written outside', recovery.dispatchers[0]['reason'])

    def test_dispatcher_rejects_bad_frame_or_unresolved_constant_join(self) -> None:
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

    def test_dispatcher_rejects_interior_entries_and_changed_load_register(self) -> None:
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

    def test_previous_function_prologue_never_supplies_next_frame(self) -> None:
        extra = '''.p2align 4
.type next_function,@function
next_function: body: popcnt rax,rdi; ret
.size next_function, .-next_function'''
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; pop rbp; ret',
                                         extra=extra, stripped=True,
                                         caller='call target; call next_function; ret')
        row = recovery.row(symbols['body'])
        self.assertEqual(self.evidence(recovery, symbols['body'])['entry'], symbols['next_function'])
        self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (7, 8))
        self.assertEqual(self.rule(row, 6), ('SAME_VALUE', None))

    def test_nearby_prologue_without_entry_is_rejected(self) -> None:
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; pop rbp; ret', stripped=True,
                                         extra='int3; int3; body: popcnt rax,rdi; ret')
        with self.assertRaisesRegex(Gap, 'not reachable'):
            recovery.row(symbols['body'])

    def test_unknown_entry_never_uses_a_prologue_guess(self) -> None:
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; body: nop; pop rbp; ret',
                                         stripped=True, caller='ret')
        with self.assertRaisesRegex(Gap, 'no trusted'):
            recovery.row(symbols['body'])

    def test_diamond_intersects_frame_aliases_from_both_predecessors(self) -> None:
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
        self.assertEqual((row_cfa(row).reg, row_cfa(row).offset), (7, 16))
        self.assertEqual(self.rule(row, 6), ('OFFSET', -16))

    def test_diamond_missing_prologue_dominance_rejects(self) -> None:
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

    def test_balanced_loop_converges_but_growing_stack_rejects(self) -> None:
        recovery, symbols = self.recover('loop_body: push rax; pop rax; dec edi; jnz loop_body; ret')
        self.assertEqual(row_cfa(recovery.row(symbols['loop_body'])).offset, 8)
        recovery, symbols = self.recover('loop_body: push rax; dec edi; jnz loop_body; pop rax; ret')
        with self.assertRaisesRegex(Gap, 'disagree about stack depth'):
            recovery.row(symbols['loop_body'])

    def test_external_branch_and_address_taken_interior_reject(self) -> None:
        recovery, symbols = self.recover('push rbp; mov rbp,rsp; body: nop; pop rbp; ret',
                                         extra='outside: jmp body')
        with self.assertRaisesRegex(Gap, 'external direct branch'):
            recovery.row(symbols['body'])
        recovery, symbols = self.recover('body: nop; interior: nop; ret', addresses=('interior',))
        with self.assertRaisesRegex(Gap, 'address-taken interior'):
            recovery.row(symbols['body'])

    def test_unknown_edges_pivots_and_unbalanced_returns_reject(self) -> None:
        for body in ('body: jmp rax', 'body: and rsp,-16; ret',
                     'body: mov esp,eax; ret', 'body: push rax; ret',
                     'body: xor ebx,ebx; ret', 'body: ret 8'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_partial_overwrite_of_saved_value_and_return_address_reject(self) -> None:
        for body in ('push rbx; mov byte ptr [rsp+7],0; xor ebx,ebx; body: nop; pop rbx; ret',
                     'body: mov byte ptr [rsp+3],0; ret'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_repeated_segmented_or_truncated_stack_writes_reject(self) -> None:
        for body in ('mov rdi,rsp; body: rep stosq; ret',
                     'body: mov fs:[rsp],rax; ret',
                     'body: mov [esp],eax; ret'):
            with self.subTest(body=body):
                recovery, symbols = self.recover(body)
                with self.assertRaises(Gap):
                    recovery.row(symbols['body'])

    def test_call_discards_red_zone_saves_and_caller_saved_aliases(self) -> None:
        recovery, symbols = self.recover('''
mov [rsp-8],rbx
xor ebx,ebx
call helper
body: mov rbx,[rsp-8]
ret''', extra='helper: ret')
        with self.assertRaisesRegex(Gap, 'no recoverable incoming value'):
            recovery.row(symbols['body'])

    def test_ordinary_calls_preserve_allocated_saves(self) -> None:
        recovery, symbols = self.recover('push rbx; xor ebx,ebx; call helper; body: nop; pop rbx; ret',
                                         extra='helper: ret')
        self.assertEqual(self.rule(recovery.row(symbols['body']), 3), ('OFFSET', -16))

    def test_balanced_direct_tail_call_is_an_exit(self) -> None:
        recovery, symbols = self.recover('body: jmp helper', extra='.type helper,@function\nhelper: ret')
        self.assertEqual(row_cfa(recovery.row(symbols['body'])).offset, 8)

    def test_instruction_budget_and_lifecycle_are_explicit_gaps(self) -> None:
        recovery, symbols = self.recover('body: nop; nop; nop; ret', max_instructions=2)
        with self.assertRaisesRegex(Gap, 'budget'):
            recovery.row(symbols['body'])
        self.assertEqual(recovery.report()['rejected'], 1)
        with self.assertRaisesRegex(ValueError, 'already finished'):
            recovery.feed(ix.Decoder(64, b'\x90').decode())


class NativeUnwindIntegrationTests(unittest.TestCase):
    def test_strict_cli_infers_missing_fde_and_unwinds_native_timer(self) -> None:
        # Reuse the existing real libgcc signal oracle. Only exercise's CFI is
        # removed; its caller and the C harness retain compiler-authored CFI.
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
            command = [sys.executable, '-m', 'static_penryn.patch', str(original),
                       str(output), '--allow-relocate', '--require-unwind', '--no-dataflow']
            rejected = subprocess.run(command, capture_output=True, text=True, timeout=90)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(output.exists())
            accepted = subprocess.run(command + ['--infer-unwind'], capture_output=True,
                                      text=True, timeout=90)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            report = checked.as_object(checked.load_json(Path(str(output) + '.json').read_text()), 'patch report')
            unwound = checked.as_object(report['unwind'], 'unwind report')
            self.assertTrue(unwound['native_coverage_complete'])
            self.assertGreaterEqual(checked.as_int(unwound['inferred_ranges'], 'inferred ranges'), 2)
            self.assertFalse(checked.as_object(unwound['frame_recovery'], 'frame recovery')['compiler_authored'])
            with output.open('rb') as stream:
                section = ELFFile(stream).get_section_by_name('.penryn')
                assert section is not None
                limits = [hex(section['sh_addr']), hex(section['sh_addr'] + section['sh_size'])]
            result = subprocess.run([str(output), *limits, 'timer'], capture_output=True,
                                    text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('failures=0', result.stdout)
            print('inferred native timer:', result.stdout.strip())


# Row markers: which table, or the inference, answered a query.
OUTER, INNER, UNRELATED, INFERRED = range(4)


class StandardCIE(CIE):
    """Return column 16, no signal frame; pyelftools reads items from self.header."""
    def __init__(self) -> None:
        self.header = {'return_address_register': 16, 'augmentation': b'zR'}


class Frame(FDE):
    """An FDE for [start, end) whose single decoded row carries a marker."""
    def __init__(self, start: int, end: int, marker: int) -> None:
        self.header = {'initial_location': start, 'address_range': end - start}
        self.cie = StandardCIE()
        self.rows: list[CFIRow] = [{'pc': start, 'marker': marker}]

    def get_decoded(self) -> DecodedCallFrameTable:
        return DecodedCallFrameTable(table=self.rows, reg_order=[])


class EHFrame(DWARFInfo):
    """DWARF info that is only these .eh_frame entries."""
    def __init__(self, entries: list[CIE | FDE | ZERO]) -> None:
        self.entries = entries

    def has_EH_CFI(self) -> bool:
        return True

    def EH_CFI_entries(self) -> list[CIE | FDE | ZERO]:
        return self.entries


class Header(Section):
    """A section that is only its header, from which pyelftools reads items."""
    def __init__(self, **header: int | str) -> None:
        self.header = header


class FrameELF(ELFFile):
    """An ELF whose every section lies at 4096 and whose DWARF info is given."""
    def __init__(self, dwarf: DWARFInfo) -> None:
        self.dwarf = dwarf

    def get_section_by_name(self, name: str) -> Section | None:
        return Header(sh_addr=4096)

    def get_dwarf_info(self, relocate_dwarf_sections: bool = True, follow_links: bool = True) -> DWARFInfo:
        return self.dwarf


class Inference(Recovery):
    """Frame inference that records each query and answers with `result`."""
    def __init__(self) -> None:
        self.calls: list[int] = []
        self.result: CFIRow | None = None

    def row(self, pc: int) -> 'CFIRow':
        self.calls.append(pc)
        if self.result is None:
            raise AssertionError(f'unexpected frame inference at {pc}')
        return self.result

    def evidence(self, pc: int) -> RowEvidence | None:
        return None


class NativeFDEIndexTests(unittest.TestCase):
    def index(self) -> tuple[unwind.Index, Inference]:
        frames: list[CIE | FDE | ZERO] = [Frame(100, 200, OUTER), Frame(120, 140, INNER),
                                          Frame(300, 320, UNRELATED)]
        fallback = Inference()
        index = unwind.Index(FrameELF(EHFrame(frames)), frame_recovery=fallback)
        return index, fallback

    def test_earlier_covering_fde_survives_later_finished_overlap(self) -> None:
        index, fallback = self.index()
        self.assertEqual(index.row(150)['marker'], OUTER)
        self.assertEqual(index.row(310)['marker'], UNRELATED)
        self.assertFalse(fallback.calls)

    def test_ambiguous_overlap_rejects_without_inference(self) -> None:
        index, fallback = self.index()
        with self.assertRaisesRegex(unwind.Unsupported, 'multiple original FDEs'):
            index.row(130)
        self.assertFalse(fallback.calls)

    def test_only_a_real_coverage_gap_invokes_inference(self) -> None:
        index, fallback = self.index()
        fallback.result = {'pc': 200, 'marker': INFERRED}
        self.assertEqual(index.row(200)['marker'], INFERRED)
        once: list[int] = [200]
        self.assertEqual(fallback.calls, once)


if __name__ == '__main__':
    unittest.main()
