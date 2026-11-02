#!/usr/bin/env python3
"""End-to-end profile, region, and recovered-entry integration checks.

These small syscall-only ELFs execute as rewritten payloads under QEMU Penryn.
Their original code, reports, target tables and relocated branch/RIP operands
are checked together; lower-level arithmetic and unit tests live elsewhere.
"""
import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
from typing import Literal, overload
import unittest

from iced_x86 import Decoder, FlowControl
from static_penryn import patch
from static_penryn.checked import as_int, as_list, as_object, as_str, load_json
from static_penryn.elfcheck import validate_elf
from . import test_patch as fixtures


def objects(value: object, what: str) -> list[dict[str, object]]:
    """A report array of JSON objects."""
    return [as_object(item, what) for item in as_list(value, what)]


def hexint(value: object, what: str) -> int:
    """A report address, written as a hexadecimal string."""
    return int(as_str(value, what), 16)


class IntegrationTests(unittest.TestCase):
    fixture = fixtures.PatchTests.fixture
    elf = fixtures.PatchTests.elf
    penryn = fixtures.PatchTests.penryn

    @classmethod
    def setUpClass(cls) -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        for name in ('cc', 'ld', 'qemu-x86_64'):
            if not shutil.which(name):
                raise RuntimeError(f'required integration test dependency missing: {name}')

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix='penryn-integration-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    @overload
    def invoke(self, binary: Path, *arguments: str | Path, name: str = ...,
               success: Literal[True] = ...) -> tuple[Path, dict[str, object]]: ...
    @overload
    def invoke(self, binary: Path, *arguments: str | Path, name: str = ...,
               success: Literal[False]) -> subprocess.CompletedProcess[str]: ...
    def invoke(self, binary: Path, *arguments: str | Path, name: str = 'output', success: bool = True
               ) -> tuple[Path, dict[str, object]] | subprocess.CompletedProcess[str]:
        before = binary.read_bytes()
        output = self.work / name
        result = subprocess.run([sys.executable, '-m', 'static_penryn.patch', str(binary),
                                 str(output), *map(str, arguments)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(binary.read_bytes(), before, 'input changed during rewrite')
        if not success:
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + '.json').exists())
            return result
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = as_object(load_json(Path(str(output) + '.json').read_text()), 'report')
        self.assertEqual(report['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(report['output_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
        validate_elf(output.read_bytes(), self.elf(output))
        self.assertFalse(patch.scan(self.elf(output), inventory_only=True)[0])
        return output, report

    def profile(self, binary: Path, weights: dict[int, int], *, digest: str | None = None,
                name: str = 'profile.json') -> Path:
        path = self.work / name
        content: dict[str, object] = {
            'input_sha256': digest or hashlib.sha256(binary.read_bytes()).hexdigest(),
            'site_counts': [{'address': hex(address), 'executions': count}
                            for address, count in weights.items()],
        }
        path.write_text(json.dumps(content))
        return path

    def assert_ranges(self, original: Path, output: Path, report: dict[str, object]) -> None:
        before, after = original.read_bytes(), output.read_bytes()
        old, new = self.elf(original), self.elf(output)
        code = new.get_section_by_name('.penryn')
        assert code is not None
        code_start, code_end = code['sh_addr'], code['sh_addr'] + code['sh_size']
        occupied = []
        for item in objects(report['patches'], 'patches'):
            origin, end, stub, stub_end = (hexint(item[key], key)
                                         for key in ('address', 'end', 'stub', 'stub_end'))
            source_offset = patch.va_offset(old, origin)
            self.assertEqual(bytes.fromhex(as_str(item['original'], 'original')),
                             before[source_offset:source_offset + end - origin])
            self.assertTrue(code_start <= stub < stub_end <= code_end)
            offset = patch.va_offset(new, origin)
            entry = Decoder(64, after[offset:offset + 15], ip=origin).decode()
            self.assertEqual(entry.flow_control, FlowControl.UNCONDITIONAL_BRANCH)
            self.assertEqual(entry.near_branch_target, hexint(item['cave'], 'cave') if item['cave'] else stub)
            previous_end, previous_original = stub, origin - 1
            for row in objects(item['instruction_ranges'], 'instruction_ranges'):
                address, start, stop = (hexint(row[key], key) for key in ('original_address', 'start', 'end'))
                self.assertTrue(previous_end <= start < stop <= stub_end)
                self.assertTrue(previous_original < address < end)
                previous_end, previous_original = stop, address
            tail = patch.va_offset(new, stub_end - 5)
            back = Decoder(64, after[tail:tail + 5], ip=stub_end - 5).decode()
            self.assertEqual(back.near_branch_target, end)
            occupied.append((stub, stub_end))
        occupied.sort()
        self.assertTrue(all(left[1] <= right[0] for left, right in zip(occupied, occupied[1:])))

    def test_wrong_input_profile_fails_without_publishing(self) -> None:
        binary = self.fixture('mov ebx,255\npopcnt rax,rbx\ncmp eax,8\njne .Lfail')
        profile = self.profile(binary, {}, digest='0' * 64)
        result = self.invoke(binary, '--profile', profile, success=False)
        self.assertIn('different original executable', result.stderr)
        self.assertNotIn('Decoding executable sections', result.stdout)

    def test_hot_layout_is_deterministic_and_preserves_execution(self) -> None:
        binary = self.fixture('mov ebx,255\npopcnt rax,rbx\ncmp eax,8\njne .Lfail\n'
                              'popcnt rcx,rbx\ncmp ecx,8\njne .Lfail\n'
                              'popcnt rdx,rbx\ncmp edx,8\njne .Lfail')
        addresses = [ins.ip for ins, _ in patch.scan(self.elf(binary), inventory_only=True)[0]]
        profile = self.profile(binary, dict(zip(addresses, (1, 100, 100))))
        first, report = self.invoke(binary, '--profile', profile, name='first')
        second, report2 = self.invoke(binary, '--profile', profile, name='second')
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(report['patches'], report2['patches'])
        order = [hexint(row['address'], 'address') for row in objects(report['patches'], 'patches')]
        hot_first = [addresses[1], addresses[2], addresses[0]]
        self.assertEqual(order, hot_first)
        stubs = [hexint(row['stub'], 'stub') for row in objects(report['patches'], 'patches')]
        ascending = sorted(hexint(row['stub'], 'stub') for row in objects(report['patches'], 'patches'))
        self.assertEqual(stubs, ascending)
        self.assert_ranges(binary, first, report)
        self.penryn(first)

    def test_register_region_rewrite_reports_glue_and_exact_ranges(self) -> None:
        binary = self.fixture('mov ebx,255\npopcnt rax,rbx\nmov rcx,rax\n'
                              'popcnt r8,rcx\nadd rax,r8\ncmp eax,9\njne .Lfail')
        output, report = self.invoke(binary, '--regions', '--allow-relocate')
        self.assertEqual(report['fused_regions'], 1)
        self.assertEqual(report['eliminated_site_jumps'], 1)
        self.assertEqual(report['sites'], 1)
        ranges = objects(objects(report['patches'], 'patches')[0]['instruction_ranges'], 'instruction_ranges')
        mnemonics = [row['mnemonic'] for row in ranges]
        expected = ['POPCNT', 'MOV', 'POPCNT']
        self.assertEqual(mnemonics, expected)
        self.assert_ranges(binary, output, report)
        self.penryn(output)

    def test_rip_load_region_is_opt_in_and_remains_pie_relative(self) -> None:
        binary = self.fixture('mov ebx,255\npopcnt rax,rbx\nmov rcx,[rip+.Lvalue]\n'
                              'popcnt r8,rcx\nadd rax,r8\ncmp eax,16\njne .Lfail',
                              pie=True, extra='.section .rodata\n.Lvalue: .quad 255')
        simple, before = self.invoke(binary, '--regions', '--allow-relocate', name='simple')
        output, report = self.invoke(binary, '--regions', '--region-loads', '--allow-relocate', name='loads')
        self.assertEqual(before['fused_regions'], 0)
        self.assertEqual(report['fused_regions'], 1)
        original_load = next(ins for sec in self.elf(binary).iter_sections() if sec['sh_flags'] & 4
                             for ins in Decoder(64, sec.data(), ip=sec['sh_addr'])
                             if ins.is_ip_rel_memory_operand)
        ranges = objects(objects(report['patches'], 'patches')[0]['instruction_ranges'], 'instruction_ranges')
        row = next(row for row in ranges if row['mnemonic'] == 'MOV')
        address = hexint(row['start'], 'start')
        offset = patch.va_offset(self.elf(output), address)
        moved = Decoder(64, output.read_bytes()[offset:offset + 15], ip=address).decode()
        self.assertEqual(moved.ip_rel_memory_address, original_load.ip_rel_memory_address)
        self.assert_ranges(binary, output, report)
        self.penryn(simple)
        self.penryn(output)
        self.penryn(output)  # A separate PIE load must resolve the same relative operand.

    def test_relative_table_entry_prevents_fusion_across_an_indirect_entry(self) -> None:
        body = ('mov ebx,255\nxor edi,edi\ncall .Ldispatch\ncmp eax,8\njne .Lfail\n'
                'mov edi,1\ncall .Ldispatch\ncmp eax,8\njne .Lfail')
        extra = ('.text\n.Ldispatch:\ncmp edi,1\nja .Lfail\nlea rdx,[rip+.Ltable]\n'
                 'movsxd rax,DWORD PTR [rdx+rdi*4]\nadd rax,rdx\njmp rax\n'
                 '.Lfirst: popcnt rax,rbx\n.Lsecond: mov rcx,rbx\npopcnt r8,rcx\nmov rax,r8\nret\n'
                 '.section .rodata\n.Ltable: .long .Lfirst-.Ltable, .Lsecond-.Ltable')
        binary = self.fixture(body, extra=extra)
        output, report = self.invoke(binary, '--regions', '--allow-relocate')
        tables = as_list(as_object(report['control_flow'], 'control_flow')['relative_tables'], 'relative_tables')
        self.assertEqual(len(tables), 1)
        table = as_object(tables[0], 'relative_tables')
        self.assertEqual(table['entries'], 2)
        self.assertEqual(report['fused_regions'], 0)
        self.assertEqual(report['sites'], 2)
        address = max(as_int(target, 'targets') for target in as_list(table['targets'], 'targets'))
        offset = patch.va_offset(self.elf(binary), address)
        self.assertEqual(output.read_bytes()[offset:offset + 3], binary.read_bytes()[offset:offset + 3])
        table_offset = patch.va_offset(self.elf(binary), as_int(table['table'], 'table'))
        self.assertEqual(output.read_bytes()[table_offset:table_offset + 8], binary.read_bytes()[table_offset:table_offset + 8])
        self.assert_ranges(binary, output, report)
        self.penryn(output)

    def test_cold_site_stays_separate_even_inside_a_safe_region(self) -> None:
        binary = self.fixture('mov ebx,255\npopcnt rax,rbx\nmov rcx,rax\n'
                              'popcnt r8,rcx\ncmp r8d,1\njne .Lfail')
        addresses = [ins.ip for ins, _ in patch.scan(self.elf(binary), inventory_only=True)[0]]
        profile = self.profile(binary, {addresses[0]: 10, addresses[1]: 0})
        output, report = self.invoke(binary, '--regions', '--allow-relocate', '--profile', profile)
        self.assertEqual(report['fused_regions'], 0)
        self.assertEqual(report['sites'], 2)
        self.penryn(output)

    def test_region_flags_require_explicit_relocation_authorization(self) -> None:
        binary = self.fixture('popcnt rax,rbx')
        result = self.invoke(binary, '--regions', success=False)
        self.assertIn('--regions requires --allow-relocate', result.stderr)
        result = self.invoke(binary, '--region-loads', success=False)
        self.assertIn('--region-loads requires --regions', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
