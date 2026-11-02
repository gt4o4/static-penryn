#!/usr/bin/env python3
"""Grouping counterexamples and shared-frame hardware equivalence.

Unit tests: python -m unittest tests.test_regions
Full GPR/XMM/flags/red-zone oracle: python -m tests.test_regions --remote lix-ory
The remote worker reuses test_lower.py and refuses a CPU lacking real ISA
support. It never uses kernel opemu as its expected-result implementation.
"""
import argparse
from collections.abc import Container, Iterable, Mapping, Sequence
import io
import json
from pathlib import Path
import resource
import shlex
import subprocess
import tempfile
from typing import TypedDict, Unpack
import unittest

import iced_x86 as ix
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from static_penryn.checked import constants
from static_penryn.dataflow import Hints, analyze
from static_penryn.patch import Site
from static_penryn import lower
from static_penryn import regions
from .test_controlflow import present
from .test_lower import state_wrapper, worker


_REGISTERS = constants(ix.Register)


def iced_register(name: str) -> ix.Register_:
    """ix.Register.<name>, the value getattr reads from the same module."""
    value = _REGISTERS[name]
    # iced's Register type is a plain int at runtime (ix.Register_ is int).
    if not isinstance(value, ix.Register_):
        raise TypeError(f'not a register: {name}')
    return value


def decode(code: str) -> list[ix.Instruction]:
    return list(ix.Decoder(64, bytes.fromhex(code), ip=0x1000))


class FakeRecovery:
    def __init__(self, instructions: Sequence[ix.Instruction], *, bounds: bool = True, block: bool = False,
                 missing: Container[int] = ()) -> None:
        self.instructions = {ins.ip: ins for ins in instructions if ins.ip not in missing}
        self.interval = (instructions[0].ip, instructions[-1].next_ip) if bounds else None
        self.block = (instructions[0].ip, instructions[-1].next_ip) if block else None

    def bounds(self, address: int) -> tuple[int, int] | None:
        return self.interval

    def lookup(self, address: int) -> ix.Instruction | None:
        return self.instructions.get(address)

    def block_bounds(self, address: int) -> tuple[int, int] | None:
        return self.block


def prepared(code: str) -> tuple[list[ix.Instruction], list[Site]]:
    instructions = decode(code)
    sites = [Site([ins], ins.ip - 0x1000, ins.next_ip, hints=[Hints()])
             for ins in instructions if ins.mnemonic in lower.SUPPORTED]
    return instructions, sites


PAIR = 'f3480fb8c1 4889f2 f34c0fb8c2'  # popcnt rax,rcx; mov rdx,rsi; popcnt r8,rdx


class GroupOptions(TypedDict, total=False):
    """regions.group's keyword options; an absent key keeps its default."""
    weights: Mapping[int, int] | None
    max_instructions: int
    max_bytes: int
    allow_loads: bool


class RegionTests(unittest.TestCase):
    def grouped(self, code: str = PAIR, targets: Iterable[int] = (), spans: Iterable[tuple[int, int]] = (),
                **kwargs: Unpack[GroupOptions]) -> list[Site]:
        instructions, sites = prepared(code)
        return regions.group(sites, targets, spans, FakeRecovery(instructions), **kwargs)

    def test_plain_register_region_keeps_original_order(self) -> None:
        instructions, sites = prepared(PAIR)
        result = regions.group(sites, [], [], FakeRecovery(instructions))
        self.assertEqual(len(result), 1)
        # Bound first: in assertEqual's Any context a comprehension infers list[Any].
        grouped_ips, original_ips = [i.ip for i in result[0].sequence], [i.ip for i in instructions]
        self.assertEqual(grouped_ips, original_ips)
        self.assertEqual(result[0].end, instructions[-1].next_ip)
        self.assertEqual(result[0].offset, 0)
        self.assertEqual(len(result[0].hints), 2)
        self.assertIsNone(result[0].cave)
        self.assertIsNone(result[0].tail)

    def test_interior_entry_at_glue_or_second_site_prevents_merge(self) -> None:
        instructions, _ = prepared(PAIR)
        for address in (instructions[0].ip + 1, instructions[1].ip, instructions[2].ip):
            self.assertEqual(len(self.grouped(targets=[address])), 2)
        self.assertEqual(len(self.grouped(targets=[instructions[0].ip])), 1)

    def test_loader_and_table_data_spans_prevent_merge(self) -> None:
        for span in ((0x1000, 0x1001), (0x1004, 0x1007), (0x1008, 0x1010)):
            self.assertEqual(len(self.grouped(spans=[span])), 2)

    def test_unknown_boundaries_missing_starts_and_function_end_prevent_merge(self) -> None:
        instructions, sites = prepared(PAIR)
        for recovery in (FakeRecovery(instructions, bounds=False),
                         FakeRecovery(instructions, missing=[instructions[1].ip])):
            self.assertEqual(len(regions.group(sites, [], [], recovery)), 2)
        recovery = FakeRecovery(instructions)
        recovery.interval = (0x1000, instructions[2].ip)
        self.assertEqual(len(regions.group(sites, [], [], recovery)), 2)

    def test_profile_selects_but_never_overrides_control_flow_evidence(self) -> None:
        instructions, sites = prepared(PAIR)
        hot = {site.ip: 100 for site in sites}
        self.assertEqual(len(self.grouped(weights=hot)), 1)
        self.assertEqual(len(self.grouped(weights={sites[0].ip: 100})), 2)
        self.assertEqual(len(self.grouped(weights=hot, targets=[instructions[1].ip])), 2)

    def test_verified_block_fallback_without_function_metadata(self) -> None:
        instructions, sites = prepared(PAIR)
        recovery = FakeRecovery(instructions, bounds=False, block=True)
        self.assertEqual(len(regions.group(sites, [], [], recovery)), 1)
        self.assertEqual(len(regions.group(sites, [instructions[1].ip], [], recovery)), 2)
        recovery.block = (0x1000, instructions[2].ip)
        self.assertEqual(len(regions.group(sites, [], [], recovery)), 2)

    def test_instruction_and_byte_budgets(self) -> None:
        self.assertEqual(len(self.grouped(max_instructions=2)), 2)
        self.assertEqual(len(self.grouped(max_bytes=12)), 2)

    def test_grouped_sites_keep_adjacency_and_existing_relocated_tail(self) -> None:
        instructions = decode('f3480fb8c1 4889f2 f34c0fb8c2')
        first = Site([instructions[0]], 0, instructions[1].next_ip,
                     cave=0x2000, tail=instructions[1], hints=[Hints()])
        second = Site([instructions[2]], 8, instructions[2].next_ip, hints=[Hints()])
        result = regions.group([first, second], [], [], FakeRecovery(instructions))
        self.assertEqual(len(result), 1)
        grouped_text, original_text = [str(i) for i in result[0].sequence], [str(i) for i in instructions]
        self.assertEqual(grouped_text, original_text)

    def test_stack_frame_registers_and_explicit_segment_registers_are_rejected(self) -> None:
        for code in ('4889e0', '4889e8', '488da801000000', '8ed8', '8ed0', '8cd8', '8cd0'):
            with self.subTest(code=code):
                self.assertFalse(regions.region_safe(decode(code)[0], glue=True, allow_loads=True))

    def test_control_transfers_and_privileged_glue_are_rejected(self) -> None:
        for code in ('c3', 'eb00', '7400', 'e800000000', 'ffe0', '0f20c0', '0f05', 'f001d8'):
            self.assertFalse(regions.region_safe(decode(code)[0], glue=True, allow_loads=True))

    def test_memory_glue_requires_explicit_load_option(self) -> None:
        code = 'f3480fb8c1 488b17 f34c0fb8c2'  # register-addressed MOV load
        self.assertEqual(len(self.grouped(code)), 2)
        self.assertEqual(len(self.grouped(code, allow_loads=True)), 1)
        for code in ('488b07', '660f6f07', 'f30f6f07'):
            self.assertFalse(regions.region_safe(decode(code)[0], glue=True))
            self.assertTrue(regions.region_safe(decode(code)[0], glue=True, allow_loads=True))

    def test_load_option_still_rejects_stores_rmw_stack_and_tls(self) -> None:
        for code in ('488907', '660f7f07', '480107', '488b0424', '488b4500',
                     '64488b07', '65488b07', '67488b0500000000'):
            self.assertFalse(regions.region_safe(decode(code)[0], glue=True, allow_loads=True))

    def test_shared_lowering_saves_only_registers_unused_by_every_original(self) -> None:
        instructions, sites = prepared(PAIR)
        _, _, _, report = regions.shared_lowering(instructions, {s.ip: Hints() for s in sites})
        self.assertNotIn('rax', report['gprs'])
        self.assertNotIn('rcx', report['gprs'])
        self.assertNotIn('rdx', report['gprs'])
        self.assertNotIn('rsi', report['gprs'])
        self.assertNotIn('r8', report['gprs'])
        self.assertNotIn('rsp', report['gprs'])
        self.assertNotIn('rbp', report['gprs'])

    def test_scratch_values_are_saved_once_per_region(self) -> None:
        instructions, sites = prepared('f3480fb8f1 f34c0fb8c2')
        prefix, bodies, suffix, report = regions.shared_lowering(
            instructions, {s.ip: Hints() for s in sites})
        self.assertIn('rax', report['gprs'])
        self.assertEqual(prefix.count('push rax'), 1)
        self.assertEqual(suffix.count('pop rax'), 1)
        # Both steps are POPCNT, so no body is a None (relocated glue).
        self.assertNotIn('push rax', '\n'.join([present(body) for body in bodies]))

    def test_shared_frame_rejects_ineligible_steps_without_mutation(self) -> None:
        instructions, sites = prepared('f3480fb8c1 488b17 f34c0fb8c2')
        hints = {s.ip: Hints() for s in sites}
        with self.assertRaises(ValueError):
            regions.shared_lowering(instructions, hints)
        regions.shared_lowering(instructions, hints, allow_loads=True)
        after, fresh = [str(i) for i in instructions], [str(i) for i in decode('f3480fb8c1 488b17 f34c0fb8c2')]
        self.assertEqual(after, fresh)

    def test_profile_hash_duplicates_and_counts_are_checked(self) -> None:
        with tempfile.TemporaryDirectory(prefix='penryn-region-profile-') as directory:
            path = Path(directory) / 'profile.json'
            # data's values type as object, so the duplicate case below reuses
            # data['site_counts'][0] through its name, row.
            row: dict[str, object] = {'address': '0x1000', 'executions': 3}
            data: dict[str, object] = {'input_sha256': 'abc', 'site_counts': [row]}
            path.write_text(json.dumps(data))
            counts = {0x1000: 3}
            self.assertEqual(regions.read_profile(path, 'abc'), counts)
            with self.assertRaises(ValueError):
                regions.read_profile(path, 'def')
            for rows in ([row] * 2,
                         [{'executions': 3}],
                         [{'address': '0x1000'}],
                         [{'address': 0x1000, 'executions': -1}],
                         [{'address': True, 'executions': 3}],
                         [{'address': 0x1000, 'executions': True}]):
                data['site_counts'] = rows
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    regions.read_profile(path, 'abc')


def oracle_cases() -> list[tuple[str, str, bool]]:
    registers = ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi'] + [f'r{n}' for n in range(8, 16)]
    cases: list[tuple[str, str, bool]] = []
    for size in (2, 4, 8):
        def sized(name: str) -> str:
            return lower._reg(iced_register(name.upper()), size)
        for index, destination in enumerate(registers):
            source = registers[(index + 1) % len(registers)]
            cases.append((f'popcnt {sized(destination)}, {sized(source)}\n'
                          f'popcnt {sized(source)}, {sized(destination)}', 'register', False))
    for source_size, destination_size in ((1, 4), (2, 4), (4, 4), (1, 8), (8, 8)):
        for index, destination in enumerate(registers):
            source = registers[(index + 1) % len(registers)]
            dst = lower._reg(iced_register(destination.upper()), destination_size)
            src = lower._reg(iced_register(source.upper()), source_size)
            cases.append((f'crc32 {dst}, {src}\ncrc32 {dst}, {src}', 'register', False))
    for high in ('ah', 'bh', 'ch', 'dh'):
        for dest in ('eax', 'ebx', 'ecx', 'edx'):
            cases.append((f'crc32 {dest}, {high}\npopcnt {dest}, {dest}\ncrc32 {dest}, {high}', 'register', False))
    # XMM numbers, not the register names destination and source hold above.
    for xmm_destination in range(16):
        xmm_source = (xmm_destination + 1) % 16
        cases.append((f'pcmpgtq xmm{xmm_destination}, xmm{xmm_source}\n'
                      f'pcmpgtq xmm{xmm_source}, xmm{xmm_destination}', 'register', False))
    cases.extend([
        ('popcnt r8, r9\nadd r10, r11\ncrc32 r12, r13\npcmpgtq xmm8, xmm9', 'register', False),
        ('pcmpgtq xmm8, xmm9\npxor xmm0, xmm0\npcmpgtq xmm10, xmm11\npxor xmm1, xmm1', 'register', False),
        ('popcnt rsi, rcx\nshl rdx, cl\ncrc32 r8, r9\nrol r10, cl\ncrc32 r11, r12', 'register', False),
        ('popcnt ax, bx\nmov cx, ax\npcmpgtq xmm7, xmm8\ncrc32 edx, ch', 'register', False),
        ('popcnt rax, QWORD PTR [rdi]\ncrc32 rcx, QWORD PTR [rdi+8]\npcmpgtq xmm1, XMMWORD PTR [rdi+16]', 'base', False),
        ('popcnt rax, rcx\nmov rdx, QWORD PTR [rdi]\ncrc32 r8, rdx', 'base', True),
        ('pcmpgtq xmm0, xmm1\nmovdqa xmm2, XMMWORD PTR [rdi+16]\npcmpgtq xmm3, xmm2', 'base', True),
        ('pcmpgtq xmm0, xmm1\nmovdqu xmm2, XMMWORD PTR [rdi+1]\npcmpgtq xmm3, xmm2', 'base', True),
        ('popcnt eax, eax\nmovdqa xmm1, XMMWORD PTR [rdi]\npcmpeqb xmm1, xmm0\n'
         'pmovmskb ecx, xmm1\npopcnt ecx, ecx\nmovdqa xmm1, XMMWORD PTR [rdi+16]\n'
         'pcmpeqb xmm1, xmm0\npmovmskb edx, xmm1\npopcnt edx, edx\n'
         'movdqa xmm1, XMMWORD PTR [rdi+32]\npcmpeqb xmm1, xmm0\n'
         'pmovmskb esi, xmm1\npopcnt esi, esi', 'base', True),
        ('\n'.join(f'popcnt {register}, {register}' for register in registers), 'register', False),
        ('\n'.join(f'pcmpgtq xmm{k}, xmm{(k + 1) % 16}' for k in range(16)), 'register', False),
    ])
    return cases


class Case(TypedDict):
    """One manifest row for test_lower's worker."""
    instruction: str
    mode: str
    dataflow: bool
    allow_loads: bool
    shared: regions.SharedFrame


def generate_oracle(directory: Path) -> Path:
    cases = oracle_cases()
    source = ['.intel_syntax noprefix\n.text\n']
    for index, (body, _, _) in enumerate(cases):
        source += [f'case_{index}:\n{body}\ncase_end_{index}:\n']
    path = directory / 'originals.s'
    path.write_text(''.join(source))
    obj = directory / 'originals.o'
    subprocess.run(['cc', '-c', '-o', str(obj), str(path)], check=True)
    elf = ELFFile(io.BytesIO(obj.read_bytes()))
    text = present(elf.get_section_by_name('.text')).data()
    symtab = elf.get_section_by_name('.symtab')
    assert isinstance(symtab, SymbolTableSection)
    symbols = {symbol.name: symbol['st_value'] for symbol in symtab.iter_symbols()}
    formatter = ix.Formatter(ix.FormatterSyntax.INTEL)
    formatter.hex_prefix, formatter.hex_suffix = '0x', ''
    manifest: list[Case]
    assembly, manifest = ['.intel_syntax noprefix\n.text\n'], []
    for case_index, (body, mode, allow_loads) in enumerate(cases):
        lo, hi = symbols[f'case_{case_index}'], symbols[f'case_end_{case_index}']
        steps = list(ix.Decoder(64, text[lo:hi], ip=0x2000000))
        for optimize in (False, True):
            hints = {ins.ip: analyze(steps[n + 1:]) if optimize else Hints()
                     for n, ins in enumerate(steps) if ins.mnemonic in lower.SUPPORTED}
            prefix, bodies, suffix, sharing = regions.shared_lowering(steps, hints, allow_loads=allow_loads)
            lowered = prefix + [replacement if replacement is not None else formatter.format(ins)
                                for ins, replacement in zip(steps, bodies)] + suffix
            index = len(manifest)
            assembly += [state_wrapper(f'native_{index}', body),
                         state_wrapper(f'lowered_{index}', '\n'.join(lowered))]
            manifest.append({'instruction': body, 'mode': mode, 'dataflow': optimize,
                             'allow_loads': allow_loads, 'shared': sharing})
    assembly += [lower.support_assembly(), '.section .testdata,"aw"\n.balign 16\n'
                 '.global test_memory\ntest_memory:\n.zero 64\n.section .note.GNU-stack,"",@progbits\n']
    source_file = directory / 'regions_test.s'
    source_file.write_text(''.join(assembly))
    library = directory / 'regions_test.so'
    subprocess.run(['cc', '-shared', '-nostdlib', '-o', str(library), str(source_file)], check=True)
    library.with_suffix('.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return library


class Arguments(argparse.Namespace):
    remote: str | None
    iterations: int
    output: Path | None


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remote', help='SSH host with hardware POPCNT/SSE4.2')
    parser.add_argument('--iterations', type=int, default=100)
    parser.add_argument('--output', type=Path, help='retain generated oracle artifacts here')
    args = parser.parse_args(namespace=Arguments())
    with tempfile.TemporaryDirectory(prefix='penryn-regions-') as temporary:
        directory = args.output or Path(temporary)
        directory.mkdir(parents=True, exist_ok=True)
        library = generate_oracle(directory)
        if args.remote:
            remote = subprocess.check_output(['ssh', args.remote, 'mktemp -d /tmp/penryn-regions.XXXXXXXX'], text=True).strip()
            try:
                subprocess.run(['scp', '-q', str(library), str(library.with_suffix('.json')),
                                str(Path(__file__).with_name('test_lower.py')), f'{args.remote}:{remote}/'], check=True)
                subprocess.run(['ssh', args.remote, 'python3', f'{remote}/test_lower.py',
                                '--run', f'{remote}/regions_test.so', '--iterations', str(args.iterations)], check=True)
            finally:
                subprocess.run(['ssh', args.remote, 'rm -rf -- ' + shlex.quote(remote)], check=True)
        else:
            worker(library, args.iterations)


if __name__ == '__main__':
    main()
