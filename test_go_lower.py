#!/usr/bin/env python3
"""Check Go's stack-neutral POPCNT contract against real hardware."""
import argparse
import io
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import iced_x86 as ix
from elftools.elf.elffile import ELFFile
from dataflow import Hints
import go_lower
import lower
from test_lower import state_wrapper, worker


def instruction(destination=ix.Register.RAX, source=ix.Register.RBX, width=8):
    if width == 4:
        destination = ix.RegisterExt.full_register32(destination)
        source = ix.RegisterExt.full_register32(source)
    return ix.Instruction.create_reg_reg(
        ix.Code.POPCNT_R64_RM64 if width == 8 else ix.Code.POPCNT_R32_RM32,
        destination, source)


class Contract(unittest.TestCase):
    def test_requires_dead_xmm(self):
        for available in (frozenset(), frozenset({ix.Register.XMM15})):
            with self.assertRaises(go_lower.Unsupported):
                go_lower.lower_popcnt(instruction(), dead_xmms=available)

    def test_reserved_destination(self):
        for register in (ix.Register.RSP, ix.Register.RBP, ix.Register.R14):
            with self.assertRaises(go_lower.Unsupported):
                go_lower.lower_popcnt(instruction(register), dead_xmms=frozenset({ix.Register.XMM0}))

    def test_proven_dead_gpr_needs_no_xmm(self):
        body, proof = go_lower.lower_popcnt(instruction(), Hints(dead_registers=frozenset({ix.Register.RCX})))
        self.assertEqual(proof['dead_xmms'], [])
        self.assertNotIn('rsp', body)
        self.assertNotIn('movq', body)

    def test_final_byte_audit(self):
        for code in (b'', b'\x50', b'\x5d', b'\x49\x89\xc6', b'\xff\xd0',
                     b'\x48\x8b\x00', b'\x48\x89\x00', b'\x48\x8b\x05\x00\x00\x00\x00'):
            with self.subTest(code=code.hex()), self.assertRaises(go_lower.Unsupported):
                go_lower.validate_emitted(code, 0x1000)
        go_lower.validate_emitted(b'\x48\x8b\x05\x00\x00\x00\x00', 0x1000,
                                  constant_ranges=[(0x1007, 0x100f)])


def generate(work):
    assembly = ['.intel_syntax noprefix', '.text']
    manifest = []
    formatter = ix.Formatter(ix.FormatterSyntax.INTEL)
    for destination in lower._REGS:
        if destination in (ix.Register.RBP, ix.Register.R14):
            continue
        for source in lower._REGS:
            for width in (4, 8):
                for flags in (False, True):
                    for xmm in (ix.Register.XMM0, ix.Register.XMM7, ix.Register.XMM14, None):
                        ins = instruction(destination, source, width)
                        dead = frozenset(lower._REGS) - {ix.Register.RBP, ix.Register.R14} if xmm is None else frozenset()
                        body, proof = go_lower.lower_popcnt(ins, Hints(preserve_flags=flags, dead_registers=dead),
                                                           dead_xmms=frozenset({xmm}) if xmm is not None else frozenset())
                        n = len(manifest)
                        assembly += [state_wrapper(f'native_{n}', formatter.format(ins)),
                                     state_wrapper(f'lowered_{n}',
                                                   f'.global body_{n}\nbody_{n}:\n{body}\n'
                                                   f'.global end_{n}\nend_{n}:')]
                        slots = ([r-ix.Register.RAX for r in dead if r != destination] if xmm is None else
                                 [17+2*(xmm-ix.Register.XMM0), 18+2*(xmm-ix.Register.XMM0)])
                        manifest.append(dict(instruction=formatter.format(ins), mode='register',
                                             preserve_flags=flags, proof=proof,
                                             dead_slots=slots))
    assembly += [lower.support_assembly(), '.data', '.global test_memory',
                 'test_memory: .zero 64', '.section .note.GNU-stack,"",@progbits']
    (work/'go_lower.S').write_text('\n'.join(assembly))
    library = work/'lower_test.so'
    subprocess.run(['cc', '-shared', '-fPIC', '-o', str(library), str(work/'go_lower.S')], check=True)
    elf = ELFFile(io.BytesIO(library.read_bytes()))
    symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
    code = elf.get_section_by_name('.text')
    rodata = elf.get_section_by_name('.rodata')
    for n in range(len(manifest)):
        a, b = symbols[f'body_{n}'], symbols[f'end_{n}']
        go_lower.validate_emitted(code.data()[a-code['sh_addr']:b-code['sh_addr']], a,
                                  constant_ranges=[(rodata['sh_addr'], rodata['sh_addr']+rodata['sh_size'])])
    library.with_suffix('.json').write_text(json.dumps(manifest))
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remote')
    parser.add_argument('--iterations', type=int, default=40)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Contract)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)
    with tempfile.TemporaryDirectory(prefix='penryn-go-lower-') as directory:
        library = generate(Path(directory))
        if args.remote:
            remote = subprocess.check_output(['ssh', args.remote, 'mktemp -d /tmp/penryn-go-lower.XXXXXXXX'], text=True).strip()
            try:
                subprocess.run(['scp', '-q', str(library), str(library.with_suffix('.json')),
                                str(Path(__file__).with_name('test_lower.py')), f'{args.remote}:{remote}/'], check=True)
                subprocess.run(['ssh', args.remote, 'python3', f'{remote}/test_lower.py', '--run',
                                f'{remote}/lower_test.so', '--iterations', str(args.iterations)], check=True)
            finally:
                subprocess.run(['ssh', args.remote, 'rm -rf -- ' + shlex.quote(remote)], check=True)
        else:
            worker(library, args.iterations)


if __name__ == '__main__':
    main()
