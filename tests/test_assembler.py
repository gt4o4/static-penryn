"""The assembler: LLVM's exit() becomes an exception, and objects are unchanged."""
import unittest

import llvmlite.binding as llvm

from static_penryn import assembler

VALID = (
    '.intel_syntax noprefix\n.text\n.globl f\nf:\n  popcnt rax, rbx\n  ret\n',
    '.text\n.globl g\ng:\n  .cfi_startproc\n  pushq %rbp\n  .cfi_def_cfa_offset 16\n'
    '  .cfi_offset 6, -16\n  popq %rbp\n  .cfi_def_cfa_offset 8\n  ret\n  .cfi_endproc\n',
    '.section .rodata\n.p2align 4\nmask:\n  .quad 0x5555555555555555, 0x3333333333333333\n'
    '.text\nh:\n  movdqa mask(%rip), %xmm0\n  .reloc ., R_X86_64_NONE, h\n  ret\n',
)
INVALID = '.text\npopcnt rax, rbx\n'  # AT&T syntax needs a size suffix here


def in_process(source: str) -> bytes:
    """llvmlite's own emission, for comparison."""
    module = llvm.parse_assembly(f'module asm "{assembler._ir_string(source)}"\n')
    return assembler._machine().emit_object(module)


class AssemblerTests(unittest.TestCase):
    def test_object_matches_llvmlite_emission(self) -> None:
        for source in VALID:
            with self.subTest(source=source):
                self.assertEqual(assembler.assemble(source), in_process(source))

    def test_exit_becomes_value_error_and_emission_continues(self) -> None:
        for _ in range(3):
            with self.assertRaises(ValueError) as caught:
                assembler.assemble(INVALID)
            message = str(caught.exception)
            self.assertIn('exit(1)', message)
            self.assertIn('error: <inline asm>', message)
        for source in VALID:
            self.assertEqual(assembler.assemble(source), in_process(source))


if __name__ == '__main__':
    unittest.main()
