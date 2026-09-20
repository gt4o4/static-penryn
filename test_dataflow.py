#!/usr/bin/env python3
"""Liveness counterexamples: preservation must win whenever proof is absent."""
import unittest
import iced_x86 as ix
from dataflow import analyze


def hints(hex_bytes):
    return analyze(ix.Decoder(64, bytes.fromhex(hex_bytes)))


class DataflowTests(unittest.TestCase):
    def test_zero_idiom_and_full_writes(self):
        h = hints('31c0 4889cb')  # xor eax,eax; mov rbx,rcx
        self.assertFalse(h.preserve_flags)
        self.assertEqual(h.dead_registers, {ix.Register.RAX, ix.Register.RBX})

    def test_partial_write_does_not_kill(self):
        self.assertNotIn(ix.Register.RAX, hints('88d8 4889c1').dead_registers)
        self.assertNotIn(ix.Register.RAX, hints('6689d8').dead_registers)

    def test_conditional_move_reads_old_destination(self):
        h = hints('0f44c1 31c0')  # cmove eax,ecx; xor eax,eax
        self.assertTrue(h.preserve_flags)
        self.assertNotIn(ix.Register.RAX, h.dead_registers)

    def test_sbb_reads_carry(self):
        self.assertTrue(hints('19c0').preserve_flags)

    def test_inc_does_not_kill_carry(self):
        self.assertTrue(hints('ffc0').preserve_flags)
        self.assertFalse(hints('ffc0 f8').preserve_flags)

    def test_variable_shift_does_not_prove_flag_death(self):
        self.assertTrue(hints('d3e0').preserve_flags)
        self.assertTrue(hints('c1e000').preserve_flags)

    def test_memory_and_control_flow_are_barriers(self):
        for code in ('488b00 31c0', 'e800000000 31c0', '7400 31c0', 'c3 31c0'):
            h = hints(code)
            self.assertTrue(h.preserve_flags)
            self.assertNotIn(ix.Register.RAX, h.dead_registers)

    def test_privileged_segment_and_lock_are_barriers(self):
        # mov rax,cr0; mov ax,ds; lock add eax,ebx (invalid prefix).
        for code in ('0f20c0 31c0', '668cd8 31c0', 'f001d8 31c0'):
            h = hints(code)
            self.assertTrue(h.preserve_flags)
            self.assertNotIn(ix.Register.RAX, h.dead_registers)

    def test_address_calculation_reads_registers(self):
        h = hints('488d0409 31c9')  # lea rax,[rcx+rcx]; xor ecx,ecx
        self.assertIn(ix.Register.RAX, h.dead_registers)
        self.assertNotIn(ix.Register.RCX, h.dead_registers)

    def test_used_alias_cannot_be_scratch(self):
        self.assertNotIn(ix.Register.RAX, hints('88c3 31c0').dead_registers)
        self.assertNotIn(ix.Register.RAX, hints('88e3 31c0').dead_registers)

    def test_lahf_observes_status(self):
        self.assertTrue(hints('9f 31c0').preserve_flags)

    def test_destination_reads_happen_before_writes(self):
        self.assertNotIn(ix.Register.RAX, hints('01d8').dead_registers)
        self.assertNotIn(ix.Register.RAX, hints('4887d8').dead_registers)

    def test_unanalysed_instructions_do_not_kill(self):
        self.assertTrue(hints('0fa2 31c0').preserve_flags)  # CPUID
        self.assertNotIn(ix.Register.RAX, hints('f7f3 31c0').dead_registers)  # DIV


if __name__ == '__main__':
    unittest.main(verbosity=2)
