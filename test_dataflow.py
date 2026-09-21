#!/usr/bin/env python3
"""Liveness counterexamples: preservation must win whenever proof is absent."""
import unittest
import iced_x86 as ix
from dataflow import analyze


def hints(hex_bytes):
    return analyze(ix.Decoder(64, bytes.fromhex(hex_bytes)))


def graph_hints(hex_bytes, *, missing=(), **kwargs):
    code = bytes.fromhex(hex_bytes)
    instructions = list(ix.Decoder(64, code, ip=0x1000))
    lookup = {ins.ip: ins for ins in instructions if ins.ip not in missing}
    return analyze(instructions, lookup=lookup.get,
                   bounds=(0x1000, 0x1000 + len(code)), **kwargs)


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

    def test_full_xmm_write_and_alias_reads(self):
        h = hints('660fefc0 660f6fd1')  # pxor xmm0,xmm0; movdqa xmm2,xmm1
        self.assertEqual(h.dead_xmms, {ix.Register.XMM0, ix.Register.XMM2})
        h = hints('660f6fc1 660fefc9')  # reading xmm1 first prevents its kill
        self.assertNotIn(ix.Register.XMM1, h.dead_xmms)

    def test_partial_xmm_write_and_arithmetic_reads(self):
        for code in ('f20f10c1 660fefc0', 'f30f10c1 660fefc0',
                     '660fc4c001 660fefc0', '660ffcc1 660fefc0'):
            self.assertNotIn(ix.Register.XMM0, hints(code).dead_xmms)

    def test_scalar_movq_kills_whole_xmm(self):
        self.assertIn(ix.Register.XMM0, hints('f30f7ec1').dead_xmms)

    def test_float_exceptions_and_vex_remain_barriers(self):
        for code in ('0f58c1 660fefc0', 'c5f957c0 31c0'):
            h = hints(code)
            self.assertFalse(h.dead_xmms)
            self.assertFalse(h.dead_registers)

    def test_both_conditional_successors_must_kill(self):
        # je right; xor eax,eax; jmp end; right: xor eax,eax; end: ret
        h = graph_hints('7404 31c0 eb02 31c0 c3')
        self.assertIn(ix.Register.RAX, h.dead_registers)
        self.assertTrue(h.preserve_flags)  # branch consumes old ZF
        h = graph_hints('7404 31c0 eb02 89c1 c3')
        self.assertNotIn(ix.Register.RAX, h.dead_registers)

    def test_all_paths_xmm_kills(self):
        h = graph_hints('7406 660fefc0 eb04 660fefc0 c3')
        self.assertIn(ix.Register.XMM0, h.dead_xmms)
        h = graph_hints('7406 660fefc0 eb04 660f6fc8 c3')
        self.assertNotIn(ix.Register.XMM0, h.dead_xmms)

    def test_branch_flags_read_after_a_kill_are_dead(self):
        self.assertFalse(graph_hints('31c9 7404 31c0 eb02 31c0 c3').preserve_flags)

    def test_loops_unknown_targets_and_limits_are_barriers(self):
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('7402 ebfc 31c0 c3').dead_registers)
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('7404 31c0 eb02 31c0 c3', missing={0x1006}).dead_registers)
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('7404 31c0 eb02 31c0 c3', max_branches=0).dead_registers)
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('7404 31c0 eb02 31c0 c3', max_nodes=2).dead_registers)

    def test_branch_into_middle_of_instruction_is_unknown(self):
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('eb01 b800000000 31c0 c3').dead_registers)

    def test_out_of_function_and_indirect_edges_are_unknown(self):
        self.assertNotIn(ix.Register.RAX, graph_hints('eb7e 31c0').dead_registers)
        self.assertNotIn(ix.Register.RAX, graph_hints('ffe1 31c0').dead_registers)

    def test_fault_on_one_successor_prevents_proof(self):
        self.assertNotIn(ix.Register.RAX,
                         graph_hints('7404 31c0 eb05 488b00 31c0 c3').dead_registers)

    def test_loop_after_kill_keeps_valid_proof(self):
        self.assertIn(ix.Register.RAX, graph_hints('31c0 ebfe').dead_registers)


if __name__ == '__main__':
    unittest.main(verbosity=2)
