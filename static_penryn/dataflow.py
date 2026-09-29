"""Conservative, bounded liveness proofs on verified normal-execution paths.

Only unconditional full-register overwrites kill an old GPR value. Any read,
including address calculation or conditional use, makes it live. Analysis
stops at unknown control flow, faults/privileged operations, and real memory
accesses; bounded verified successors can be followed without assumptions
about calling conventions, distant blocks or signal handlers.
This is an optimization of normal execution, not async context equivalence.
"""
from dataclasses import dataclass
import iced_x86 as ix

GPRS = frozenset(range(ix.Register.RAX, ix.Register.R15 + 1)) - {ix.Register.RSP}
XMMS = frozenset(range(ix.Register.XMM0, ix.Register.XMM15 + 1))
STATUS = (ix.RflagsBits.CF | ix.RflagsBits.PF | ix.RflagsBits.AF |
          ix.RflagsBits.ZF | ix.RflagsBits.SF | ix.RflagsBits.OF)
READS = {ix.OpAccess.READ, ix.OpAccess.COND_READ, ix.OpAccess.READ_WRITE,
         ix.OpAccess.READ_COND_WRITE}
# Variable-count shifts/rotates are deliberately absent: zero can leave the
# flags untouched even though instruction metadata lists flags as modified.
FLAG_KILLERS = {getattr(ix.Mnemonic, name) for name in (
    'ADD', 'ADC', 'SUB', 'SBB', 'CMP', 'NEG', 'AND', 'OR', 'XOR', 'TEST',
    'INC', 'DEC', 'CLC', 'STC', 'POPCNT', 'PCMPISTRI', 'PCMPISTRM',
    'PCMPESTRI', 'PCMPESTRM', 'PCMPESTRI64', 'PCMPESTRM64')}
SAFE = {getattr(ix.Mnemonic, name) for name in (
    'MOV', 'MOVZX', 'MOVSX', 'MOVSXD', 'LEA', 'ADD', 'ADC', 'SUB', 'SBB',
    'CMP', 'NEG', 'NOT', 'AND', 'OR', 'XOR', 'TEST', 'INC', 'DEC', 'CLC',
    'STC', 'CMC', 'SHL', 'SHR', 'SAR', 'SAL', 'ROL', 'ROR', 'RCL', 'RCR',
    'BSWAP', 'XCHG', 'NOP', 'POPCNT', 'CRC32', 'PCMPGTQ', 'LAHF', 'SAHF')
    if hasattr(ix.Mnemonic, name)}
SAFE |= {value for name, value in vars(ix.Mnemonic).items()
         if name.startswith('CMOV') or name.startswith('SET')}
# Register-only integer/bitwise SSE operations do not raise floating-point
# exceptions. Memory operands still stop the proof. Scalar MOVSS/MOVSD and
# partial insertions are safe to inspect: iced describes the old-destination
# read, so they cannot incorrectly kill an entire XMM value.
SAFE |= {getattr(ix.Mnemonic, name) for name in (
    'MOVAPS', 'MOVAPD', 'MOVUPS', 'MOVUPD', 'MOVDQA', 'MOVDQU', 'MOVD', 'MOVQ',
    'MOVSS', 'MOVSD', 'PXOR', 'PAND', 'PANDN', 'POR', 'XORPS', 'XORPD', 'ANDPS',
    'ANDPD', 'ANDNPS', 'ANDNPD', 'ORPS', 'ORPD', 'PSHUFD', 'PSHUFLW', 'PSHUFHW',
    'SHUFPS', 'SHUFPD', 'PUNPCKLBW', 'PUNPCKLWD', 'PUNPCKLDQ', 'PUNPCKLQDQ',
    'PUNPCKHBW', 'PUNPCKHWD', 'PUNPCKHDQ', 'PUNPCKHQDQ', 'UNPCKLPS',
    'UNPCKLPD', 'UNPCKHPS', 'UNPCKHPD', 'PACKSSWB', 'PACKSSDW', 'PACKUSWB',
    'PCMPEQB', 'PCMPEQW', 'PCMPEQD', 'PCMPGTB', 'PCMPGTW', 'PCMPGTD',
    'PADDB', 'PADDW', 'PADDD', 'PADDQ', 'PADDSB', 'PADDSW', 'PADDUSB', 'PADDUSW',
    'PSUBB', 'PSUBW', 'PSUBD', 'PSUBQ', 'PSUBSB', 'PSUBSW', 'PSUBUSB', 'PSUBUSW',
    'PMULLW', 'PMULHW', 'PMULHUW', 'PMULUDQ', 'PMADDWD', 'PSADBW', 'PAVGB',
    'PAVGW', 'PMINUB', 'PMINSW', 'PMAXUB', 'PMAXSW', 'PSLLW', 'PSLLD', 'PSLLQ',
    'PSRLW', 'PSRLD', 'PSRLQ', 'PSRAW', 'PSRAD', 'PSLLDQ', 'PSRLDQ',
    'PINSRW', 'PEXTRW', 'PMOVMSKB', 'MOVMSKPS', 'MOVMSKPD')}


@dataclass(frozen=True)
class Hints:
    preserve_flags: bool = True
    dead_registers: frozenset = frozenset()
    dead_xmms: frozenset = frozenset()


def analyze(instructions, limit=24, *, lookup=None, bounds=None,
            max_nodes=64, max_branches=4):
    """Facts after a replacement; an unproven value always remains live.

    Without lookup/bounds, retain the original fall-through-only behavior.
    A lookup must return the instruction at a previously verified instruction
    boundary, or None. Bounds must contain the original instruction and its
    function. Direct branches may then be followed inside those bounds. Every
    successor must prove death; loops, missing successors, calls, memory and
    finite budgets stop each affected path conservatively. No ABI assumptions
    or execution-profile coverage are used as liveness evidence.
    """
    local = {}
    first = None
    previous = None
    for index, ins in enumerate(instructions):
        if index >= limit or (previous is not None and ins.ip != previous):
            break
        if first is None:
            first = ins.ip
        local[ins.ip] = ins
        previous = ins.next_ip
    if first is None:
        return Hints()
    cfg = lookup is not None and bounds is not None
    factory = ix.InstructionInfoFactory()
    budget = [max_nodes, max_branches]

    def result(dead, dead_xmm, flags_pending, flags_read):
        return Hints(flags_read or bool(flags_pending), frozenset(dead),
                     frozenset(dead_xmm))

    def merge(left, right):
        return Hints(left.preserve_flags or right.preserve_flags,
                     left.dead_registers & right.dead_registers,
                     left.dead_xmms & right.dead_xmms)

    def visit(address, pending, dead, pending_xmm, dead_xmm,
              flags_pending, flags_read, path, allow_local=True):
        while True:
            current = result(dead, dead_xmm, flags_pending, flags_read)
            if (address in path or budget[0] <= 0
                    or (cfg and not bounds[0] <= address < bounds[1])):
                return current
            # Direct destinations must go through lookup, including a branch
            # into the middle of the locally decoded fall-through window.
            ins = local.get(address) if allow_local else None
            if ins is None and cfg:
                ins = lookup(address)
            if (ins is None or ins.ip != address or ins.is_invalid
                    or ins.is_privileged or ins.has_lock_prefix
                    or ins.encoding != ix.EncodingKind.LEGACY
                    or (cfg and ins.next_ip > bounds[1])):
                return current
            direct = ins.flow_control in (
                ix.FlowControl.CONDITIONAL_BRANCH, ix.FlowControl.UNCONDITIONAL_BRANCH)
            if direct:
                if (not cfg or budget[1] <= 0 or ins.op0_kind not in (
                        ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32,
                        ix.OpKind.NEAR_BRANCH64)):
                    return current
            elif (ins.flow_control != ix.FlowControl.NEXT
                  or (ins.mnemonic not in SAFE and ins.mnemonic not in FLAG_KILLERS)):
                return current
            info = factory.info(ins)
            if any(m.access != ix.OpAccess.NO_MEM_ACCESS for m in info.used_memory()):
                return current
            registers = list(info.used_registers())
            if any(ix.RegisterExt.is_segment_register(reg.register) for reg in registers):
                return current
            budget[0] -= 1
            path = path | {address}
            for reg in registers:
                if reg.access in READS:
                    pending.discard(ix.RegisterExt.full_register(reg.register))
                    if ix.RegisterExt.is_vector_register(reg.register):
                        pending_xmm.discard(ix.Register.XMM0 + ix.RegisterExt.number(reg.register))
            for reg in registers:
                # iced reports zero-extending r32 writes as r64, but partial
                # writes as r8/r16. Read-modify-write operands were used above.
                if reg.access == ix.OpAccess.WRITE:
                    if ix.RegisterExt.is_gpr64(reg.register) and reg.register in pending:
                        dead.add(reg.register)
                        pending.remove(reg.register)
                    if ix.RegisterExt.is_xmm(reg.register) and reg.register in pending_xmm:
                        dead_xmm.add(reg.register)
                        pending_xmm.remove(reg.register)
            if ins.rflags_read & flags_pending:
                flags_read = True
            if ins.mnemonic in FLAG_KILLERS:
                flags_pending &= ~ins.rflags_modified
            if direct:
                budget[1] -= 1
                taken = visit(ins.near_branch_target, pending.copy(), dead.copy(),
                              pending_xmm.copy(), dead_xmm.copy(), flags_pending,
                              flags_read, path, allow_local=False)
                if ins.flow_control == ix.FlowControl.UNCONDITIONAL_BRANCH:
                    return taken
                fallen = visit(ins.next_ip, pending, dead, pending_xmm, dead_xmm,
                               flags_pending, flags_read, path, allow_local=False)
                return merge(taken, fallen)
            address = ins.next_ip
            if not pending and not pending_xmm and not flags_pending:
                return result(dead, dead_xmm, flags_pending, flags_read)

    return visit(first, set(GPRS), set(), set(XMMS), set(), STATUS, False, set())
