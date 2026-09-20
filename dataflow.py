"""Conservative, bounded liveness proofs for a single fall-through path.

Only unconditional full-register overwrites kill an old GPR value. Any read,
including address calculation or conditional use, makes it live. Analysis
stops at control flow, faults/privileged operations, and real memory accesses;
no assumptions about calling conventions, distant blocks or signal handlers.
This is an optimization of normal execution, not async context equivalence.
"""
from dataclasses import dataclass
import iced_x86 as ix

GPRS = frozenset(range(ix.Register.RAX, ix.Register.R15 + 1)) - {ix.Register.RSP}
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


@dataclass(frozen=True)
class Hints:
    preserve_flags: bool = True
    dead_registers: frozenset = frozenset()


def analyze(instructions, limit=24):
    """Facts after a replacement instruction; unknown values remain live."""
    pending = set(GPRS)
    dead = set()
    flags_pending = STATUS
    flags_read = False
    factory = ix.InstructionInfoFactory()
    for index, ins in enumerate(instructions):
        if (index >= limit or ins.is_invalid or ins.flow_control != ix.FlowControl.NEXT
                or ins.is_privileged or ins.has_lock_prefix):
            break
        if ins.mnemonic not in SAFE and ins.mnemonic not in FLAG_KILLERS:
            break
        info = factory.info(ins)
        if any(m.access != ix.OpAccess.NO_MEM_ACCESS for m in info.used_memory()):
            break
        registers = list(info.used_registers())
        if any(ix.RegisterExt.is_segment_register(reg.register) for reg in registers):
            break
        for reg in registers:
            if reg.access in READS:
                pending.discard(ix.RegisterExt.full_register(reg.register))
        for reg in registers:
            # iced reports r32 writes as their zero-extending r64 write, but
            # reports partial writes as r8/r16. CMOV's old-destination read
            # is processed above even where it also reports a full write.
            if reg.access == ix.OpAccess.WRITE and ix.RegisterExt.is_gpr64(reg.register):
                if reg.register in pending:
                    dead.add(reg.register)
                    pending.remove(reg.register)
        if ins.rflags_read & flags_pending:
            flags_read = True
        if ins.mnemonic in FLAG_KILLERS:
            flags_pending &= ~ins.rflags_modified
        if not pending and not flags_pending:
            break
    return Hints(flags_read or bool(flags_pending), frozenset(dead))
