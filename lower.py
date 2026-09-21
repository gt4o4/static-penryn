"""Leaf SSE4.2/POPCNT lowerings for x86-64 Penryn.

The caller emits Intel-syntax GAS and appends a jump to the continuation.
No register is reserved by the trampoline.  All stack writes are below the
original 128-byte SysV red zone.  As with any stack-using instrumentation,
the input must not alias the new scratch area below that red zone; the
additional stack must be mapped. Optional native unwind metadata is generated
separately by unwind.py. MAX_STACK_BYTES includes the protected red zone.

RIP memory loads deliberately use an explicit PC-relative relocation: GAS
silently treats an already-defined absolute .set symbol as a displacement.
The relocation remains correct when the containing ELF is loaded with a bias.
"""

import iced_x86 as ix


MAX_STACK_BYTES = 176
SUPPORTED = {ix.Mnemonic.POPCNT, ix.Mnemonic.CRC32, ix.Mnemonic.PCMPGTQ}
_FORMATTER = ix.Formatter(ix.FormatterSyntax.INTEL)
_REGS = [ix.Register.RAX, ix.Register.RCX, ix.Register.RDX,
         ix.Register.RBX, ix.Register.RSI, ix.Register.RDI,
         ix.Register.R8, ix.Register.R9, ix.Register.R10, ix.Register.R11,
         ix.Register.R12, ix.Register.R13, ix.Register.R14, ix.Register.R15,
         ix.Register.RBP]
_WIDTH_NAMES = {
    ix.Register.RAX: ("al", "ax", "eax", "rax"),
    ix.Register.RCX: ("cl", "cx", "ecx", "rcx"),
    ix.Register.RDX: ("dl", "dx", "edx", "rdx"),
    ix.Register.RBX: ("bl", "bx", "ebx", "rbx"),
    ix.Register.RSP: ("spl", "sp", "esp", "rsp"),
    ix.Register.RBP: ("bpl", "bp", "ebp", "rbp"),
    ix.Register.RSI: ("sil", "si", "esi", "rsi"),
    ix.Register.RDI: ("dil", "di", "edi", "rdi"),
    **{getattr(ix.Register, f"R{n}"): (f"r{n}b", f"r{n}w", f"r{n}d", f"r{n}")
       for n in range(8, 16)},
}
_MEM_SIZES = {1: "BYTE", 2: "WORD", 4: "DWORD", 8: "QWORD", 16: "XMMWORD"}


class LoweringError(ValueError):
    """A form that cannot be lowered with the implemented guarantees."""


def reg_name(register):
    return _FORMATTER.format_register(register).lower()


def _reg(register, size=8):
    return _WIDTH_NAMES[ix.RegisterExt.full_register(register)][{1: 0, 2: 1, 4: 2, 8: 3}[size]]


def _signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def _address_size(ins):
    memories = ix.InstructionInfoFactory().info(ins).used_memory()
    if not memories:
        raise LoweringError("instruction has no memory operand")
    return memories[0].address_size


def memory_operand(ins, operand_index=1, stack_delta=0):
    """Render a memory operand; use memory_load() to include RIP relocation.

    stack_delta is original RSP minus current RSP.  Other address registers
    must still contain their original values at the actual load.
    """
    if ins.op_kind(operand_index) != ix.OpKind.MEMORY:
        raise LoweringError("expected an ordinary memory operand")
    if ins.memory_base == ix.Register.EIP:
        raise LoweringError("EIP-relative addr32 memory is not supported")
    address_size = _address_size(ins)
    if address_size not in (ix.CodeSize.CODE32, ix.CodeSize.CODE64):
        raise LoweringError("only 32- and 64-bit addressing is supported")
    size = ix.MemorySizeExt.size(ins.memory_size)
    if size not in _MEM_SIZES:
        raise LoweringError(f"unsupported memory width {size}")
    segment = ""
    if ins.memory_segment in (ix.Register.FS, ix.Register.GS):
        segment = reg_name(ins.memory_segment) + ":"
    if ins.memory_base == ix.Register.RIP:
        return f"{_MEM_SIZES[size]} PTR {segment}[rip]"
    parts = []
    if ins.memory_base != ix.Register.NONE:
        parts.append(reg_name(ins.memory_base))
    if ins.memory_index != ix.Register.NONE:
        parts.append(f"{reg_name(ins.memory_index)}*{ins.memory_index_scale}")
    bits = 32 if address_size == ix.CodeSize.CODE32 else 64
    displacement = _signed(ins.memory_displacement, bits)
    if ins.memory_base in (ix.Register.RSP, ix.Register.ESP):
        displacement += stack_delta
        if bits == 32:
            displacement = _signed(displacement, 32)
    # A 64-bit effective address still has only a signed 32-bit displacement.
    if bits == 64 and not -(1 << 31) <= displacement < (1 << 31):
        raise LoweringError("stack adjustment exceeds encodable memory displacement")
    if displacement or not parts:
        parts.append(str(displacement))
    return f"{_MEM_SIZES[size]} PTR {segment}[{' + '.join(parts)}]"


def memory_load(ins, destination, stack_delta=0, mnemonic="mov", operand_index=1):
    """A complete GAS load, including any RIP relocation and addr32 prefix."""
    operand = memory_operand(ins, operand_index, stack_delta)
    prefix = "addr32 " if _address_size(ins) == ix.CodeSize.CODE32 else ""
    result = f"{prefix}{mnemonic} {destination}, {operand}"
    if ins.memory_base == ix.Register.RIP:
        result += f"\n.reloc .-4, R_X86_64_PC32, 0x{ins.ip_rel_memory_address:x}-4"
    return result


def _source_size(ins):
    if ins.op1_kind == ix.OpKind.REGISTER:
        return ix.RegisterExt.size(ins.op1_register)
    if ins.op1_kind == ix.OpKind.MEMORY:
        return ix.MemorySizeExt.size(ins.memory_size)
    raise LoweringError("unsupported source operand")


def _source_load(ins, scratch, stack_delta):
    size = _source_size(ins)
    if size not in (1, 2, 4, 8):
        raise LoweringError(f"unsupported scalar source width {size}")
    target = _reg(scratch, max(size, 4))
    opcode = "movzx" if size < 4 else "mov"
    if ins.op1_kind == ix.OpKind.MEMORY:
        return [memory_load(ins, target, stack_delta, opcode)]
    source = ins.op1_register
    if ix.RegisterExt.full_register(source) == ix.Register.RSP:
        lines = [f"lea {_reg(scratch)}, [rsp + {stack_delta}]"]
        if size < 4:
            lines.append(f"movzx {_reg(scratch, 4)}, {_reg(scratch, size)}")
        elif size == 4:
            lines.append(f"mov {_reg(scratch, 4)}, {_reg(scratch, 4)}")
        return lines
    return [f"{opcode} {target}, {reg_name(source)}"]


def _prologue(scratch, preserve_flags):
    if not scratch and not preserve_flags:
        return []
    return (["lea rsp, [rsp - 128]"] + (["pushfq"] if preserve_flags else [])
            + [f"push {_reg(r)}" for r in scratch])


def _epilogue(scratch, preserve_flags):
    if not scratch and not preserve_flags:
        return []
    return ([f"pop {_reg(r)}" for r in reversed(scratch)]
            + (["popfq"] if preserve_flags else []) + ["lea rsp, [rsp + 128]"])


def _scalar_scratch(ins, count, dead_registers):
    if ins.op0_kind != ix.OpKind.REGISTER or not ix.RegisterExt.is_gpr(ins.op0_register):
        raise LoweringError("expected a general-purpose destination register")
    destination = ix.RegisterExt.full_register(ins.op0_register)
    if destination == ix.Register.RSP:
        raise LoweringError("RSP/ESP/SP destinations require a different trampoline")
    candidates = sorted((r for r in _REGS if r != destination),
                        key=lambda r: r not in dead_registers)
    # MOVZX r32, AH/CH/DH/BH cannot carry REX. The first temporary receives
    # the source before any other register changes; this also handles aliases
    # with the destination and memory base/index without special cases.
    if ins.op1_kind == ix.OpKind.REGISTER and ins.op1_register in (
            ix.Register.AH, ix.Register.CH, ix.Register.DH, ix.Register.BH):
        legacy = next(r for r in candidates if r < ix.Register.R8)
        candidates.remove(legacy)
        candidates.insert(0, legacy)
    return candidates[:count]


def _frame(scratch, preserve_flags, dead_registers):
    saved = [r for r in scratch if r not in dead_registers]
    delta = 128 + len(saved) * 8 + 8 * preserve_flags if saved or preserve_flags else 0
    return saved, delta


def _popcnt(ins, preserve_flags, dead_registers):
    size = ix.RegisterExt.size(ins.op0_register)
    if size not in (2, 4, 8) or _source_size(ins) != size:
        raise LoweringError("unsupported POPCNT form")
    destination = ix.RegisterExt.full_register(ins.op0_register)
    if destination == ix.Register.RSP:
        raise LoweringError("RSP/ESP/SP destinations require a different trampoline")
    if preserve_flags:
        # SAHF reconstructs POPCNT's complete defined flag result. RAX is
        # either the scratch register or the destination written afterward.
        if destination == ix.Register.RAX:
            scratch = _scalar_scratch(ins, 2 if size == 2 else 1, dead_registers)
            value = scratch[0]
            temporary = scratch[1] if size == 2 else ix.Register.RAX
        elif size == 2:
            value = next(r for r in _scalar_scratch(ins, 3, dead_registers) if r != ix.Register.RAX)
            scratch = [value, ix.Register.RAX]
            temporary = ix.Register.RAX
        else:
            scratch = [ix.Register.RAX]
            value, temporary = ins.op0_register, ix.Register.RAX
    else:
        scratch = _scalar_scratch(ins, 2 if size == 2 else 1, dead_registers)
        value = scratch[0] if size == 2 else ins.op0_register
        temporary = scratch[-1]
    saved, stack_delta = _frame(scratch, False, dead_registers)
    width = max(size, 4)
    v, t = _reg(value, width), _reg(temporary, width)
    masks = (["QWORD PTR [rip + .Lpenryn_pop55]", "QWORD PTR [rip + .Lpenryn_pop33]",
              "QWORD PTR [rip + .Lpenryn_pop0f]", "QWORD PTR [rip + .Lpenryn_pop01]"]
             if width == 8 else ["0x55555555", "0x33333333", "0x0f0f0f0f", "0x01010101"])
    lines = _prologue(saved, False) + _source_load(ins, value, stack_delta)
    # Fixed-work SWAR: pair counts, nibble counts, byte counts, horizontal sum.
    lines += [f"mov {t}, {v}", f"shr {t}, 1", f"and {t}, {masks[0]}", f"sub {v}, {t}",
              f"mov {t}, {v}", f"shr {t}, 2", f"and {v}, {masks[1]}",
              f"and {t}, {masks[1]}", f"add {v}, {t}", f"mov {t}, {v}",
              f"shr {t}, 4", f"add {v}, {t}", f"and {v}, {masks[2]}",
              f"imul {v}, {masks[3]}", f"shr {v}, {width * 8 - 8}"]
    if preserve_flags:
        # CF from count<1 becomes AH=0x40 iff count==0. AND clears OF,
        # SAHF sets the other five status flags from AH, and neither changes
        # DF or control flags. This avoids the expensive serializing POPFQ.
        lines += [f"cmp {v}, 1", "sbb ah, ah", "and ah, 64", "sahf"]
    if ix.RegisterExt.full_register(value) != destination:
        lines.append(f"mov {reg_name(ins.op0_register)}, {_reg(value, size)}")
    return lines + _epilogue(saved, False)


def _crc32(ins, preserve_flags, dead_registers):
    destination_size = ix.RegisterExt.size(ins.op0_register)
    source_size = _source_size(ins)
    if destination_size not in (4, 8) or source_size not in (1, 2, 4, 8):
        raise LoweringError("unsupported CRC32 form")
    if (destination_size == 8 and source_size not in (1, 8)) or (destination_size == 4 and source_size == 8):
        raise LoweringError("invalid CRC32 operand widths")
    scratch = _scalar_scratch(ins, 3, dead_registers)
    if preserve_flags and ix.RegisterExt.full_register(ins.op0_register) != ix.Register.RAX and ix.Register.RAX not in scratch:
        scratch[-1] = ix.Register.RAX
    source, index, table = scratch
    saved, stack_delta = _frame(scratch, preserve_flags, dead_registers)
    lines = _prologue(saved, preserve_flags) + _source_load(ins, source, stack_delta)
    crc = _reg(ins.op0_register, 4)
    lines.append(f"lea {_reg(table)}, [rip + .Lpenryn_crc32c]")
    if source_size < 4:
        # Narrow forms retain the unused high seed bytes. Fold only the
        # consumed bytes through the table and xor the shifted seed afterward.
        lines += [f"xor {_reg(source, 4)}, {crc}", f"shr {crc}, {source_size * 8}"]
    else:
        # CRC32 r64 reads only the low 32 bits of its old destination.
        if source_size == 8:
            lines.append(f"mov {crc}, {crc}")
        lines.append(f"xor {_reg(source, max(source_size, 4))}, {_reg(ins.op0_register, max(source_size, 4))}")
    # Slicing-by-width makes all table loads independent of each other's
    # results. Eight shared 256-entry tables cover every scalar CRC32 form.
    for byte in range(source_size):
        lines.append(f"movzx {_reg(index, 4)}, {_reg(source, 1)}")
        operation = "mov" if byte == 0 and source_size >= 4 else "xor"
        offset = (source_size - byte - 1) * 1024
        lines.append(f"{operation} {crc}, DWORD PTR [{_reg(table)} + {_reg(index)}*4 + {offset}]")
        if byte + 1 < source_size:
            lines.append(f"shr {_reg(source, max(source_size, 4))}, 8")
    if preserve_flags:
        # Restore only the six arithmetic flags our integer code changes.
        # AH receives saved SF/ZF/AF/PF/CF. AL=0 or 8 plus 120 reconstructs OF
        # before SAHF (which leaves OF unchanged). DF and control flags have
        # never changed, so avoiding POPFQ preserves them without its cost.
        output_is_rax = ix.RegisterExt.full_register(ins.op0_register) == ix.Register.RAX
        if output_is_rax:
            lines.append(f"mov {_reg(source, 4)}, eax")
        flags_offset = len(saved) * 8
        lines += [f"mov ah, BYTE PTR [rsp + {flags_offset}]",
                  f"mov al, BYTE PTR [rsp + {flags_offset + 1}]",
                  "and al, 8", "add al, 120", "sahf"]
        if output_is_rax:
            lines.append(f"mov eax, {_reg(source, 4)}")
        lines += [f"pop {_reg(r)}" for r in reversed(saved)]
        return lines + ["lea rsp, [rsp + 136]"]
    return lines + _epilogue(saved, False)


def _pcmpgtq(ins, preserve_flags, dead_registers, dead_xmms=frozenset()):
    if ins.op0_kind != ix.OpKind.REGISTER or not ix.RegisterExt.is_xmm(ins.op0_register):
        raise LoweringError("expected an XMM destination")
    if _source_size(ins) != 16:
        raise LoweringError("expected a 128-bit PCMPGTQ source")
    destination = reg_name(ins.op0_register)
    if ins.op1_kind == ix.OpKind.REGISTER and ins.op0_register == ins.op1_register:
        return [f"pxor {destination}, {destination}"]
    excluded = {ins.op0_register, ins.op1_register}
    count = 3 if ins.op1_kind == ix.OpKind.MEMORY else 2
    candidates = sorted((r for r in range(ix.Register.XMM0, ix.Register.XMM15 + 1)
                         if r not in excluded), key=lambda r: r not in dead_xmms)
    scratch_regs = candidates[:count]
    scratch = [reg_name(r) for r in scratch_regs]
    saved = [reg_name(r) for r in scratch_regs if r not in dead_xmms]
    difference, equal = scratch[:2]
    stack_delta = 128 + 16 * len(saved) if saved else 0
    lines = [f"lea rsp, [rsp - {stack_delta}]"] if stack_delta else []
    lines += [f"movdqu XMMWORD PTR [rsp + {i * 16}], {r}" for i, r in enumerate(saved)]
    if ins.op1_kind == ix.OpKind.MEMORY:
        source = scratch[2]
        # Legacy PCMPGTQ memory requires 16-byte alignment; preserve that fault.
        lines.append(memory_load(ins, source, stack_delta, "movdqa"))
    else:
        source = reg_name(ins.op1_register)
    # Compare high dwords signed. If equal, the sign of (source-destination)
    # resolves the low dwords unsigned without changing any integer flags.
    lines += [f"movdqa {difference}, {source}", f"movdqa {equal}, {destination}",
              f"psubq {difference}, {destination}", f"psrad {difference}, 31",
              f"pcmpeqd {equal}, {source}", f"pcmpgtd {destination}, {source}",
              f"pand {difference}, {equal}", f"por {destination}, {difference}",
              f"pshufd {destination}, {destination}, 0xf5"]
    lines += [f"movdqu {r}, XMMWORD PTR [rsp + {i * 16}]" for i, r in enumerate(saved)]
    return lines + ([f"lea rsp, [rsp + {stack_delta}]"] if stack_delta else [])


def support_assembly():
    """Shared read-only constants, position independent and Penryn compatible."""
    tables = []
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        table.append(value)
    tables.append(table)
    for _ in range(7):
        tables.append([(v >> 8) ^ table[v & 255] for v in tables[-1]])
    lines = ['.section .rodata.penryn.crc32c,"a",@progbits', '.balign 64', '.Lpenryn_crc32c:']
    for table in tables:
        lines.extend('.long ' + ', '.join(f'0x{v:08x}' for v in table[i:i + 8])
                     for i in range(0, 256, 8))
    lines += ['.section .rodata.penryn.popcnt,"a",@progbits', '.balign 64']
    for label, value in (("55", "5555555555555555"), ("33", "3333333333333333"),
                         ("0f", "0f0f0f0f0f0f0f0f"), ("01", "0101010101010101")):
        lines += [f'.Lpenryn_pop{label}:', f'.quad 0x{value}']
    return "\n".join(lines) + "\n"


def lower(ins, *, preserve_flags=True, dead_registers=frozenset(), dead_xmms=frozenset()):
    """Return leaf Intel-syntax GAS, excluding header and continuation jump.

    Defaults preserve every non-output register and architecturally specified
    flag. Callers may elide GPR saves or arithmetic-flag restoration only with
    a proof that their original values are dead after this instruction. Even
    with preserve_flags=False, DF and control flags are never changed.
    """
    if ins.has_lock_prefix:
        raise LoweringError("LOCK-prefixed instruction cannot be lowered")
    if not isinstance(preserve_flags, bool):
        raise LoweringError("preserve_flags must be boolean")
    if any(r not in _WIDTH_NAMES or r == ix.Register.RSP for r in dead_registers):
        raise LoweringError("dead_registers must contain full non-stack GPRs")
    if any(not ix.Register.XMM0 <= r <= ix.Register.XMM15 for r in dead_xmms):
        raise LoweringError("dead_xmms must contain legacy XMM0..XMM15 registers")
    implementation = {ix.Mnemonic.POPCNT: _popcnt, ix.Mnemonic.CRC32: _crc32,
                      ix.Mnemonic.PCMPGTQ: _pcmpgtq}.get(ins.mnemonic)
    if implementation is None:
        raise LoweringError(f"unsupported instruction: {_FORMATTER.format(ins)}")
    if ins.mnemonic == ix.Mnemonic.PCMPGTQ:
        return "\n".join(_pcmpgtq(ins, preserve_flags, dead_registers, dead_xmms)) + "\n"
    return "\n".join(implementation(ins, preserve_flags, dead_registers)) + "\n"
