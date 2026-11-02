"""Bounded straight-line grouping; profiles select work, never prove safety.

Existing instruction lowerings remain the arithmetic implementation. A region
can share temporary registers unused by *every* original instruction, saving
their incoming values once at entry and restoring them once at exit. Ordinary
glue defaults to nonfaulting register operations with no stack/frame use.
Read-only load glue requires a separate opt-in for relocated fault contexts.
A POPCNT pair (qword_pairs) loads its later qword at the earlier POPCNT,
where a fault of that load is then raised.
"""
import bisect
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
import re
from typing import TYPE_CHECKING, Protocol, TypedDict

import iced_x86 as ix
from . import lower
from .checked import as_object, constants, is_list, load_json, member

if TYPE_CHECKING:
    from .dataflow import Hints
    from .patch import Site


_MNEMONICS = constants(ix.Mnemonic)
GLUE = {_MNEMONICS[name] for name in (
    'MOV', 'MOVZX', 'MOVSX', 'MOVSXD', 'LEA', 'ADD', 'SUB', 'AND', 'OR',
    'XOR', 'TEST', 'CMP', 'INC', 'DEC', 'NEG', 'NOT', 'BSWAP', 'NOP',
    'SHL', 'SHR', 'SAR', 'ROL', 'ROR', 'PXOR', 'PAND', 'POR', 'MOVDQA',
    'MOVDQU', 'MOVQ', 'MOVD', 'PSHUFD', 'PADDQ', 'PADDD', 'PSUBQ',
    'PSUBD', 'PCMPEQB', 'PCMPEQD', 'PCMPGTD', 'PMOVMSKB')}
INFO = ix.InstructionInfoFactory()


class BlockRecovery(Protocol):
    """What grouping reads of controlflow.Recovery; tests substitute fakes."""
    def bounds(self, address: int) -> tuple[int, int] | None: ...
    def block_bounds(self, address: int) -> tuple[int, int] | None: ...
    def lookup(self, address: int) -> ix.Instruction | None: ...


class SharedFrame(TypedDict):
    """shared_lowering's report of the region's shared save frame."""
    gprs: list[str]
    xmms: list[str]
    frame_bytes: int
    maximum_stack_bytes: int


def read_profile(path: Path, input_sha256: str) -> dict[int, int]:
    """Only exact-input execution profiles influence grouping and layout."""
    report = as_object(load_json(path.read_text()), 'profile')
    if report.get('input_sha256') != input_sha256:
        raise ValueError('profile belongs to a different original executable')
    rows = report.get('site_counts')
    if not is_list(rows):
        raise ValueError('profile requires a site_counts execution-count array')
    result: dict[int, int] = {}
    for row in rows:
        row = as_object(row, 'profile site count')
        raw = member(row, 'address', 'profile site count')
        address = int(raw, 0) if isinstance(raw, str) else raw
        count = member(row, 'executions', 'profile site count')
        if (type(address) is not int or not 0 <= address < 1 << 64
                or type(count) is not int or count < 0 or address in result):
            raise ValueError('profile contains an invalid or duplicate execution count')
        result[address] = count
    return result


def sequence(site: 'Site') -> list[ix.Instruction]:
    return site.sequence or site.insns + ([site.tail] if site.tail is not None else [])


def region_safe(ins: ix.Instruction, *, glue: bool = False, allow_loads: bool = False) -> bool:
    if ins.is_invalid or ins.has_lock_prefix or ins.is_privileged or ins.flow_control != ix.FlowControl.NEXT:
        return False
    if glue and ins.mnemonic not in GLUE:
        return False
    if not glue and ins.mnemonic not in lower.SUPPORTED:
        return False
    if any(ins.op_kind(n) == ix.OpKind.REGISTER
           and ix.RegisterExt.is_segment_register(ins.op_register(n)) for n in range(ins.op_count)):
        return False
    info = INFO.info(ins)
    for used in info.used_registers():
        reg = ix.RegisterExt.full_register(used.register)
        if reg in (ix.Register.RSP, ix.Register.RBP) or ix.RegisterExt.is_segment_register(used.register):
            # Default DS/SS memory segments are harmless in long mode; explicit
            # FS/GS and stack-relative accesses need a different contract.
            if used.register not in (ix.Register.DS, ix.Register.SS):
                return False
    if ins.memory_base in (ix.Register.EIP, ix.Register.RSP, ix.Register.ESP,
                           ix.Register.RBP, ix.Register.EBP):
        return False
    memories = [m for m in info.used_memory() if m.access != ix.OpAccess.NO_MEM_ACCESS]
    if glue and memories:
        if (not allow_loads or ins.mnemonic not in (ix.Mnemonic.MOV, ix.Mnemonic.MOVDQA, ix.Mnemonic.MOVDQU)
                or ins.op0_kind != ix.OpKind.REGISTER or ins.op1_kind != ix.OpKind.MEMORY
                or any(m.access != ix.OpAccess.READ for m in memories)):
            return False
    return True


def group(sites: Iterable['Site'], targets: Iterable[int], protected_ranges: Iterable[tuple[int, int]],
          recovery: BlockRecovery, *, weights: Mapping[int, int] | None = None,
          max_instructions: int = 24, max_bytes: int = 96, allow_loads: bool = False) -> list['Site']:
    """Merge within recovered function/block bounds, without known interior entries."""
    protected = sorted(targets)
    spans = sorted(protected_ranges)
    starts = [a for a, _ in spans]
    ends: list[int] = []
    for _, end in spans:
        ends.append(max(end, ends[-1] if ends else 0))

    def occupied(a: int, b: int) -> bool:
        index = bisect.bisect_left(protected, a)
        return index < len(protected) and protected[index] < b

    def protected_bytes(a: int, b: int) -> bool:
        index = bisect.bisect_left(starts, b) - 1
        return index >= 0 and ends[index] > a

    grouped: list['Site'] = []
    for candidate in sites:
        if not grouped:
            grouped.append(candidate)
            continue
        previous = grouped[-1]
        bounds = recovery.bounds(previous.ip) or recovery.block_bounds(previous.ip)
        eligible = (bounds is not None and candidate.end <= bounds[1]
                    and candidate.ip >= previous.end
                    and candidate.end - previous.ip <= max_bytes
                    and not occupied(previous.ip + 1, candidate.end)
                    and not protected_bytes(previous.ip, candidate.end))
        if weights is not None:
            eligible &= all(weights.get(i.ip, 0) > 0 for i in previous.insns + candidate.insns)
        old_steps, new_steps = sequence(previous), sequence(candidate)
        glue: list[ix.Instruction] = []
        address = previous.end
        if eligible:
            while address < candidate.ip and len(glue) < max_instructions:
                ins = recovery.lookup(address)
                if ins is None or ins.next_ip > candidate.ip or not region_safe(ins, glue=True, allow_loads=allow_loads):
                    break
                glue.append(ins)
                address = ins.next_ip
            eligible = address == candidate.ip
        combined = old_steps + glue + new_steps
        eligible &= len(combined) <= max_instructions
        eligible &= all(region_safe(i, glue=i.mnemonic not in lower.SUPPORTED, allow_loads=allow_loads) for i in combined)
        if not eligible:
            grouped.append(candidate)
            continue
        grouped[-1] = replace(previous, insns=previous.insns + candidate.insns,
                              hints=previous.hints + candidate.hints, end=candidate.end,
                              cave=None, tail=None, sequence=combined)
    return grouped


def mask_source(steps: Sequence[ix.Instruction], index: int) -> int | None:
    """The XMM register whose PMOVMSKB, the step just before, wrote the source
    of the POPCNT at index; adjacency is the proof that neither changed."""
    ins = steps[index]
    if ins.mnemonic != ix.Mnemonic.POPCNT or index == 0 or ins.op1_kind != ix.OpKind.REGISTER:
        return None
    previous = steps[index - 1]
    if (previous.mnemonic != ix.Mnemonic.PMOVMSKB or previous.op1_kind != ix.OpKind.REGISTER
            or not ix.RegisterExt.is_xmm(previous.op1_register)
            or ix.RegisterExt.full_register(previous.op0_register)
            != ix.RegisterExt.full_register(ins.op1_register)):
        return None
    return previous.op1_register


_WRITES = {ix.OpAccess.WRITE, ix.OpAccess.READ_WRITE, ix.OpAccess.COND_WRITE, ix.OpAccess.READ_COND_WRITE}


def _written(steps: Iterable[ix.Instruction]) -> set[int]:
    return {ix.RegisterExt.full_register(used.register) for ins in steps
            for used in INFO.info(ins).used_registers() if used.access in _WRITES}


def qword_pairs(steps: Sequence[ix.Instruction]) -> dict[int, int]:
    """POPCNT r64, m64 steps counted with the next such step, by index.

    Loading the later source with the earlier one reads what the later
    POPCNT would have read when two facts hold: no step between them
    accesses memory, so no other load of this thread is reordered with it,
    and neither the earlier POPCNT nor a step between writes a register of
    the later address. Pairs are taken left to right and never overlap.
    """
    pairs: dict[int, int] = {}
    first: int | None = None
    for index, ins in enumerate(steps):
        if lower.pairable(ins):
            address = {ix.RegisterExt.full_register(r) for r in (ins.memory_base, ins.memory_index)
                       if r != ix.Register.NONE}
            if first is not None and not address & _written(steps[first:index]):
                pairs[first] = index
                first = None
            else:
                first = index
        elif any(m.access != ix.OpAccess.NO_MEM_ACCESS for m in INFO.info(ins).used_memory()):
            first = None
    return pairs


def shared_lowering(steps: Sequence[ix.Instruction], hints: Mapping[int, 'Hints'], *,
                    allow_loads: bool = False) -> tuple[list[str], list[str | None], list[str], SharedFrame]:
    """Return prefix, per-instruction bodies, suffix, and shared-save report.

    None bodies are original glue instructions relocated by iced-x86. Every
    arithmetic body is generated by lower.lower; no second implementation of
    instruction semantics is introduced here. A POPCNT right after the
    PMOVMSKB that wrote its source is lowered from that PMOVMSKB's XMM
    register (mask_source). The POPCNT pairs of qword_pairs carry their
    counts in hold, the last of the free XMM registers, which no original
    instruction uses and no lowering from the first of a pair through the
    second takes as a temporary: a pair whose first lacks two more dead or
    free XMM registers stays scalar, and one pair is active at a time.
    """
    used_gprs: set[int]
    used_xmms: set[int]
    used_gprs, used_xmms = set(), set()
    for ins in steps:
        if not region_safe(ins, glue=ins.mnemonic not in lower.SUPPORTED, allow_loads=allow_loads):
            raise ValueError('region cannot safely share a scratch frame')
        for used in INFO.info(ins).used_registers():
            if ix.RegisterExt.is_gpr(used.register):
                used_gprs.add(ix.RegisterExt.full_register(used.register))
            elif ix.RegisterExt.is_xmm(used.register):
                used_xmms.add(used.register)
    free_gprs = frozenset(r for r in lower._REGS if r not in used_gprs and r != ix.Register.RBP)
    free_gprs = frozenset(sorted(free_gprs, key=lower._REGS.index)[:3])
    free_xmms = frozenset(r for r in range(ix.Register.XMM0, ix.Register.XMM15 + 1)
                          if r not in used_xmms)
    free_xmms = frozenset(sorted(free_xmms)[:3])
    hold = max(free_xmms, default=None)
    pairs = {first: second for first, second in qword_pairs(steps).items() if hold is not None
             and len((hints[steps[first].ip].dead_xmms | free_xmms) - {hold}) >= 2}
    seconds = set(pairs.values())
    held = {n for first, second in pairs.items() for n in range(first, second + 1)}
    bodies: list[str | None] = []
    for n, ins in enumerate(steps):
        if ins.mnemonic not in lower.SUPPORTED:
            bodies.append(None)
            continue
        hint = hints[ins.ip]
        dead_xmms = hint.dead_xmms | free_xmms
        if n in held and hold is not None:
            dead_xmms -= {hold}
        bodies.append(lower.lower(ins, preserve_flags=hint.preserve_flags,
                                  dead_registers=hint.dead_registers | free_gprs,
                                  dead_xmms=dead_xmms, mask_source=mask_source(steps, n),
                                  hold=hold if n in pairs or n in seconds else None,
                                  pair_second=steps[pairs[n]] if n in pairs else None))
    text = '\n'.join(b for b in bodies if b is not None)
    # Save only free temporaries actually selected by the shared allocator.
    saved_gprs = [r for r in lower._REGS if r in free_gprs
                  and any(re.search(r'\b' + alias + r'\b', text)
                          for alias in lower._WIDTH_NAMES[r] + (('ah',) if r == ix.Register.RAX else ()))]
    saved_xmms = [r for r in sorted(free_xmms) if re.search(r'\b' + lower.reg_name(r) + r'\b', text)]
    if not saved_gprs and not saved_xmms:
        return [], bodies, [], {'gprs': [], 'xmms': [], 'frame_bytes': 0,
                               'maximum_stack_bytes': lower.MAX_STACK_BYTES}
    # All original steps exclude stack/frame operands, so their addresses do
    # not depend on this outer frame. Nested lowerings keep their own offsets.
    delta = 128 + 16 * len(saved_xmms)
    prefix = [f'lea rsp, [rsp - {delta}]']
    prefix += [f'movdqu [rsp + {16 * n}], {lower.reg_name(r)}' for n, r in enumerate(saved_xmms)]
    prefix += [f'push {lower.reg_name(r)}' for r in saved_gprs]
    suffix = [f'pop {lower.reg_name(r)}' for r in reversed(saved_gprs)]
    suffix += [f'movdqu {lower.reg_name(r)}, [rsp + {16 * n}]' for n, r in enumerate(saved_xmms)]
    suffix += [f'lea rsp, [rsp + {delta}]']
    return prefix, bodies, suffix, {
        'gprs': [lower.reg_name(r) for r in saved_gprs],
        'xmms': [lower.reg_name(r) for r in saved_xmms],
        'frame_bytes': delta + len(saved_gprs) * 8,
        'maximum_stack_bytes': delta + len(saved_gprs) * 8 + lower.MAX_STACK_BYTES,
    }
