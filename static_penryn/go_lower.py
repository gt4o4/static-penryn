"""Stack-neutral Go POPCNT lowerings composed from the scalar implementation.

A scratch GPR is parked in an independently proven-dead XMM register. Go
metadata must mark the entire range unsafe for asynchronous preemption while
a pointer may temporarily be hidden in that XMM register. This module never
assumes that an arbitrary XMM is free: the caller supplies proof-backed hints.
"""
from collections.abc import Iterable, Sequence
import re
from typing import TYPE_CHECKING, NotRequired, TypedDict

import iced_x86 as ix

from .dataflow import Hints
from . import lower

if TYPE_CHECKING:
    from .go_runtime import Audit, AuditFunction
    from .patch import Site


class Unsupported(ValueError):
    pass


# Stack use, which the Go contract forbids.
_STACK = re.compile(r'\b(?:push\w*|pop(?:fq)?|rsp|esp)\b')


class LoweringProof(TypedDict):
    """Why a Go POPCNT body leaves the stack, frame and goroutine register intact."""
    kind: str
    stack_delta: int
    no_calls: bool
    no_memory_writes: bool
    preserved_frame_pointer: bool
    preserved_goroutine_register: bool
    dead_gprs: NotRequired[list[str]]
    dead_xmms: list[str]
    parked_gprs: list[str]
    requires_unsafe_pcdata: bool


class SiteProof(LoweringProof):
    original_pc: int
    function: str
    scratch_proof: str
    layout_profile: str


class Rejection(TypedDict):
    address: int
    function: str
    reason: str


def lower_popcnt(ins: ix.Instruction, hints: Hints = Hints(), *,
                 dead_xmms: frozenset[int] = frozenset()) -> tuple[str, LoweringProof]:
    if (ins.mnemonic != ix.Mnemonic.POPCNT
            or ins.op0_kind != ix.OpKind.REGISTER or ins.op1_kind != ix.OpKind.REGISTER
            or ix.RegisterExt.size(ins.op0_register) not in (4, 8)):
        raise Unsupported('Go lowering requires a register-only 32/64-bit POPCNT')
    destination = ix.RegisterExt.full_register(ins.op0_register)
    if destination in (ix.Register.RSP, ix.Register.RBP, ix.Register.R14):
        raise Unsupported('Go lowering cannot change RSP, RBP or the goroutine register')
    dead_gprs = hints.dead_registers - {ix.Register.RBP, ix.Register.R14}
    direct = lower.lower(ins, preserve_flags=hints.preserve_flags, dead_registers=dead_gprs)
    if not _STACK.search(direct):
        return direct, {
            'kind': 'go-stack-neutral-popcnt', 'stack_delta': 0,
            'no_calls': True, 'no_memory_writes': True,
            'preserved_frame_pointer': True, 'preserved_goroutine_register': True,
            'dead_gprs': [lower.reg_name(r) for r in sorted(dead_gprs)],
            'dead_xmms': [], 'parked_gprs': [], 'requires_unsafe_pcdata': True,
        }
    available = sorted((hints.dead_xmms | dead_xmms) &
                       frozenset(range(ix.Register.XMM0, ix.Register.XMM15)))
    if not available:
        raise Unsupported('Go lowering has no proven-dead non-reserved XMM scratch register')
    # Existing SWAR code needs one temporary at these widths. Pretend the GPR
    # is dead only to suppress its stack save; the wrapper saves it in XMM.
    temporaries = frozenset(lower._REGS) - {ix.Register.RBP, ix.Register.R14}
    body = lower.lower(ins, preserve_flags=hints.preserve_flags,
                       dead_registers=temporaries)
    scratch = ix.Register.RCX if destination == ix.Register.RAX else ix.Register.RAX
    scratch_name = lower.reg_name(scratch)
    xmm = available[0]
    xmm_name = lower.reg_name(xmm)
    if _STACK.search(body):
        raise Unsupported('scalar implementation introduced a forbidden Go stack/register operation')
    # Preserve even GPRs declared dead: the only non-output clobber is the
    # explicitly dead XMM, keeping original GPR pointer values at both exits.
    assembly = f'movq {xmm_name}, {scratch_name}\n{body}\nmovq {scratch_name}, {xmm_name}'
    return assembly, {
        'kind': 'go-stack-neutral-popcnt', 'stack_delta': 0,
        'no_calls': True, 'no_memory_writes': True,
        'preserved_frame_pointer': True, 'preserved_goroutine_register': True,
        'dead_xmms': [xmm_name], 'parked_gprs': [scratch_name],
        'requires_unsafe_pcdata': True,
    }


def validate_emitted(code: bytes, address: int, *,
                     constant_ranges: Sequence[tuple[int, int]] = ()) -> list[ix.Instruction]:
    """Audit final linked bytes; constants may be read only through RIP."""
    info = ix.InstructionInfoFactory()
    instructions = list(ix.Decoder(64, code, ip=address))
    for n, ins in enumerate(instructions):
        if (ins.is_invalid or ins.is_privileged or ins.has_lock_prefix
                or ins.encoding != ix.EncodingKind.LEGACY):
            raise Unsupported(f'unsupported Go replacement encoding: {ins}')
        if ins.flow_control != ix.FlowControl.NEXT:
            if (n != len(instructions)-1 or ins.flow_control != ix.FlowControl.UNCONDITIONAL_BRANCH
                    or ins.op0_kind != ix.OpKind.NEAR_BRANCH64):
                raise Unsupported(f'Go replacement contains a call or internal control flow: {ins}')
        for register in info.info(ins).used_registers():
            if (register.access in (ix.OpAccess.WRITE, ix.OpAccess.COND_WRITE,
                                    ix.OpAccess.READ_WRITE, ix.OpAccess.READ_COND_WRITE)
                    and ix.RegisterExt.full_register(register.register) in
                    (ix.Register.RSP, ix.Register.RBP, ix.Register.R14, ix.Register.ZMM15)):
                raise Unsupported(f'Go replacement changes a reserved register: {ins}')
        for memory in info.info(ins).used_memory():
            if (memory.access != ix.OpAccess.READ or ins.memory_base != ix.Register.RIP
                    or ins.memory_segment in (ix.Register.FS, ix.Register.GS)):
                raise Unsupported(f'Go replacement accesses unverified memory: {ins}')
            size = ix.MemorySizeExt.size(memory.memory_size)
            if not any(a <= ins.ip_rel_memory_address and
                       ins.ip_rel_memory_address + size <= b for a, b in constant_ranges):
                raise Unsupported(f'Go replacement reads outside verified constants: {ins}')
    if not instructions or instructions[-1].next_ip != address + len(code):
        raise Unsupported('empty or truncated Go replacement')
    return instructions


def unused_function_xmms(audit: 'Audit', function: 'AuditFunction') -> frozenset[int]:
    """Borrow an unused register only under a verified Go ABIInternal profile."""
    if not audit.abi_internal(function):
        return frozenset()
    start, end = function['start'], function['end']
    if end - start > 1024 * 1024:
        return frozenset()
    unused = set(range(ix.Register.XMM0, ix.Register.XMM15))
    factory = ix.InstructionInfoFactory()
    for ins in ix.Decoder(64, audit.read(start, end-start), ip=start):
        if ins.is_invalid:
            return frozenset()
        for used in factory.info(ins).used_registers():
            full = ix.RegisterExt.full_register(used.register)
            if ix.Register.ZMM0 <= full <= ix.Register.ZMM31:
                unused.discard(ix.Register.XMM0 + full - ix.Register.ZMM0)
    return frozenset(unused)


def prepare(sites: 'Iterable[Site]', audit: 'Audit', *, allow_abi_borrow: bool = True
            ) -> tuple[dict[int, str], dict[int, SiteProof], list[Rejection]]:
    """Prepare independently supported Go sites, recording every rejection."""
    bodies: dict[int, str] = {}
    proofs: dict[int, SiteProof] = {}
    rejected: list[Rejection] = []
    borrowed: dict[int, frozenset[int]] = {}
    for site in sites:
        try:
            f = audit.function(site.ip)
        except ValueError:
            continue
        try:
            if not audit.profile:
                raise Unsupported(audit.profile_error)
            if site.sequence or site.tail is not None or len(site.insns) != 1:
                raise Unsupported('Go registration requires one complete instruction without a moved tail')
            if f['start'] not in borrowed:
                borrowed[f['start']] = unused_function_xmms(audit, f) if allow_abi_borrow else frozenset()
            hint = site.hints[0] if site.hints else Hints()
            body, proof = lower_popcnt(site.insns[0], hint, dead_xmms=borrowed[f['start']])
            audit.replacement_site(site.ip)
            bodies[site.ip] = body
            proofs[site.ip] = {**proof, 'original_pc': site.ip, 'function': f['name'],
                               'scratch_proof': 'local-dataflow' if proof.get('dead_gprs') or hint.dead_xmms else 'verified-ABIInternal-unused-XMM',
                               'layout_profile': audit.profile['name']}
        except ValueError as error:
            rejected.append(dict(address=site.ip, function=f['name'], reason=str(error)))
    return bodies, proofs, rejected
