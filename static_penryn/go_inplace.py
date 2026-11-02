#!/usr/bin/env python3
"""Audited in-place replacements for explicitly pinned Go assembly functions.

The initial recipe targets agy 1.2.7's ABI0 byte counter. It introduces no
stack frame, call, external mapping or relocation. Existing Go function
boundaries and stack metadata remain authoritative. Unknown binaries or
metadata layouts are refused rather than generalized from a profile.
"""
import bisect
import hashlib
import io
from pathlib import Path
import re
import struct
import tempfile
from typing import TYPE_CHECKING, TypedDict, cast

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from iced_x86 import (Decoder, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
                      Register, RegisterExt)

from . import assembler, go_runtime
from .checked import unpack_ints
from .go_runtime import AGY_SHA256

if TYPE_CHECKING:
    from .gometa import GoFunction, GoMetadata
    from .go_runtime import InplaceRuntime

START, END = 0x6811700, 0x68118c0
PINNED = {
    'countbody': (START, END, '991fd3b836302bd34ec02a9c9b8f1197c9a589a4dae77b388a63db3573e8d2b2'),
    'internal/bytealg.Count': (END, 0x68118e0, 'dd9506e51afa83ed0449555c36aad8794f53f3471acb80b09027a9d815c498d6'),
    'internal/bytealg.CountString': (0x68118e0, 0x6811900, 'f888d3f00a8d6a7edbb904714a87a95c5f2be88e7952ec2f7d31ce36223a0655'),
}
ORIGINAL_POPCNT = (0x681174c, 0x6811785, 0x68117bd, 0x68117f2,
                   0x6811839, 0x681183d, 0x6811894)

# PSADBW sums eight 0xff equality bytes into each qword. For 0 <= n <=16,
# floor((255*n + 255)/256) == n, avoiding POPCNT and division completely.
# Short inputs use the original function's page-safe forward/backward load
# rule. Their masks have byte precision; no byte outside the slice counts.
ASSEMBLY = r'''
.intel_syntax noprefix
.text
.global countbody, countbody_code_end, countbody_constants, countbody_end
countbody:
    movq xmm0, rax
    punpcklbw xmm0, xmm0
    punpcklbw xmm0, xmm0
    pshufd xmm0, xmm0, 0
    xor r12d, r12d
    mov rdi, rsi
    cmp rbx, 16
    jb .Ltail
.Lloop:
    movdqu xmm1, [rdi]
    pcmpeqb xmm1, xmm0
    psadbw xmm1, [rip + .Lzero]
    movq rdx, xmm1
    psrldq xmm1, 8
    movq rcx, xmm1
    add edx, ecx
    add edx, 255
    shr edx, 8
    add r12, rdx
    add rdi, 16
    sub rbx, 16
    cmp rbx, 16
    jae .Lloop
.Ltail:
    test rbx, rbx
    jz .Ldone
    mov r10, rdi
    and r10d, 4095
    cmp r10d, 4080
    ja .Lbackward
    movdqu xmm1, [rdi]
    pcmpeqb xmm1, xmm0
    lea r10, [rip + .Lmask_end]
    sub r10, rbx
    jmp .Lmask
.Lbackward:
    movdqu xmm1, [rdi + rbx - 16]
    pcmpeqb xmm1, xmm0
    lea r10, [rip + .Lzero]
    add r10, rbx
.Lmask:
    movdqu xmm0, [r10]
    pand xmm1, xmm0
    psadbw xmm1, [rip + .Lzero]
    movq rdx, xmm1
    psrldq xmm1, 8
    movq rcx, xmm1
    add edx, ecx
    add edx, 255
    shr edx, 8
    add r12, rdx
.Ldone:
    mov [r8], r12
    ret
countbody_code_end:
    .balign 16, 0xcc
countbody_constants:
.Lzero:
    .zero 16
    .fill 16, 1, 255
.Lmask_end:
    .zero 16
countbody_end:
.section .note.GNU-stack,"",@progbits
'''


def assemble(work: str | Path | None = None) -> tuple[bytes, dict[str, int]]:
    """Return the audited 448-byte function and code/constants boundaries."""
    if work is None:
        with tempfile.TemporaryDirectory(prefix='penryn-countbody-') as temp:
            return assemble(Path(temp))
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    source, obj = work / 'countbody.S', work / 'countbody.o'
    source.write_text(ASSEMBLY)
    obj.write_bytes(assembler.assemble(ASSEMBLY))
    elf = ELFFile(io.BytesIO(obj.read_bytes()))
    for section in elf.iter_sections():
        if section['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            if not isinstance(section, RelocationSection):
                raise ValueError('in-place countbody relocation section is not an ELF relocation table')
            if section.num_relocations():
                raise ValueError('in-place countbody unexpectedly needs relocation')
    symtab = elf.get_section_by_name('.symtab')
    if not isinstance(symtab, SymbolTableSection):
        raise ValueError('in-place countbody object has no ELF symbol table')
    symbols = {s.name: s['st_value'] for s in symtab.iter_symbols()}
    text = elf.get_section_by_name('.text')
    if text is None:
        raise ValueError('in-place countbody object has no .text section')
    body = text.data()
    if len(body) > END - START or symbols['countbody'] != 0:
        raise ValueError('in-place countbody does not fit the original function')
    audit(body, symbols['countbody_code_end'], symbols['countbody_constants'])
    return body + b'\xcc' * (END - START - len(body)), symbols


def audit(body: bytes, code_end: int, constants: int) -> None:
    """Check stack neutrality, ISA, control flow and the limited write set."""
    instructions = list(Decoder(64, body[:code_end], ip=0))
    starts = {i.ip for i in instructions}
    factory = InstructionInfoFactory()
    allowed = {Mnemonic.MOVQ, Mnemonic.PUNPCKLBW, Mnemonic.PSHUFD,
               Mnemonic.XOR, Mnemonic.MOV, Mnemonic.CMP, Mnemonic.JB, Mnemonic.JAE,
               Mnemonic.MOVDQU, Mnemonic.PCMPEQB, Mnemonic.PSADBW, Mnemonic.PSRLDQ,
               Mnemonic.ADD, Mnemonic.SHR, Mnemonic.SUB, Mnemonic.TEST, Mnemonic.JE,
               Mnemonic.AND, Mnemonic.JA, Mnemonic.LEA, Mnemonic.JMP, Mnemonic.PAND,
               Mnemonic.RET}
    allowed_registers = {Register.RBX, Register.RCX, Register.RDX, Register.RDI,
                         Register.R10, Register.R12, Register.ZMM0, Register.ZMM1}
    writes = {OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE}
    for ins in instructions:
        if ins.is_invalid or ins.mnemonic not in allowed:
            raise ValueError(f'unexpected in-place instruction: {ins}')
        if ins.flow_control in (FlowControl.CONDITIONAL_BRANCH, FlowControl.UNCONDITIONAL_BRANCH):
            if ins.near_branch_target not in starts:
                raise ValueError('in-place branch leaves decoded code')
        if ins.mnemonic == Mnemonic.RET:
            continue
        info = factory.info(ins)
        for register in info.used_registers():
            full = RegisterExt.full_register(register.register)
            if full == Register.RSP:
                raise ValueError('in-place code touches RSP')
            if register.access in writes and full not in allowed_registers:
                raise ValueError('in-place code expands the clobber contract')
        for memory in info.used_memory():
            if memory.access in writes and not (memory.base == Register.R8 and memory.index == Register.NONE
                                                and memory.displacement == 0):
                raise ValueError('in-place code writes outside the result slot')
        if ins.is_ip_rel_memory_operand and not constants <= ins.ip_rel_memory_address < len(body):
            raise ValueError('in-place constant reference leaves the replacement')
    if not instructions or instructions[-1].mnemonic != Mnemonic.RET:
        raise ValueError('in-place function has no terminating return')


def at_address(data: bytes, elf: ELFFile, start: int, end: int) -> bytes:
    mappings = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                and s['p_flags'] & 1 and s['p_vaddr'] <= start
                and end <= s['p_vaddr'] + s['p_filesz']]
    if len(mappings) != 1:
        raise ValueError('in-place function has no unique executable mapping')
    offset = mappings[0]['p_offset'] + start - mappings[0]['p_vaddr']
    return data[offset:offset + end - start]


class InplaceEvidence(TypedDict):
    recipe: str
    input_sha256: str
    original_sha256: str
    replacement_sha256: str
    function: str
    end: int
    original_metadata_preserved: bool
    go_runtime: 'InplaceRuntime'
    code_bytes: int
    stack_delta: int
    call_free: bool
    clobbers: list[str]
    input_contract: str


class InplacePatch(TypedDict):
    """Same-length replacement bytes for one pinned original function."""
    address: int
    original_bytes: bytes
    replacement_bytes: bytes
    covered_original_sites: list[int]
    evidence: InplaceEvidence


def plan(data: bytes, elf: ELFFile, metadata: 'GoMetadata', *, work: str | Path | None = None) -> list[InplacePatch]:
    """Return one verified recipe; metadata must include audited Go PC tables.

    This is deliberately opt-in and tied to an exact input payload. Function
    bytes alone cannot prove that a different executable has no new callers
    entering its interior, or that its runtime metadata has the same meaning.
    """
    if hashlib.sha256(data).hexdigest() != AGY_SHA256:
        raise ValueError('Go in-place recipe supports only the pinned agy 1.2.7 payload')
    functions = {f['name']: f for table in metadata['tables'] for f in table['functions']
                 if f['name'] in PINNED}
    for name, (start, end, digest) in PINNED.items():
        function = functions.get(name)
        if function is None or (function['start'], function['end']) != (start, end):
            raise ValueError(f'missing/mismatched Go function metadata for {name}')
        if hashlib.sha256(at_address(data, elf, start, end)).hexdigest() != digest:
            raise ValueError(f'changed pinned Go function bytes: {name}')
    # Parse the original runtime structures, not a caller-supplied boolean.
    # FuncFlagAsm disables asynchronous Go preemption in this pinned runtime.
    runtime_evidence = go_runtime.Audit(data, elf, metadata).inplace('countbody')
    body, symbols = assemble(work)
    covered = START
    for begin, end, delta in runtime_evidence['pcsp']:
        if begin != covered or delta != 0:
            raise ValueError('original Go pcsp is not continuously stack-neutral')
        covered = end
    if START + symbols['countbody_code_end'] > covered:
        raise ValueError('replacement code exceeds the original Go pcsp coverage')
    original = at_address(data, elf, START, END)
    sites = [i.ip for i in Decoder(64, original, ip=START) if i.mnemonic == Mnemonic.POPCNT]
    if tuple(sites) != ORIGINAL_POPCNT:
        raise ValueError('pinned Go countbody instruction coverage changed')
    return [dict(address=START, original_bytes=original, replacement_bytes=body,
                 covered_original_sites=sites,
                 evidence=dict(recipe='agy-1.2.7-countbody-sse2-v1', input_sha256=AGY_SHA256,
                               original_sha256=PINNED['countbody'][2],
                               replacement_sha256=hashlib.sha256(body).hexdigest(),
                               function='countbody', end=END, original_metadata_preserved=True,
                               go_runtime=runtime_evidence,
                               code_bytes=symbols['countbody_code_end'], stack_delta=0,
                               call_free=True, clobbers=['rbx', 'rcx', 'rdx', 'rdi', 'r10', 'r12', 'xmm0', 'xmm1', 'status_flags'],
                               input_contract='ABI0 byte slice/string with nonnegative valid length'))]

# Dormancy is a second, independent proof. These functions retain their bytes;
# zero profile counts are never consulted. The GC AVX512 dispatch chain is not
# included: its wrapper has an unresolved raw address reference in .noptrdata.
DISPATCH_PINNED = {
    'internal/cpu.Initialize': (0x68017e0, 0x6801840, 'e2d10829ee5d872ad8b5dd2528032d8f4f273ff554e25ebff0f0e7ab6ecdd8ca'),
    'internal/cpu.doinit': (0x6801d40, 0x6802840, '26c5cfa5c6aa03e45b6f138bd571f73812b9367b227443fbb39f0d79fddc8cac'),
    'internal/cpu.processOptions': (0x6801840, 0x6801d40, '1a13af1087af6f2845c5c583462d5e6ed300f2b9eef09a2c691a4df164dfb7f6'),
    'internal/cpu.cpuid': (0x6802c20, 0x6802c40, 'b3b18afa01d03ad028180721dd82a11f4b4b700272ef41aed647fcc48145cc86'),
    'indexbody': (0x6811aa0, 0x6811dc0, '062f795a62148e1f91ce72d04f96298c1aec503aadb81f4aae07d74a36ccdf55'),
    'hash/crc32.archInitCastagnoli': (0x6a5d980, 0x6a5dba0, '318ebf0570c5bee681d19327f08e4b4b4b0aadf9edbef848710da3dc1a596d85'),
    'hash/crc32.archUpdateCastagnoli': (0x6a5dba0, 0x6a5dfc0, '30a8c14bf513493ec1b50cbc79862093abe4b46575e482d998f57dd30fa156ed'),
    'hash/crc32.castagnoliSSE42': (0x6a5e560, 0x6a5e620, '6ad20b9522fe7a18e78541c95ebff1d7673937d95fa562635f1a10a4236db3ac'),
    'hash/crc32.castagnoliSSE42Triple': (0x6a5e620, 0x6a5e6a0, '0d67664aaf8323e6afc7894b9702efa480224e6460e58f52c46b4d7f2988ff55'),
}
SSE42_FLAG = 0xdd52721
CRC_CALLS = {0x6a5daa0: 0x6a5e560, 0x6a5db00: 0x6a5e560,
             0x6a5dc2e: 0x6a5e560, 0x6a5dd0a: 0x6a5e620,
             0x6a5de58: 0x6a5e620, 0x6a5df40: 0x6a5e560}


def reachable(instructions: list[Instruction], forced_edges: dict[int, int] | None = None) -> set[int]:
    """Conservative local CFG: both branch arms, calls return, no indirect jump.

    A forced edge represents a separately verified condition, never a profile.
    Reject missing instruction boundaries or control transfers we cannot model.
    """
    by_pc = {ins.ip: ins for ins in instructions}
    forced_edges = forced_edges or {}
    pending, visited = [instructions[0].ip], set()
    while pending:
        pc = pending.pop()
        if pc in visited:
            continue
        if pc not in by_pc:
            raise ValueError('dispatch CFG leaves the verified function')
        visited.add(pc)
        ins = by_pc[pc]
        if ins.is_invalid:
            raise ValueError('invalid instruction in dispatch CFG')
        if pc in forced_edges:
            if ins.flow_control != FlowControl.CONDITIONAL_BRANCH:
                raise ValueError('dispatch forced edge does not name a branch')
            target = forced_edges[pc]
            if target not in (ins.near_branch_target, ins.next_ip):
                raise ValueError('dispatch forced edge is not an original successor')
            pending.append(target)
        elif ins.flow_control in (FlowControl.NEXT, FlowControl.CALL, FlowControl.INDIRECT_CALL):
            pending.append(ins.next_ip)
        elif ins.flow_control == FlowControl.CONDITIONAL_BRANCH:
            pending.extend((ins.next_ip, ins.near_branch_target))
        elif ins.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
            pending.append(ins.near_branch_target)
        elif ins.flow_control not in (FlowControl.RETURN, FlowControl.EXCEPTION, FlowControl.INTERRUPT):
            raise ValueError('unresolved indirect control flow in dispatch CFG')
    return visited


def flag_false_edges(instructions: list[Instruction], address: int) -> dict[int, int]:
    """Evaluate adjacent CMP byte [flag],0/1 and JE/JNE with flag known zero."""
    result = {}
    for comparison, branch in zip(instructions, instructions[1:]):
        if not (comparison.mnemonic == Mnemonic.CMP and comparison.is_ip_rel_memory_operand
                and comparison.ip_rel_memory_address == address
                and comparison.op0_kind == OpKind.MEMORY
                and comparison.op1_kind == OpKind.IMMEDIATE8
                and comparison.immediate8 in (0, 1)):
            continue
        if branch.mnemonic not in (Mnemonic.JE, Mnemonic.JNE):
            raise ValueError('CPU flag comparison has an unknown branch')
        equals = comparison.immediate8 == 0
        taken = equals if branch.mnemonic == Mnemonic.JE else not equals
        result[branch.ip] = branch.near_branch_target if taken else branch.next_ip
    if not result:
        raise ValueError('missing audited CPU dispatch comparison')
    return result


def _closed_direct_references(data: bytes, elf: ELFFile, metadata: 'GoMetadata', protected: list[tuple[int, int]],
                              helpers: set[int]) -> list[tuple[int, int]]:
    """Audit ordinary Go code-address representations in the exact input.

    The pinned Go assembler/compiler uses rel32 branches and RIP-relative LEA
    for text addresses, with absolute pointer words in data/relocations. Search
    all executable sections, including non-Go callers. Any unresolved incoming
    branch or escaped helper address refuses this recipe.
    """
    def function_start(f: 'GoFunction') -> int:
        return f['start']
    functions = sorted((f for t in metadata['tables'] for f in t['functions']), key=function_start)
    starts = [f['start'] for f in functions]
    decoded: dict[int, dict[int, Instruction]] = {}

    def actual(pc: int) -> Instruction | None:
        index = bisect.bisect_right(starts, pc) - 1
        if index < 0 or pc >= functions[index]['end']:
            raise ValueError('unresolved non-Go reference into guarded Go code')
        f = functions[index]
        if f['start'] not in decoded:
            decoded[f['start']] = {i.ip: i for i in Decoder(64, at_address(data, elf, f['start'], f['end']), ip=f['start'])}
        return decoded[f['start']].get(pc)

    def owner(address: int) -> tuple[int, int] | None:
        return next((r for r in protected if r[0] <= address < r[1]), None)

    calls = {}
    # Lookahead allows adjacent/overlapping instruction-byte candidates.
    direct = re.compile(rb'(?=([\xe8\xe9]|\x0f[\x80-\x8f])(.{4}))', re.DOTALL)
    lea = re.compile(rb'(?=([\x40-\x4f]?\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(.{4}))', re.DOTALL)
    for section in elf.iter_sections():
        if not section['sh_flags'] & 4 or section['sh_type'] == 'SHT_NOBITS':
            continue
        blob = section.data()
        base = section['sh_addr']
        for match in direct.finditer(blob):
            pc = base + match.start()
            # Both lookahead groups always participate in a match.
            target = pc + len(cast(bytes, match[1])) + 4 + unpack_ints('<i', cast(bytes, match[2]))[0]
            dest = owner(target)
            if dest is None:
                continue
            ins = actual(pc)
            if ins is None or ins.flow_control not in (FlowControl.CALL, FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CONDITIONAL_BRANCH):
                continue  # Candidate occurred inside another decoded instruction.
            if ins.near_branch_target != target:
                continue
            source = owner(pc)
            if target != dest[0] and source != dest:
                raise ValueError('incoming reference bypasses the guarded function entry')
            if target in helpers and source != dest:
                calls[pc] = target
        # rel8 branches can cross a function boundary only within 128 bytes.
        # Inspect these windows rather than scanning every short branch in the
        # complete executable a second time.
        windows: set[int] = set()
        for begin, end in protected:
            left, right = max(base, begin - 130), min(base + len(blob), end + 130)
            if left < right:
                windows.update(range(left, right - 1))
        for pc in sorted(windows):
            opcode = blob[pc - base]
            if not (0x70 <= opcode <= 0x7f or 0xe0 <= opcode <= 0xe3 or opcode == 0xeb):
                continue
            displacement = blob[pc - base + 1]
            target = pc + 2 + (displacement if displacement < 128 else displacement - 256)
            dest = owner(target)
            if dest is None:
                continue
            ins = actual(pc)
            if ins is None or ins.flow_control not in (FlowControl.CONDITIONAL_BRANCH, FlowControl.UNCONDITIONAL_BRANCH):
                continue
            if ins.near_branch_target != target:
                continue
            source = owner(pc)
            if target != dest[0] and source != dest:
                raise ValueError('incoming short reference bypasses the guarded function entry')
            if target in helpers and source != dest:
                calls[pc] = target
        for match in lea.finditer(blob):
            pc = base + match.start()
            target = pc + len(cast(bytes, match[1])) + 4 + unpack_ints('<i', cast(bytes, match[2]))[0]
            dest = owner(target)
            if dest is None:
                continue
            ins = actual(pc)
            if ins is None or ins.mnemonic != Mnemonic.LEA or not ins.is_ip_rel_memory_operand:
                continue
            if ins.ip_rel_memory_address == target and (target != dest[0] or target in helpers):
                raise ValueError('guarded helper/interior address escapes through LEA')
    for address in helpers:
        # Whole-file unaligned checks intentionally also reject apparent data
        # coincidences. Classifying those would require another pinned recipe.
        if struct.pack('<Q', address) in data or struct.pack('<I', address) in data:
            raise ValueError('unresolved literal reference to guarded helper')
    if calls != CRC_CALLS:
        raise ValueError('guarded CRC caller closure differs from the pinned audit')
    return sorted(calls.items())


class CpuidProof(TypedDict):
    leaf: int
    register: str
    bit: int
    target_value: int
    assignment: int
    implementation: int


class OptionsProof(TypedDict):
    function: str
    store: int
    enabling_requires_existing_true: bool


class DispatchEvidence(TypedDict):
    recipe: str
    input_sha256: str
    classification: str
    target_cpu: str
    feature: str
    flag_address: int
    initial_value: int
    cpuid: CpuidProof
    options: OptionsProof
    crc_callers: list[tuple[int, int]]
    flag_references: list[int]
    function_sha256: dict[str, str]
    proof_scope: str
    uses_profile: bool


class DormantEvidence(DispatchEvidence):
    function: str


class DormantSite(TypedDict):
    """One original instruction left in place on a proven-unreachable path."""
    address: int
    original_bytes: bytes
    evidence: DormantEvidence


def dormant(data: bytes, elf: ELFFile, metadata: 'GoMetadata') -> list[DormantSite]:
    """Return 18 proven-unreachable SSE4.2 sites for the exact Penryn target.

    The remaining AVX512 FilterNil POPCNT is deliberately not classified: an
    unaligned absolute wrapper-address literal has no validated interpretation.
    This API raises on unknown inputs instead of trusting zero dynamic counts.
    """
    if hashlib.sha256(data).hexdigest() != AGY_SHA256:
        raise ValueError('Go dispatch proof supports only the pinned agy 1.2.7 payload')
    functions = {f['name']: f for t in metadata['tables'] for f in t['functions']}
    decoded = {}
    for name, (start, end, digest) in DISPATCH_PINNED.items():
        f = functions.get(name)
        if f is None or (f['start'], f['end']) != (start, end):
            raise ValueError(f'missing/mismatched dispatch metadata: {name}')
        body = at_address(data, elf, start, end)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError(f'changed pinned dispatch function: {name}')
        decoded[name] = list(Decoder(64, body, ip=start))
    # The flag starts as zero in loader-created BSS. CPUID's only assignment is
    # ECX bit 20; the pinned options loop can disable but cannot enable a false
    # feature. Exact whole-function hashes above freeze the surrounding paths.
    if not any(s['p_type'] == 'PT_LOAD' and s['p_vaddr'] + s['p_filesz'] <= SSE42_FLAG
               < s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments()):
        raise ValueError('SSE4.2 capability flag is not loader-zeroed BSS')
    instructions = {i.ip: i for row in decoded.values() for i in row}
    checks = {0x68024c4: 'bt eax,14h', 0x68024c8: 'setb byte ptr [0DD52721h]',
              0x6801af8: 'test dl,dl', 0x6801afc: 'cmp byte ptr [rbx],0',
              0x6801b6a: 'mov [rbx],dl'}
    for pc, expected in checks.items():
        if pc not in instructions or str(instructions[pc]).lower() != expected.lower():
            raise ValueError('CPU initialization/options proof changed')
    safe = {}
    for name in ('indexbody', 'hash/crc32.archInitCastagnoli', 'hash/crc32.archUpdateCastagnoli'):
        safe[name] = reachable(decoded[name], flag_false_edges(decoded[name], SSE42_FLAG))
    if any(call in safe[name] for call in CRC_CALLS for name in safe):
        raise ValueError('CRC call remains reachable with SSE4.2 unavailable')
    protected = [(DISPATCH_PINNED[n][0], DISPATCH_PINNED[n][1]) for n in safe]
    protected += [(DISPATCH_PINNED[n][0], DISPATCH_PINNED[n][1]) for n in
                  ('hash/crc32.castagnoliSSE42', 'hash/crc32.castagnoliSSE42Triple')]
    closure = _closed_direct_references(data, elf, metadata, protected, {0x6a5e560, 0x6a5e620})
    # Audit the private capability byte's code references too. Its address
    # escapes only once, into internal/cpu's pinned option record. The pinned
    # processOptions implementation above is that record's monotone writer.
    flag_references = {}
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_NOBITS' or not section['sh_flags'] & 4:
            continue
        for ins in Decoder(64, section.data(), ip=section['sh_addr']):
            if ins.is_ip_rel_memory_operand and ins.ip_rel_memory_address == SSE42_FLAG:
                flag_references[ins.ip] = ins.mnemonic
    expected_flag_references = {0x6802053: Mnemonic.LEA, 0x68024c8: Mnemonic.SETB,
                                0x6811d3b: Mnemonic.CMP, 0x6a5d99d: Mnemonic.CMP,
                                0x6a5dbc2: Mnemonic.CMP, 0x6a5e2fd: Mnemonic.CMP}
    if flag_references != expected_flag_references or struct.pack('<I', SSE42_FLAG) in data:
        raise ValueError('CPU capability has an unaudited address reference')
    evidence: DispatchEvidence = dict(recipe='agy-1.2.7-go-sse42-dispatch-v1', input_sha256=AGY_SHA256,
                                      classification='cpu-dispatch-unreachable', target_cpu='Penryn',
                                      feature='SSE4.2', flag_address=SSE42_FLAG, initial_value=0,
                                      cpuid=dict(leaf=1, register='ecx', bit=20, target_value=0,
                                                 assignment=0x68024c8, implementation=0x6802c20),
                                      options=dict(function='internal/cpu.processOptions', store=0x6801b6a,
                                                   enabling_requires_existing_true=True),
                                      crc_callers=closure, flag_references=sorted(flag_references), function_sha256={n: p[2] for n, p in DISPATCH_PINNED.items()},
                                      proof_scope='exact input, Go rel8/rel32/LEA/absolute-pointer address representations',
                                      uses_profile=False)
    rows: list[DormantSite] = []
    for name in ('indexbody', 'hash/crc32.castagnoliSSE42', 'hash/crc32.castagnoliSSE42Triple'):
        for ins in decoded[name]:
            if ins.mnemonic not in (Mnemonic.CRC32, Mnemonic.PCMPESTRI):
                continue
            if name in safe and ins.ip in safe[name]:
                raise ValueError('unsupported instruction remains reachable with SSE4.2 unavailable')
            rows.append(dict(address=ins.ip, original_bytes=at_address(data, elf, ins.ip, ins.next_ip),
                             evidence={**evidence, 'function': name}))
    if len(rows) != 18:
        raise ValueError('guarded SSE4.2 site set changed')
    return rows
