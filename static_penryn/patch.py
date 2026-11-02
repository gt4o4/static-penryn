#!/usr/bin/env python3
"""Experimental offline ELF64 lowering. Writes a new file; never edits the input.

The report is a coverage record, not a proof of arbitrary binary control flow.
Only decoded executable sections are rewritten. Indirect entry points, JIT code,
shared libraries, and asynchronous unwind metadata need separate validation.
"""
import argparse
import bisect
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from typing import TYPE_CHECKING, TypedDict

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from elftools.elf.relocation import RelocationSection
from iced_x86 import BlockEncoder, Decoder, FlowControl, Instruction, Mnemonic, OpKind, Register
from . import go_inplace, go_lower, go_runtime, lower, native_frames, regions, strings, unwind
from .assembler import assemble
from .checked import constants, required, unpack_ints
from .controlflow import Recovery
from .dataflow import Hints, analyze
from .elfcheck import ElfMetadata, validate_elf

if TYPE_CHECKING:
    from pwnlib.elf.elf import ELF
    from .controlflow import CFGReport
    from .go_inplace import DormantEvidence, DormantSite, InplacePatch
    from .go_lower import Rejection, SiteProof
    from .go_runtime import Audit, BuildResult, StubRange
    from .native_frames import Recovery as FrameRecovery
    from .regions import SharedFrame
    from .strings import HelperReport
    from .unwind import Range, Report as UnwindReport, Result as UnwindResult, RuntimeAudit

    class DormantInstruction(TypedDict):
        address: int
        original_bytes: str
        evidence: DormantEvidence

    class PatchEntry(TypedDict):
        address: str
        end: str
        original: str
        stub: str
        stub_end: str
        instruction_ranges: list[InstructionRange]
        cave: str | None
        instructions: list[str]
        tail: str | None
        region: bool
        shared_frame: SharedFrame | NoSharedFrame
        optimization: list[Optimization]

    class PatchReport(TypedDict):
        # schema_version 2, in its JSON key order.
        schema_version: int
        input: str
        input_sha256: str
        output: str
        output_sha256: str
        families: dict[str, int]
        sites: int
        short_jumps: int
        relocated_following: int
        added_code_bytes: int
        added_payload_bytes: int
        remaining_decoded_supported: int
        dataflow_enabled: bool
        control_flow: CFGReport
        runtime: RuntimeAudit
        unwind: UnwindReport | UnwindDisabled
        added_unwind_bytes: int
        added_go_metadata_bytes: int
        go_runtime_enabled: bool
        go_inplace_enabled: bool
        go_dispatch_enabled: bool
        dormant_instructions: list[DormantInstruction]
        inplace_patches: list[dict[str, object]]
        regions_enabled: bool
        region_loads_enabled: bool
        fused_regions: int
        eliminated_site_jumps: int
        profile: str | None
        flags_proven_dead: int
        sites_with_dead_gprs: int
        sites_with_dead_xmms: int
        string_helpers: HelperReport | NoHelpers
        helpers: list[HelperAddresses]
        unscanned_rx_ranges: list[UnscannedRange]
        timing_seconds: dict[str, float]
        string_core_sha256: dict[str, str]
        experimental: bool
        limitations: list[str]
        patches: list[PatchEntry]

_MNEMONICS = constants(Mnemonic)
FAMILIES = {_MNEMONICS[name]: name for name in (
    'POPCNT', 'CRC32', 'PCMPGTQ', 'PCMPISTRI', 'PCMPISTRM',
    'PCMPESTRI', 'PCMPESTRM', 'PCMPESTRI64', 'PCMPESTRM64')}
HERE = Path(__file__).resolve().parent
# The pinned opemu-linux checkout beside this one (nix-configs' submodules/).
OPEMU_CORE = HERE.parents[1] / 'opemu-linux/core'
CORE_HASHES = {
    'emu-core.c': '37afd5483069ddd7d746da5b247b425b7fad7b0b7f23c1335fd68097478de475',
    'emu-core.h': '805c42a74ada75b48c00e1d134b4b938647c25ecd718fd18df4205c8d30cc9cd',
}
REGISTER_NAMES = {value: name.lower() for name, value in constants(Register).items()}


def align(value: int, alignment: int = 4096) -> int:
    return (value + alignment - 1) & -alignment


def run(*args: str | Path) -> None:
    subprocess.run([str(x) for x in args], check=True)


def digest(data: bytes | bytearray | memoryview) -> str:
    return hashlib.sha256(data).hexdigest()


def publish(output: Path, report_path: Path, result: bytes | bytearray,
            report: Mapping[str, object], mode: int) -> None:
    """Publish complete new files without truncation or partial executables."""
    temporary: list[Path] = []
    linked_report = False
    try:
        files: tuple[tuple[Path, bytes | bytearray, int], ...] = (
            (output, result, mode & 0o777),
            (report_path, (json.dumps(report, indent=2) + '\n').encode(), 0o644),
        )
        for path, content, permissions in files:
            fd, name = tempfile.mkstemp(prefix='.static-penryn-', dir=path.parent)
            temporary.append(Path(name))
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
                os.fchmod(stream.fileno(), permissions)
        # link() is exclusive: a late symlink/file never gets overwritten.
        os.link(temporary[1], report_path)
        linked_report = True
        os.link(temporary[0], output)
    except BaseException:
        if linked_report:
            try:
                if os.path.samestat(report_path.lstat(), temporary[1].stat()):
                    report_path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for path in temporary:
            path.unlink(missing_ok=True)


@dataclass
class Site:
    insns: list[Instruction]
    offset: int
    end: int
    cave: int | None = None
    tail: Instruction | None = None
    hints: list[Hints] = field(default_factory=list)
    sequence: list[Instruction] = field(default_factory=list)

    @property
    def ip(self) -> int:
        return self.insns[0].ip


type Hit = tuple[Instruction, Section]


def scan(elf: ELFFile, *, inventory_only: bool = False, metadata: ElfMetadata | None = None,
         recovery: 'Recovery | None' = None, frame_recovery: 'FrameRecovery | None' = None
         ) -> tuple[list[Hit], set[int], list[tuple[int, int]]]:
    hits: list[Hit] = []
    targets = {elf['e_entry']}
    caves: list[tuple[int, int]] = []
    frame_pointers: set[int] = set()
    if metadata:
        targets.update(metadata['pointer_targets'])
    for sec in elf.iter_sections():
        if not inventory_only and isinstance(sec, SymbolTableSection):
            targets.update(s['st_value'] for s in sec.iter_symbols() if s['st_value'])
        if (not inventory_only and isinstance(sec, RelocationSection)
                and (metadata is None or not sec['sh_flags'] & 2)):
            symbols = elf.get_section(sec['sh_link']) if sec['sh_link'] else None
            for rel in sec.iter_relocations():
                if rel.is_RELA():
                    addend = rel['r_addend']
                    if rel['r_info_sym'] and symbols is not None:
                        if not isinstance(symbols, SymbolTableSection):
                            raise ValueError(f'relocation section {sec.name} links to a non-symbol section')
                        addend += symbols.get_symbol(rel['r_info_sym'])['st_value']
                    targets.add(addend)
        if not sec['sh_flags'] & 4:
            continue
        data = sec.data()
        if inventory_only:
            hits.extend((ins, sec) for ins in Decoder(64, data, ip=sec['sh_addr'])
                        if ins.mnemonic in FAMILIES)
            continue
        padding: int | None = None
        previous_terminates = False
        for ins in Decoder(64, data, ip=sec['sh_addr']):
            if recovery is not None:
                recovery.feed(ins)
            if frame_recovery is not None:
                frame_recovery.feed(ins)
            flow = ins.flow_control
            mnemonic = ins.mnemonic
            if flow != FlowControl.NEXT and ins.op0_kind in (
                OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64
            ):
                targets.add(ins.near_branch_target)
            if ins.is_ip_rel_memory_operand:
                targets.add(ins.ip_rel_memory_address)
                if frame_recovery is not None:
                    frame_pointers.add(ins.ip_rel_memory_address)
            if mnemonic in (Mnemonic.MOV, Mnemonic.PUSH):
                # Retained immediate code pointers matter even in stripped
                # ET_EXEC images (movabs/jmp, push/ret). False positives here
                # only make relocation more conservative.
                for op in range(ins.op_count):
                    if ins.op_kind(op) in (OpKind.IMMEDIATE32, OpKind.IMMEDIATE64,
                                          OpKind.IMMEDIATE32TO64):
                        targets.add(ins.immediate(op) & ((1 << 64) - 1))
                        if frame_recovery is not None:
                            frame_pointers.add(ins.immediate(op) & ((1 << 64) - 1))
            is_padding = mnemonic in (Mnemonic.NOP, Mnemonic.INT3)
            if is_padding and (padding is not None or previous_terminates):
                if padding is None:
                    padding = ins.ip
            else:
                if padding is not None and ins.ip - padding >= 5:
                    caves.append((padding, ins.ip))
                padding = None
            previous_terminates = flow in (
                FlowControl.RETURN, FlowControl.UNCONDITIONAL_BRANCH,
                FlowControl.INDIRECT_BRANCH
            )
            if mnemonic in FAMILIES:
                hits.append((ins, sec))
        if padding is not None and sec['sh_addr'] + len(data) - padding >= 5:
            caves.append((padding, sec['sh_addr'] + len(data)))
    if recovery is not None:
        recovery.finish()
        targets.update(recovery.targets)
    if frame_recovery is not None:
        frame_pointers.update(metadata['pointer_targets'] if metadata else ())
        if recovery is not None:
            frame_pointers.update(recovery.targets)
        frame_recovery.finish(address_taken=frame_pointers)
        targets.update(frame_recovery.entries)
    return hits, targets, caves


def plan(hits: Sequence[Hit], targets: set[int], caves: list[tuple[int, int]],
         allow_relocate: bool, *, optimize: bool = True,
         relocation_ranges: Sequence[tuple[int, int]] = (),
         recovery: 'Recovery | None' = None) -> list[Site]:
    used: set[int] = set()
    plans: list[Site] = []
    failures: list[str] = []
    section_data: dict[tuple[int, int], bytes] = {}
    # Do not steal a known entry point even when it is in padding.
    protected = sorted(targets)

    def occupied(a: int, b: int) -> bool:
        j = bisect.bisect_left(protected, a)
        return j < len(protected) and protected[j] < b

    relocation_ranges = sorted(relocation_ranges)
    relocation_starts = [a for a, _ in relocation_ranges]
    relocation_ends: list[int] = []
    for _, end in relocation_ranges:
        relocation_ends.append(max(end, relocation_ends[-1] if relocation_ends else 0))

    def loader_writes(a: int, b: int) -> bool:
        j = bisect.bisect_left(relocation_starts, b) - 1
        return j >= 0 and relocation_ends[j] > a

    def contents(sec: Section) -> bytes:
        key = (sec['sh_addr'], sec['sh_offset'])
        if key not in section_data:
            section_data[key] = sec.data()
        return section_data[key]

    # A target at the start of padding can fall through to any later byte.
    caves = [(a, b) for a, b in caves if not occupied(a, b) and not loader_writes(a, b)]

    for ins, sec in hits:
        if ins.ip in used:
            continue
        if occupied(ins.ip + 1, ins.next_ip) or loader_writes(ins.ip, ins.next_ip):
            failures.append(f'0x{ins.ip:x}: known overlapping instruction entry or loader relocation')
            continue
        offset = sec['sh_offset'] + ins.ip - sec['sh_addr']
        site = Site([ins], offset, ins.next_ip)
        if ins.len < 5:
            # A two-byte jump uses only the original instruction's bytes.
            for j, (a, b) in enumerate(caves):
                a = max(a, ins.ip + 2 - 128)
                if a + 5 <= b and a <= ins.ip + 2 + 127:
                    site.cave = a
                    caves[j] = (a + 5, b)
                    break
            if site.cave is None:
                if not allow_relocate:
                    failures.append(f'0x{ins.ip:x}: four-byte site without nearby padding')
                    continue
                # The experimental mode steals ONE following complete instruction.
                # All known direct branches/symbols/address-taken RIP references
                # are protected; unrecognised indirect targets remain a limitation.
                start = ins.next_ip - sec['sh_addr']
                following = Decoder(64, contents(sec)[start:start + 15], ip=ins.next_ip).decode()
                if (following.is_invalid or occupied(ins.next_ip, following.next_ip)
                        or loader_writes(ins.next_ip, following.next_ip)):
                    failures.append(f'0x{ins.ip:x}: following instruction is invalid or an entry point')
                    continue
                if following.flow_control in (FlowControl.CALL, FlowControl.INDIRECT_CALL,
                                              FlowControl.INTERRUPT, FlowControl.EXCEPTION):
                    failures.append(f'0x{ins.ip:x}: refusing to relocate call/interrupt/exception')
                    continue
                site.end = following.next_ip
                if following.mnemonic in FAMILIES:
                    site.insns.append(following)
                    used.add(following.ip)
                else:
                    site.tail = following
        for source in site.insns:
            start = source.next_ip - sec['sh_addr']
            continuation = Decoder(64, contents(sec)[start:start + 24 * 15], ip=source.next_ip)
            site.hints.append(analyze(continuation,
                                     lookup=recovery.lookup if recovery is not None else None,
                                     bounds=recovery.bounds(source.ip) if recovery is not None else None)
                              if optimize else Hints())
        plans.append(site)
    if failures:
        raise ValueError(f'{len(failures)} unsafe sites; no output written:\n' + '\n'.join(failures[:30]))
    return plans


def va_offset(elf: ELFFile, va: int) -> int:
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va < seg['p_vaddr'] + seg['p_filesz']:
            return seg['p_offset'] + va - seg['p_vaddr']
    raise ValueError(f'unmapped file address 0x{va:x}')


def offset_va(elf: ELFFile, offset: int) -> int:
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_offset'] <= offset < seg['p_offset'] + seg['p_filesz']:
            return seg['p_vaddr'] + offset - seg['p_offset']
    raise ValueError(f'file offset 0x{offset:x} is not PT_LOAD mapped')


def load_elf(path: Path | str) -> 'ELF':
    """Load PATH with pwntools: pyelftools' ELFFile over a private copy-on-write
    mmap. Patches change only that mapping; the input file is never written."""
    from pwnlib.context import context
    from pwnlib.elf.elf import ELF
    with context.local(log_level='error'):
        return ELF(str(path), checksec=False)


def write_image(elf: 'ELF', address: int, new: bytes) -> None:
    """Patch file-backed bytes of a load_elf() image at a virtual address.

    pwntools' write() silently skips an address without a file offset, so the
    whole span is resolved first and the written bytes are read back.
    """
    offset = va_offset(elf, address)
    if new and va_offset(elf, address + len(new) - 1) != offset + len(new) - 1:
        raise ValueError(f'patch at 0x{address:x} leaves its file-backed mapping')
    elf.write(address, new)
    if elf.read(address, len(new)) != new:
        raise ValueError(f'patch at 0x{address:x} did not reach the image')


def jump(src: int, dst: int) -> bytes:
    delta = dst - src - 5
    if not -(1 << 31) <= delta < 1 << 31:
        raise ValueError('branch exceeds rel32 reach')
    return b'\xe9' + struct.pack('<i', delta)


def _relocate_tail(ins: Instruction, address: int) -> bytes:
    # BlockEncoder can emit an absolute target table for >2 GiB branches.
    # Such pointers would be wrong in a PIE without dynamic relocations.
    if ins.op_count and ins.op0_kind in (OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64):
        if not -(1 << 31) + 32 <= ins.near_branch_target - address < (1 << 31) - 32:
            raise ValueError('relocated branch exceeds position-independent rel32 reach')
    if ins.memory_base == Register.EIP:
        raise ValueError('refusing to relocate EIP-relative memory operand')
    enc = BlockEncoder(64)
    enc.add(ins)
    code = enc.encode(address)
    if ins.is_ip_rel_memory_operand:
        moved = Decoder(64, code, ip=address).decode()
        # BlockEncoder may use address-size truncation for a distant low VA.
        # That preserves an ET_EXEC address but loses a PIE's load bias.
        if (moved.memory_base != Register.RIP
                or moved.ip_rel_memory_address != ins.ip_rel_memory_address):
            raise ValueError('relocated memory operand exceeds position-independent RIP reach')
    return code


class NoHelpers(TypedDict):
    """The report's string_helpers when no site needs a PCMPxSTRx helper: {}."""


class NoSharedFrame(TypedDict):
    """The report's shared_frame for a site outside a fused region: {}."""


class HelperRange(TypedDict):
    name: str
    start: int
    end: int


class StubSymbols(dict[str, int]):
    """Symbol addresses of the linked stubs, plus what the report needs from the link."""
    helper_report: 'HelperReport | NoHelpers'
    helper_ranges: list[HelperRange]
    shared_frames: 'list[SharedFrame | NoSharedFrame]'
    sequences: list[list[Instruction]]


def build_stubs(sites: Sequence[Site], address: int, work: Path, core: Path, *,
                region_loads: bool = False, go_bodies: Mapping[int, str] | None = None
                ) -> tuple[bytearray, StubSymbols]:
    sequences = [regions.sequence(site) for site in sites]
    bodies: list[list[str | None]] = []
    prefixes: list[list[str]] = []
    suffixes: list[list[str]] = []
    shared: 'list[SharedFrame | NoSharedFrame]' = []
    instructions = [i for site in sites for i in site.insns]
    for site, steps in zip(sites, sequences):
        hints = {ins.ip: site.hints[n] if site.hints else Hints()
                 for n, ins in enumerate(site.insns)}
        prefix: list[str]
        suffix: list[str]
        sharing: 'SharedFrame | NoSharedFrame'
        body: list[str | None]
        if site.sequence:
            prefix, body, suffix, sharing = regions.shared_lowering(steps, hints, allow_loads=region_loads)
        else:
            prefix, suffix, sharing, body = [], [], NoSharedFrame(), []
            for ins in steps:
                hint = hints.get(ins.ip, Hints())
                if go_bodies is not None and ins.ip in go_bodies:
                    body.append(go_bodies[ins.ip])
                elif ins.mnemonic in lower.SUPPORTED:
                    body.append(lower.lower(ins, preserve_flags=hint.preserve_flags,
                                            dead_registers=hint.dead_registers,
                                            dead_xmms=hint.dead_xmms))
                elif ins.mnemonic in strings.SUPPORTED:
                    body.append(strings.lower(ins))
                else:
                    body.append(None)
        bodies.append(body)
        prefixes.append(prefix)
        suffixes.append(suffix)
        shared.append(sharing)
    objects = [work / 'stubs.o']
    helper_report: 'HelperReport | NoHelpers' = NoHelpers()
    if any(i.mnemonic in strings.SUPPORTED for i in instructions):
        for filename, expected in CORE_HASHES.items():
            if digest((core / filename).read_bytes()) != expected:
                raise ValueError(f'{filename} differs from the validated 6641be6 core')
        obj, helper_report = strings.build_helpers(instructions, core, work)
        objects.append(obj)
    # Keep GCC's helper CFI in the intermediate ELF for the optional unwind
    # writer. Only .patch bytes become the executable payload at this stage.
    (work / 'layout.ld').write_text(f'''SECTIONS {{
      . = {address};
      .patch {address} : {{
        KEEP(*(.text)) *(.text.*)
        _penryn_code_end = .;
        . = ALIGN(64);
        _penryn_rodata_begin = .;
        *(.rodata*)
      }}
      .eh_frame : {{ KEEP(*(.eh_frame*)) }}
      /DISCARD/ : {{ *(.comment) *(.note*) }}
    }}\n''')
    moved_sizes = {(n, m): 32 for n, body in enumerate(bodies)
                   for m, text in enumerate(body) if text is None}
    for _ in range(4):
        asm = ['.intel_syntax noprefix', '.text']
        for n, site in enumerate(sites):
            asm += [f'.global site_{n}', f'site_{n}:', *prefixes[n]]
            for m, lowered in enumerate(bodies[n]):
                asm += [f'.global insn_{n}_{m}', f'insn_{n}_{m}:']
                if lowered is None:
                    if sequences[n][m] is site.tail:
                        asm += [f'.global tail_{n}', f'tail_{n}:']
                    asm += [f'.fill {moved_sizes[n, m]}, 1, 0x90']
                else:
                    asm.append(lowered)
                asm += [f'.global insn_{n}_{m}_end', f'insn_{n}_{m}_end:']
            asm += suffixes[n]
            asm += ['.byte 0xe9', '.long 0', f'.reloc .-4, R_X86_64_PC32, {site.end}-4']
            asm += [f'.global site_{n}_end', f'site_{n}_end:']
        asm += [lower.support_assembly(), '.section .note.GNU-stack,"",@progbits']
        source = '\n'.join(asm) + '\n'
        (work / 'stubs.S').write_text(source)
        (work / 'stubs.o').write_bytes(assemble(source))
        run('ld', '--gc-sections', '-T', work / 'layout.ld', '-o', work / 'stubs.elf', *objects)
        with (work / 'stubs.elf').open('rb') as f:
            stubelf = ELFFile(f)
            symtab = stubelf.get_section_by_name('.symtab')
            if not isinstance(symtab, SymbolTableSection):
                raise ValueError('linked stubs have no symbol table')
            symbols = list(symtab.iter_symbols())
            syms = StubSymbols({s.name: s['st_value'] for s in symbols})
            helpers = [HelperRange(name=s.name, start=s['st_value'],
                                   end=s['st_value'] + s['st_size'])
                       for s in symbols if s['st_info']['type'] == 'STT_FUNC'
                       and s.name.startswith('penryn_pcmp_') and s['st_size']]
            sec = stubelf.get_section_by_name('.patch')
            if sec is None:
                raise ValueError('linked stubs have no .patch section')
            if sec['sh_addr'] != address:
                raise ValueError('linker moved the injected section from its requested address')
            blob = bytearray(sec.data())
            for s in stubelf.iter_sections():
                if s['sh_flags'] & 2 and s.name not in ('.patch', '.eh_frame') and s['sh_size']:
                    raise ValueError(f'unexpected allocated helper section {s.name}')
        moved = {(n, m): _relocate_tail(sequences[n][m], syms[f'insn_{n}_{m}'])
                 for n, m in moved_sizes}
        sizes = {key: len(code) for key, code in moved.items()}
        if sizes == moved_sizes:
            for (n, m), code in moved.items():
                offset = syms[f'insn_{n}_{m}'] - address
                blob[offset:offset + len(code)] = code
            def helper_start(helper: HelperRange) -> int:
                return helper['start']

            syms.helper_report = helper_report
            syms.helper_ranges = sorted(helpers, key=helper_start)
            syms.shared_frames = shared
            syms.sequences = sequences
            return blob, syms
        moved_sizes = sizes
    raise ValueError('relocated instruction layout failed to converge')


class ExtraSection(TypedDict):
    name: str
    offset: int
    size: int
    flags: int
    alignment: int


def rewrite(data: bytes | bytearray, elf: 'ELF', sites: Sequence[Site], blob: bytes | bytearray,
            syms: Mapping[str, int], load_off: int, load_va: int, code_off: int,
            unwind_result: 'UnwindResult | None' = None, *, inplace: 'Sequence[InplacePatch]' = (),
            go_result: 'BuildResult | None' = None, go_metadata_va: int | None = None,
            go_installer_va: int | None = None) -> bytearray:
    # In-place changes go through the load_elf() image; the new mapping,
    # headers and section table are appended to its bytes afterwards.
    for item in inplace:
        original, replacement = item['original_bytes'], item['replacement_bytes']
        if len(original) != len(replacement) or elf.read(item['address'], len(original)) != original:
            raise ValueError('in-place replacement bytes/length changed after planning')
        write_image(elf, item['address'], replacement)
    for n, s in enumerate(sites):
        dest = syms[f'site_{n}']
        if va_offset(elf, s.ip) != s.offset:
            raise ValueError(f'site 0x{s.ip:x} disagrees with its PT_LOAD file mapping')
        if s.cave is None:
            patch = jump(s.ip, dest)
        else:
            patch = b'\xeb' + struct.pack('b', s.cave - s.ip - 2)
            write_image(elf, s.cave, jump(s.cave, dest))
        write_image(elf, s.ip, patch + b'\x90' * (s.end - s.ip - len(patch)))
    payload = bytearray(blob)
    metadata_offset = align(len(payload), 8)
    if unwind_result is not None:
        payload += bytes(metadata_offset - len(payload)) + unwind_result.blob
    # Zero until a Go result supplies them; only Go blocks below read them.
    installer_offset = metadata_va = go_offset = go_size = 0
    if go_result is not None:
        if go_installer_va is None or go_metadata_va is None:
            raise ValueError('Go registration needs its initializer and metadata addresses')
        metadata_va = go_metadata_va
        installer_offset = go_installer_va - load_va - code_off
        if installer_offset < len(payload):
            raise ValueError('Go initializer overlaps emitted code or native CFI')
        payload += bytes(installer_offset - len(payload)) + go_result['constructor_bytes']
        if metadata_va < align(load_va + code_off + len(payload)):
            raise ValueError('Go writable metadata overlaps an executable page')
        for loader_patch in go_result['patches']:
            address, old, new = offset_va(elf, loader_patch['offset']), loader_patch['old'], loader_patch['new']
            if len(old) != len(new) or elf.read(address, len(old)) != old:
                raise ValueError('Go loader patch no longer matches original bytes')
            write_image(elf, address, new)
    result = bytearray(elf.mmap)
    if len(result) != len(data):
        raise ValueError('patched image size differs from the input')
    phoff, old_phnum = elf['e_phoff'], elf['e_phnum']
    headers = bytearray(data[phoff:phoff + old_phnum * 56])
    has_eh_header = any(seg['p_type'] == 'PT_GNU_EH_FRAME' for seg in elf.iter_segments())
    phnum = old_phnum + 1 + int(unwind_result is not None and not has_eh_header) + int(go_result is not None)
    if phnum >= 65535 or code_off < phnum * 56:
        raise ValueError('insufficient space for new program headers')
    for n in range(old_phnum):
        kind = unpack_ints('<I', headers, n * 56)[0]
        if kind == 6:  # PT_PHDR
            struct.pack_into('<IIQQQQQQ', headers, n * 56, 6, 4, load_off, load_va,
                             load_va, phnum * 56, phnum * 56, 8)
        elif kind == 0x6474e550 and unwind_result is not None:
            address = unwind_result.header_address
            struct.pack_into('<IIQQQQQQ', headers, n * 56, kind, 4,
                             load_off + address - load_va, address, address,
                             unwind_result.header_size, unwind_result.header_size, 4)
    size = code_off + len(payload)
    headers += struct.pack('<IIQQQQQQ', 1, 5, load_off, load_va, load_va, size, size, 4096)
    if unwind_result is not None and not has_eh_header:
        address = unwind_result.header_address
        headers += struct.pack('<IIQQQQQQ', 0x6474e550, 4, load_off + address - load_va,
                               address, address, unwind_result.header_size, unwind_result.header_size, 4)
    if go_result is not None:
        go_offset = load_off + metadata_va - load_va
        go_size = len(go_result['blob'])
        headers += struct.pack('<IIQQQQQQ', 1, 6, go_offset, metadata_va,
                               metadata_va, go_size, go_size, 4096)
    result += bytes(load_off - len(result))
    result += headers + bytes(code_off - len(headers)) + payload
    if go_result is not None:
        result += bytes(go_offset-len(result)) + go_result['blob']
    struct.pack_into('<Q', result, 32, load_off)
    struct.pack_into('<H', result, 56, phnum)
    address = load_va + code_off
    code_size = syms['_penryn_code_end'] - address
    rodata_offset = syms['_penryn_rodata_begin'] - address
    extra_sections: list[ExtraSection] = [
        {'name': '.penryn', 'offset': 0, 'size': code_size, 'flags': 6, 'alignment': 16}]
    if len(blob) > rodata_offset:
        extra_sections.append({'name': '.penryn.rodata', 'offset': rodata_offset,
                               'size': len(blob) - rodata_offset, 'flags': 2, 'alignment': 64})
    if unwind_result is not None:
        extra_sections += [ExtraSection(name=sec['name'], offset=metadata_offset + sec['offset'], size=sec['size'],
                                        alignment=sec['alignment'], flags=2)
                           for sec in unwind_result.sections]
    if go_result is not None:
        extra_sections += [ExtraSection(name='.penryn.go_init', offset=installer_offset,
                                        size=len(go_result['constructor_bytes']), flags=6, alignment=16),
                           ExtraSection(name='.penryn.go_data', offset=metadata_va-address,
                                        size=go_size, flags=3, alignment=4096)]
    old_shoff, shnum = elf['e_shoff'], elf['e_shnum']
    if shnum + len(extra_sections) >= 65280:
        raise ValueError('new section count requires unsupported extended ELF numbering')
    names = bytearray(elf.get_section(elf['e_shstrndx']).data())
    name_offsets: list[int] = []
    for sec in extra_sections:
        name_offsets.append(len(names))
        names += sec['name'].encode() + b'\0'
    names_off = len(result)
    result += names
    shoff = align(len(result), 8)
    result += bytes(shoff - len(result))
    shdrs = bytearray(data[old_shoff:old_shoff + shnum * 64])
    struct.pack_into('<QQ', shdrs, elf['e_shstrndx'] * 64 + 24, names_off, len(names))
    for sec, name_offset in zip(extra_sections, name_offsets):
        shdrs += struct.pack('<IIQQQQIIQQ', name_offset, 1, sec['flags'],
                             address + sec['offset'], load_off + code_off + sec['offset'],
                             sec['size'], 0, 0, sec['alignment'], 0)
    result += shdrs
    struct.pack_into('<Q', result, 40, shoff)
    struct.pack_into('<H', result, 60, shnum + len(extra_sections))
    return result


class UnwindDisabled(TypedDict):
    enabled: bool


class HelperAddresses(TypedDict):
    name: str
    start: str
    end: str


class UnscannedRange(TypedDict):
    address: str
    file_offset: int
    bytes: int


class InstructionRange(TypedDict):
    original_address: str
    start: str
    end: str
    mnemonic: str


class Optimization(TypedDict):
    preserve_flags: bool
    dead_registers: list[str]
    dead_xmms: list[str]


class Options(argparse.Namespace):
    input: Path
    output: Path | None
    report: Path | None
    no_dataflow: bool
    profile: Path | None
    regions: bool
    region_loads: bool
    unwind: bool
    infer_unwind: bool
    go_inplace: bool
    go_dispatch: bool
    go_runtime: bool
    require_runtime: bool
    require_unwind: bool
    allow_relocate: bool
    core: Path
    work_dir: Path | None


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path)
    p.add_argument('output', type=Path, nargs='?')
    p.add_argument('--report', type=Path)
    p.add_argument('--no-dataflow', action='store_true', help='preserve all original registers and flags at every replacement boundary')
    p.add_argument('--profile', type=Path, help='exact-input QEMU execution profile for hot-first layout and region selection')
    p.add_argument('--regions', action='store_true', help='group bounded straight-line sites; requires --allow-relocate')
    p.add_argument('--region-loads', action='store_true', help='also relocate read-only load glue in regions; original fault contexts are not preserved')
    p.add_argument('--unwind', action='store_true', help='emit native backtrace metadata with explicit coverage gaps')
    p.add_argument('--infer-unwind', action='store_true', help='infer missing native frames from bounded trusted-entry CFGs; implies --unwind')
    p.add_argument('--go-inplace', action='store_true', help='apply the pinned stack-neutral agy Go countbody recipe')
    p.add_argument('--go-dispatch', action='store_true', help='retain exact agy Go SSE4.2 paths proven unreachable on Penryn')
    p.add_argument('--go-runtime', action='store_true', help='register supported stack-neutral Go replacements; report unsupported sites explicitly')
    p.add_argument('--require-runtime', action='store_true', help='require every patched Go site to have verified runtime metadata')
    p.add_argument('--require-unwind', action='store_true', help='require complete native unwind coverage and verified runtime metadata for patched Go code')
    p.add_argument('--allow-relocate', action='store_true', help='experimental: borrow next instruction at short sites; known entry points protected, indirect entries not proven')
    p.add_argument('--core', type=Path, default=OPEMU_CORE)
    p.add_argument('--work-dir', type=Path, help='retain generated assembly and linked helpers')
    args = p.parse_args(namespace=Options())
    args.unwind |= args.require_unwind or args.infer_unwind
    if args.regions and not args.allow_relocate:
        p.error('--regions requires --allow-relocate')
    if args.region_loads and not args.regions:
        p.error('--region-loads requires --regions')
    started = time.perf_counter()
    report_path: Path | None = None
    if args.output is not None:
        if args.output.exists() or args.output.is_symlink():
            p.error('output already exists; refusing to overwrite')
        report_path = args.report or Path(str(args.output) + '.json')
        if report_path.exists() or report_path.is_symlink() or report_path.resolve() == args.output.resolve():
            p.error('report must be a new file distinct from output')
        if not args.output.parent.is_dir() or not report_path.parent.is_dir():
            p.error('output and report parent directories must already exist')
        if args.work_dir is not None and (args.work_dir.exists() or args.work_dir.is_symlink()):
            p.error('--work-dir must be a new directory')
    elf = load_elf(args.input)
    data = elf.data
    metadata = validate_elf(data, elf)
    if elf.get_section_by_name('.penryn'):
        p.error('input already patched')
    validated = time.perf_counter()
    weights = regions.read_profile(args.profile, digest(data)) if args.profile else None
    go_metadata = unwind.load_go_metadata(args.input)
    go_audit: 'Audit | None' = None
    if args.go_inplace or args.go_runtime or args.go_dispatch:
        if go_metadata is None:
            p.error('Go transformations require the packaged Go metadata helper')
        go_audit = go_runtime.Audit(data, elf, go_metadata)
    functions = [(f['start'], f['end'], f['name'])
                 for table in (go_metadata['tables'] if go_metadata is not None else [])
                 for f in table['functions']]
    recovery = Recovery(elf)
    recovery.add_functions(functions, source='go')
    frame_recovery: 'FrameRecovery | None' = None
    if args.infer_unwind:
        frame_recovery = native_frames.Recovery(elf, recovery)
    print('Decoding executable sections...', flush=True)
    hits, targets, caves = scan(elf, metadata=metadata, recovery=recovery, frame_recovery=frame_recovery)
    cfg_report = recovery.finish()
    scanned = time.perf_counter()
    counts = Counter(FAMILIES[i.mnemonic] for i, _ in hits)
    families = dict(counts)
    print(json.dumps(families, sort_keys=True), flush=True)
    if args.output is None:
        return
    if not hits:
        p.error('no supported instructions found')
    inplace: 'list[InplacePatch]' = []
    unchanged_functions: list[tuple[int, int, str]] = []
    if args.go_inplace:
        inplace = go_inplace.plan(data, elf, required(go_metadata, 'Go metadata'))
        unchanged_functions += [(a, b, sha) for name, (a, b, sha) in go_inplace.PINNED.items()
                                if name != 'countbody']
    dormant: 'list[DormantSite]' = []
    if args.go_dispatch:
        dormant = go_inplace.dormant(data, elf, required(go_metadata, 'Go metadata'))
        unchanged_functions += list(go_inplace.DISPATCH_PINNED.values())
    dormant_sites = {item['address'] for item in dormant}
    inplace_sites = {pc for item in inplace for pc in item['covered_original_sites']}
    protected_ranges = (metadata['relocation_ranges'] + recovery.table_ranges +
                        [(item['address'], item['address']+len(item['replacement_bytes'])) for item in inplace] +
                        [(item['address'], item['address']+len(item['original_bytes'])) for item in dormant] +
                        [(a, b) for a, b, _ in unchanged_functions])
    sites = plan([(ins, sec) for ins, sec in hits if ins.ip not in inplace_sites | dormant_sites],
                 targets, caves, args.allow_relocate,
                 optimize=not args.no_dataflow,
                 relocation_ranges=protected_ranges,
                 recovery=recovery)
    original_runtime_audit = unwind.audit_runtime(sites, go_metadata)
    go_addresses = {item['address'] for item in original_runtime_audit['go_patch_sites']}
    before_grouping = len(sites)
    if args.regions:
        # A Go module describes exact original frames. Native region fusion
        # cannot silently change the frame/stack-map contract of Go sites.
        native_sites = [s for s in sites if not any(i.ip in go_addresses for i in s.insns)]
        go_sites = [s for s in sites if any(i.ip in go_addresses for i in s.insns)]
        sites = regions.group(native_sites, targets, protected_ranges,
                              recovery, weights=weights, allow_loads=args.region_loads) + go_sites
    if weights is not None:
        site_weights = weights

        def hot_first(site: Site) -> tuple[int, int]:
            return (-max((site_weights.get(i.ip, 0) for i in site.insns), default=0), site.ip)

        sites.sort(key=hot_first)
    go_bodies: dict[int, str] = {}
    go_proofs: 'dict[int, SiteProof]' = {}
    go_rejected: 'list[Rejection]' = []
    if args.go_runtime:
        go_bodies, go_proofs, go_rejected = go_lower.prepare(sites, required(go_audit, 'Go runtime audit'),
                                                          allow_abi_borrow=not args.no_dataflow)
        lowered_go = go_bodies

        def go_last(site: Site) -> bool:
            return site.ip in lowered_go

        # Go's findfunc interval is contiguous and contains Go stubs only.
        sites.sort(key=go_last)
    runtime_audit = unwind.audit_runtime(sites, go_metadata)
    runtime_audit['go_inplace_sites'] = sorted(inplace_sites)
    runtime_audit['go_dispatch_sites'] = sorted(dormant_sites)
    runtime_audit['go_registration_rejections'] = go_rejected
    planned = time.perf_counter()
    print(f'Lowering {len(sites)} sites...', flush=True)
    load_off = align(len(data))
    load_va = align(max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'))
    extra_header = int(args.unwind and not any(seg['p_type'] == 'PT_GNU_EH_FRAME' for seg in elf.iter_segments()))
    code_off = align((elf['e_phnum'] + 1 + extra_header + bool(go_bodies)) * 56, 16)
    unwind_result: 'UnwindResult | None' = None
    go_result: 'BuildResult | None' = None
    go_metadata_va: int | None = None
    go_installer_va: int | None = None
    with tempfile.TemporaryDirectory(prefix='static-penryn-') as temp:
        work = args.work_dir or Path(temp)
        work.mkdir(parents=True, exist_ok=True)
        blob, syms = build_stubs(sites, load_va + code_off, work, args.core,
                                 region_loads=args.region_loads, go_bodies=go_bodies)
        registered_ranges: 'list[StubRange]' = []
        for n, site in enumerate(sites):
            if site.ip in go_bodies:
                start, end = syms[f'site_{n}'], syms[f'site_{n}_end']
                code = bytes(blob[start-load_va-code_off:end-load_va-code_off])
                go_lower.validate_emitted(code, start, constant_ranges=[
                    (syms['_penryn_rodata_begin'], load_va+code_off+len(blob))])
                registered_ranges.append({'start': start, 'end': end, 'original_pc': site.ip,
                                          'continuation': site.end, 'code': code})
        ranges: 'list[Range]' = []
        if args.unwind:
            for n, site in enumerate(sites):
                if site.ip in go_bodies:
                    continue
                if site.sequence:
                    ranges.append({'start': syms[f'site_{n}'], 'end': syms[f'site_{n}_end'],
                                   'original_pc': site.ip, 'kind': 'region'})
                else:
                    for m, ins in enumerate(syms.sequences[n]):
                        last = m + 1 == len(syms.sequences[n])
                        ranges.append({'start': syms[f'insn_{n}_{m}'],
                                       'end': syms[f'site_{n}_end'] if last else syms[f'insn_{n}_{m}_end'],
                                       'original_pc': ins.ip, 'kind': 'lowered' if ins.mnemonic in FAMILIES else 'tail',
                                       'runtime': 'go' if site.ip in go_addresses else 'native'})
            unwind_result = unwind.build(elf, blob, load_va + code_off, ranges,
                                         load_va + code_off + align(len(blob), 8), work,
                                         helper_elf=work / 'stubs.elf', frame_recovery=frame_recovery)
        if registered_ranges:
            for attempt in range(4):
                rx_end = align(len(blob), 8) + len(unwind_result.blob) if unwind_result is not None else len(blob)
                go_installer_va = load_va + code_off + align(rx_end, 16)
                if args.unwind and attempt == 0:
                    # The first added initializer FDE grows the CFI stream.
                    # Leave room before its temporary linker text section;
                    # the following pass removes this provisional gap.
                    go_installer_va += 4096
                go_metadata_va = align(go_installer_va + 4096)
                go_result = go_runtime.build(required(go_audit, 'Go runtime audit'), registered_ranges,
                                             go_metadata_va, go_installer_va, work=work)
                if not args.unwind:
                    break
                unwind_result = unwind.build(elf, blob, load_va + code_off, ranges,
                    load_va + code_off + align(len(blob), 8), work,
                    helper_elf=work / 'stubs.elf', frame_recovery=frame_recovery,
                    extra_helpers=[(work/'go-init.elf', go_installer_va,
                                    go_installer_va+len(go_result['constructor_bytes']), 'go_initializer')])
                if go_installer_va == load_va + code_off + align(align(len(blob), 8)+len(unwind_result.blob), 16):
                    break
            else:
                raise ValueError('Go initializer/native unwind layout failed to converge')
        handled = set(go_bodies)
        unhandled = [item for item in runtime_audit['go_patch_sites'] if item['address'] not in handled]
        reasons: list[str] = []
        if go_metadata is None:
            reasons.append('Go metadata was not audited')
        elif go_metadata.get('go_build_version') and not go_metadata.get('tables'):
            reasons.append('Go build information exists without a validated pclntab')
        if go_audit is not None:
            runtime_audit['go_candidate_provenance'] = go_audit.candidate_provenance
            if any(item['classification'] != 'unreferenced-header-magic' for item in go_audit.candidate_provenance):
                reasons.append('unresolved or referenced Go metadata candidates')
        elif go_metadata is not None and go_metadata['rejected_candidates']:
            reasons.append('unresolved Go metadata candidates')
        if unhandled:
            reasons.append(f'{len(unhandled)} Go instruction sites still lack registered runtime metadata')
        runtime_audit.update({
            'known_go_sites_unhandled': len(unhandled), 'go_unhandled_sites': unhandled,
            'go_registered_sites': sorted(handled), 'strict_runtime_reasons': reasons,
            'go_registration': go_result['report'] if go_result else None,
            'go_startup_patches': [{'offset': item['offset'], 'original': item['old'].hex(),
                                    'replacement': item['new'].hex()}
                                   for item in go_result['patches']] if go_result else [],
            'go_lowering_proofs': list(go_proofs.values()),
            'go_safepoints_supported': bool(go_result) and not unhandled,
            'go_stack_growth_supported': bool(go_result) and not unhandled})
        if (args.require_unwind or args.require_runtime) and reasons:
            p.error('strict runtime gate: ' + '; '.join(reasons))
        if args.require_unwind and required(unwind_result, 'native unwind result').report['uncovered_ranges']:
            uncovered = required(unwind_result, 'native unwind result').report['uncovered_ranges']
            p.error(f"strict unwind gate: {len(uncovered)} ranges lack native backtrace metadata")
    compiled = time.perf_counter()
    result = rewrite(data, elf, sites, blob, syms, load_off, load_va, code_off, unwind_result,
                     inplace=inplace, go_result=go_result,
                     go_metadata_va=go_metadata_va, go_installer_va=go_installer_va)
    elf.close()
    # Reparse and decode the patched executable, including emitted helper code.
    result_elf = ELFFile(io.BytesIO(result))
    validate_elf(result, result_elf)
    remaining, _, _ = scan(result_elf, inventory_only=True)
    if {ins.ip for ins, _ in remaining} != dormant_sites:
        raise ValueError('remaining supported instruction set differs from verified dormant paths')
    for item in dormant:
        off = va_offset(result_elf, item['address'])
        if result[off:off+len(item['original_bytes'])] != item['original_bytes']:
            raise ValueError('CPU-dispatch protected bytes changed during rewriting')
    for a, b, sha in unchanged_functions:
        off = va_offset(result_elf, a)
        if digest(result[off:off+b-a]) != sha:
            raise ValueError('a function supporting the Go in-place/dispatch proof changed during rewriting')
    verified = time.perf_counter()
    report: 'PatchReport' = {
        'schema_version': 2,
        'input': str(args.input), 'input_sha256': digest(data),
        'output': str(args.output), 'output_sha256': digest(result),
        'families': families, 'sites': len(sites),
        'short_jumps': sum(s.cave is not None for s in sites),
        'relocated_following': sum(s.tail is not None or len(s.insns) > 1 for s in sites),
        'added_code_bytes': syms['_penryn_code_end'] - (load_va + code_off),
        'added_payload_bytes': len(blob), 'remaining_decoded_supported': len(remaining),
        'dataflow_enabled': not args.no_dataflow,
        'control_flow': cfg_report,
        'runtime': runtime_audit,
        'unwind': unwind_result.report if unwind_result is not None else {'enabled': False},
        'added_unwind_bytes': len(unwind_result.blob) if unwind_result is not None else 0,
        'added_go_metadata_bytes': len(go_result['blob']) if go_result else 0,
        'go_runtime_enabled': args.go_runtime, 'go_inplace_enabled': args.go_inplace,
        'go_dispatch_enabled': args.go_dispatch,
        'dormant_instructions': [{**item, 'original_bytes': item['original_bytes'].hex()} for item in dormant],
        'inplace_patches': [{key: value for key, value in item.items()
                             if key not in ('original_bytes', 'replacement_bytes')} for item in inplace],
        'regions_enabled': args.regions, 'region_loads_enabled': args.region_loads,
        'fused_regions': sum(bool(s.sequence) for s in sites),
        'eliminated_site_jumps': before_grouping - len(sites),
        'profile': str(args.profile) if args.profile else None,
        'flags_proven_dead': sum(not h.preserve_flags for s in sites for h in s.hints),
        'sites_with_dead_gprs': sum(bool(h.dead_registers) for s in sites for h in s.hints),
        'sites_with_dead_xmms': sum(bool(h.dead_xmms) for s in sites for h in s.hints),
        'string_helpers': syms.helper_report,
        'helpers': [HelperAddresses(name=h['name'], start=hex(h['start']), end=hex(h['end']))
                    for h in syms.helper_ranges] +
                   ([HelperAddresses(name='go_initializer',
                                     start=hex(required(go_installer_va, 'Go initializer address')),
                                     end=hex(required(go_installer_va, 'Go initializer address')
                                             + len(go_result['constructor_bytes'])))]
                    if go_result else []),
        'unscanned_rx_ranges': [{'address': hex(a), 'file_offset': off, 'bytes': size}
                               for a, off, size in metadata['uncovered_executable_ranges']],
        'timing_seconds': {'validate': validated - started, 'scan': scanned - validated,
                           'plan': planned - scanned, 'compile': compiled - planned,
                           'rewrite_and_verify': verified - compiled},
        'string_core_sha256': CORE_HASHES,
        'experimental': True,
        'limitations': ['linear disassembly is not a proof of code/data boundaries',
                        'indirect entry points not exhaustively recovered',
                        'Go runtime coverage is limited to the explicitly reported registered or in-place contracts',
                        'native unwind coverage is partial and reported separately',
                        'original fault contexts and exception landing pads not remapped',
                        'JIT code and shared libraries not rewritten',
                        'AVX/AES/BMI remain behind original CPU dispatch'],
        'patches': [{'address': hex(s.ip), 'end': hex(s.end),
                     'original': data[s.offset:s.offset+s.end-s.ip].hex(),
                     'stub': hex(syms[f'site_{n}']),
                     'stub_end': hex(syms[f'site_{n}_end']),
                     'instruction_ranges': [
                         {'original_address': hex(ins.ip), 'start': hex(syms[f'insn_{n}_{m}']),
                          'end': hex(syms[f'insn_{n}_{m}_end']),
                          'mnemonic': FAMILIES.get(ins.mnemonic, str(ins).split()[0].upper())}
                         for m, ins in enumerate(syms.sequences[n])],
                     'cave': hex(s.cave) if s.cave is not None else None,
                     'instructions': [str(i) for i in s.insns],
                     'tail': str(s.tail) if s.tail is not None else None,
                     'region': bool(s.sequence), 'shared_frame': syms.shared_frames[n],
                     'optimization': [{'preserve_flags': h.preserve_flags,
                                       'dead_registers': [REGISTER_NAMES[r] for r in sorted(h.dead_registers)],
                                       'dead_xmms': [REGISTER_NAMES[r] for r in sorted(h.dead_xmms)]}
                                      for h in s.hints]}
                    for n, s in enumerate(sites)]
    }
    report_path = required(report_path, 'report path')
    publish(args.output, report_path, result, report, args.input.stat().st_mode)
    print(f'Wrote {args.output}: {len(hits)} instructions, {len(blob)} bytes of code and constants; report {report_path}')


if __name__ == '__main__':
    main()
