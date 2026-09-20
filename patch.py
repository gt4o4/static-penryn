#!/usr/bin/env python3
"""Experimental offline ELF64 lowering. Writes a new file; never edits the input.

The report is a coverage record, not a proof of arbitrary binary control flow.
Only decoded executable sections are rewritten. Indirect entry points, JIT code,
shared libraries, and asynchronous unwind metadata need separate validation.
"""
import argparse
from collections import Counter
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

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from iced_x86 import BlockEncoder, Decoder, FlowControl, Mnemonic, OpKind, Register
from dataflow import Hints, analyze
from elfcheck import validate_elf

FAMILIES = {getattr(Mnemonic, name): name for name in (
    'POPCNT', 'CRC32', 'PCMPGTQ', 'PCMPISTRI', 'PCMPISTRM',
    'PCMPESTRI', 'PCMPESTRM', 'PCMPESTRI64', 'PCMPESTRM64')}
HERE = Path(__file__).resolve().parent
CORE_HASHES = {
    'emu-core.c': '37afd5483069ddd7d746da5b247b425b7fad7b0b7f23c1335fd68097478de475',
    'emu-core.h': '805c42a74ada75b48c00e1d134b4b938647c25ecd718fd18df4205c8d30cc9cd',
}
REGISTER_NAMES = {value: name.lower() for name, value in vars(Register).items()
                  if not name.startswith('_')}


def align(value, alignment=4096):
    return (value + alignment - 1) & -alignment


def run(*args):
    subprocess.run([str(x) for x in args], check=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def publish(output, report_path, result, report, mode):
    """Publish complete new files without truncation or partial executables."""
    temporary = []
    linked_report = False
    try:
        for path, content, permissions in (
            (output, result, mode & 0o777),
            (report_path, (json.dumps(report, indent=2) + '\n').encode(), 0o644),
        ):
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
    insns: list
    offset: int
    end: int
    cave: int | None = None
    tail: object = None
    hints: list = field(default_factory=list)

    @property
    def ip(self):
        return self.insns[0].ip


def scan(elf, *, inventory_only=False, metadata=None):
    hits, targets, caves = [], {elf['e_entry']}, []
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
                        addend += symbols.get_symbol(rel['r_info_sym'])['st_value']
                    targets.add(addend)
        if not sec['sh_flags'] & 4:
            continue
        data = sec.data()
        if inventory_only:
            hits.extend((ins, sec) for ins in Decoder(64, data, ip=sec['sh_addr'])
                        if ins.mnemonic in FAMILIES)
            continue
        padding = None
        previous_terminates = False
        for ins in Decoder(64, data, ip=sec['sh_addr']):
            flow = ins.flow_control
            mnemonic = ins.mnemonic
            if flow != FlowControl.NEXT and ins.op0_kind in (
                OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64
            ):
                targets.add(ins.near_branch_target)
            if ins.is_ip_rel_memory_operand:
                targets.add(ins.ip_rel_memory_address)
            if mnemonic in (Mnemonic.MOV, Mnemonic.PUSH):
                # Retained immediate code pointers matter even in stripped
                # ET_EXEC images (movabs/jmp, push/ret). False positives here
                # only make relocation more conservative.
                for op in range(ins.op_count):
                    if ins.op_kind(op) in (OpKind.IMMEDIATE32, OpKind.IMMEDIATE64,
                                          OpKind.IMMEDIATE32TO64):
                        targets.add(ins.immediate(op) & ((1 << 64) - 1))
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
    return hits, targets, caves


def plan(elf, hits, targets, caves, allow_relocate, *, optimize=True, relocation_ranges=()):
    used, plans, failures = set(), [], []
    section_data = {}
    # Do not steal a known entry point even when it is in padding.
    protected = sorted(targets)
    import bisect

    def occupied(a, b):
        j = bisect.bisect_left(protected, a)
        return j < len(protected) and protected[j] < b

    relocation_ranges = sorted(relocation_ranges)
    relocation_starts = [a for a, _ in relocation_ranges]
    relocation_ends = []
    for _, end in relocation_ranges:
        relocation_ends.append(max(end, relocation_ends[-1] if relocation_ends else 0))

    def loader_writes(a, b):
        j = bisect.bisect_left(relocation_starts, b) - 1
        return j >= 0 and relocation_ends[j] > a

    def contents(sec):
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
                if a + 5 <= b and a <= ins.ip + 2 + 127 and not occupied(a, a + 5):
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
            site.hints.append(analyze(continuation) if optimize else Hints())
        plans.append(site)
    if failures:
        raise ValueError(f'{len(failures)} unsafe sites; no output written:\n' + '\n'.join(failures[:30]))
    return plans


def va_offset(elf, va):
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va < seg['p_vaddr'] + seg['p_filesz']:
            return seg['p_offset'] + va - seg['p_vaddr']
    raise ValueError(f'unmapped file address 0x{va:x}')


def jump(src, dst):
    delta = dst - src - 5
    if not -(1 << 31) <= delta < 1 << 31:
        raise ValueError('branch exceeds rel32 reach')
    return b'\xe9' + struct.pack('<i', delta)


def _relocate_tail(ins, address):
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


def build_stubs(sites, address, work, core):
    import lower
    import strings
    bodies = []
    instructions = [i for site in sites for i in site.insns]
    for site in sites:
        body = []
        for n, ins in enumerate(site.insns):
            hint = site.hints[n] if site.hints else Hints()
            if ins.mnemonic in lower.SUPPORTED:
                body.append(lower.lower(ins, preserve_flags=hint.preserve_flags,
                                        dead_registers=hint.dead_registers))
            else:
                body.append(strings.lower(ins))
        bodies.append('\n'.join(body))
    objects = [work / 'stubs.o']
    helper_report = {}
    if any(i.mnemonic in strings.SUPPORTED for i in instructions):
        for filename, expected in CORE_HASHES.items():
            if digest((core / filename).read_bytes()) != expected:
                raise ValueError(f'{filename} differs from the validated 6641be6 core')
        obj, helper_report = strings.build_helpers(instructions, core, work)
        objects.append(obj)
    # Text and tables share an RX mapping but get distinct ELF sections.
    # A CRC table is data even when executable at the hardware page level.
    (work / 'layout.ld').write_text(f'''SECTIONS {{
      . = {address};
      .patch {address} : {{
        KEEP(*(.text)) *(.text.*)
        _penryn_code_end = .;
        . = ALIGN(64);
        _penryn_rodata_begin = .;
        *(.rodata*)
      }}
      /DISCARD/ : {{ *(.eh_frame*) *(.comment) *(.note*) }}
    }}\n''')
    tail_sizes = {n: 32 for n, s in enumerate(sites) if s.tail is not None}
    for attempt in range(4):
        asm = ['.intel_syntax noprefix', '.text']
        for n, site in enumerate(sites):
            asm += [f'.global site_{n}', f'site_{n}:', bodies[n]]
            if site.tail is not None:
                asm += [f'.global tail_{n}', f'tail_{n}:', f'.fill {tail_sizes[n]}, 1, 0x90']
            asm += ['.byte 0xe9', '.long 0', f'.reloc .-4, R_X86_64_PC32, {site.end}-4']
        asm += [lower.support_assembly(), '.section .note.GNU-stack,"",@progbits']
        (work / 'stubs.S').write_text('\n'.join(asm) + '\n')
        run('cc', '-c', '-o', work / 'stubs.o', work / 'stubs.S')
        run('ld', '--gc-sections', '-T', work / 'layout.ld', '-o', work / 'stubs.elf', *objects)
        with (work / 'stubs.elf').open('rb') as f:
            stubelf = ELFFile(f)
            syms = {s.name: s['st_value'] for s in stubelf.get_section_by_name('.symtab').iter_symbols()}
            sec = stubelf.get_section_by_name('.patch')
            if sec['sh_addr'] != address:
                raise ValueError('linker moved the injected section from its requested address')
            blob = bytearray(sec.data())
            for s in stubelf.iter_sections():
                if s['sh_flags'] & 2 and s.name != '.patch' and s['sh_size']:
                    raise ValueError(f'unexpected allocated helper section {s.name}')
        moved = {n: _relocate_tail(s.tail, syms[f'tail_{n}'])
                 for n, s in enumerate(sites) if s.tail is not None}
        sizes = {n: len(code) for n, code in moved.items()}
        if sizes == tail_sizes:
            for n, code in moved.items():
                offset = syms[f'tail_{n}'] - address
                blob[offset:offset + len(code)] = code
            syms['_helper_report'] = helper_report
            return blob, syms
        tail_sizes = sizes
    raise ValueError('relocated instruction layout failed to converge')


def rewrite(data, elf, sites, blob, syms, load_off, load_va, code_off):
    result = bytearray(data)
    for n, s in enumerate(sites):
        dest = syms[f'site_{n}']
        if s.cave is None:
            patch = jump(s.ip, dest)
        else:
            patch = b'\xeb' + struct.pack('b', s.cave - s.ip - 2)
            off = va_offset(elf, s.cave)
            result[off:off + 5] = jump(s.cave, dest)
        result[s.offset:s.offset + s.end - s.ip] = patch + b'\x90' * (s.end - s.ip - len(patch))
    phoff, phnum = elf['e_phoff'], elf['e_phnum']
    headers = bytearray(data[phoff:phoff + phnum * 56])
    size = code_off + len(blob)
    # Relocate the PHDR table into the new mapping. No NOTE or other loader
    # metadata is sacrificed. Preserve every original LOAD's offset/address.
    for n in range(phnum):
        if struct.unpack_from('<I', headers, n * 56)[0] == 6:  # PT_PHDR
            struct.pack_into('<IIQQQQQQ', headers, n * 56, 6, 4, load_off, load_va,
                             load_va, (phnum + 1) * 56, (phnum + 1) * 56, 8)
    headers += struct.pack('<IIQQQQQQ', 1, 5, load_off, load_va, load_va, size, size, 4096)
    result += b'\0' * (load_off - len(result))
    result += headers + b'\0' * (code_off - len(headers)) + blob
    struct.pack_into('<Q', result, 32, load_off)
    struct.pack_into('<H', result, 56, phnum + 1)
    # Advertise added code for disassemblers without touching original sections.
    old_names = elf.get_section(elf['e_shstrndx']).data()
    names_off = len(result)
    extra_names = b'.penryn\0.penryn.rodata\0'
    result += old_names + extra_names
    shoff = align(len(result), 8)
    result += b'\0' * (shoff - len(result))
    old_shoff, shnum = elf['e_shoff'], elf['e_shnum']
    shdrs = bytearray(data[old_shoff:old_shoff + shnum * 64])
    struct.pack_into('<QQ', shdrs, elf['e_shstrndx'] * 64 + 24, names_off, len(old_names) + len(extra_names))
    address = load_va + code_off
    code_size = syms['_penryn_code_end'] - address
    rodata_offset = syms['_penryn_rodata_begin'] - address
    shdrs += struct.pack('<IIQQQQIIQQ', len(old_names), 1, 6, load_va + code_off,
                         load_off + code_off, code_size, 0, 0, 16, 0)
    added_sections = 1
    if len(blob) > rodata_offset:
        shdrs += struct.pack('<IIQQQQIIQQ', len(old_names) + 8, 1, 2,
                             address + rodata_offset, load_off + code_off + rodata_offset,
                             len(blob) - rodata_offset, 0, 0, 64, 0)
        added_sections += 1
    result += shdrs
    struct.pack_into('<Q', result, 40, shoff)
    struct.pack_into('<H', result, 60, shnum + added_sections)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path)
    p.add_argument('output', type=Path, nargs='?')
    p.add_argument('--report', type=Path)
    p.add_argument('--no-dataflow', action='store_true', help='preserve all original registers and flags at every replacement boundary')
    p.add_argument('--allow-relocate', action='store_true', help='experimental: borrow next instruction at short sites; known entry points protected, indirect entries not proven')
    p.add_argument('--core', type=Path, default=HERE.parents[2] / 'submodules/opemu-linux/core')
    p.add_argument('--work-dir', type=Path, help='retain generated assembly and linked helpers')
    args = p.parse_args()
    started = time.perf_counter()
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
    data = args.input.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    metadata = validate_elf(data, elf)
    if elf.get_section_by_name('.penryn'):
        p.error('input already patched')
    validated = time.perf_counter()
    print('Decoding executable sections...', flush=True)
    hits, targets, caves = scan(elf, metadata=metadata)
    scanned = time.perf_counter()
    counts = Counter(FAMILIES[i.mnemonic] for i, _ in hits)
    print(json.dumps(dict(counts), sort_keys=True), flush=True)
    if args.output is None:
        return
    if not hits:
        p.error('no supported instructions found')
    sites = plan(elf, hits, targets, caves, args.allow_relocate,
                 optimize=not args.no_dataflow, relocation_ranges=metadata['relocation_ranges'])
    planned = time.perf_counter()
    print(f'Lowering {len(sites)} sites...', flush=True)
    load_off = align(len(data))
    load_va = align(max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'))
    code_off = align((elf['e_phnum'] + 1) * 56, 16)
    with tempfile.TemporaryDirectory(prefix='static-penryn-') as temp:
        work = args.work_dir or Path(temp)
        work.mkdir(parents=True, exist_ok=True)
        blob, syms = build_stubs(sites, load_va + code_off, work, args.core)
    compiled = time.perf_counter()
    result = rewrite(data, elf, sites, blob, syms, load_off, load_va, code_off)
    # Reparse and decode the patched executable, including emitted helper code.
    remaining, _, _ = scan(ELFFile(io.BytesIO(result)), inventory_only=True)
    if remaining:
        raise ValueError(f'{len(remaining)} supported instructions remain after rewrite')
    verified = time.perf_counter()
    report = {
        'input': str(args.input), 'input_sha256': digest(data),
        'output': str(args.output), 'output_sha256': digest(result),
        'families': dict(counts), 'sites': len(sites),
        'short_jumps': sum(s.cave is not None for s in sites),
        'relocated_following': sum(s.tail is not None or len(s.insns) > 1 for s in sites),
        'added_code_bytes': syms['_penryn_code_end'] - (load_va + code_off),
        'added_payload_bytes': len(blob), 'remaining_decoded_supported': len(remaining),
        'dataflow_enabled': not args.no_dataflow,
        'flags_proven_dead': sum(not h.preserve_flags for s in sites for h in s.hints),
        'sites_with_dead_gprs': sum(bool(h.dead_registers) for s in sites for h in s.hints),
        'string_helpers': syms['_helper_report'],
        'unscanned_rx_ranges': [{'address': hex(a), 'file_offset': off, 'bytes': size}
                               for a, off, size in metadata['uncovered_executable_ranges']],
        'timing_seconds': {'validate': validated - started, 'scan': scanned - validated,
                           'plan': planned - scanned, 'compile': compiled - planned,
                           'rewrite_and_verify': verified - compiled},
        'string_core_sha256': CORE_HASHES,
        'experimental': True,
        'limitations': ['linear disassembly is not a proof of code/data boundaries',
                        'indirect entry points not exhaustively recovered',
                        'no new Go/ELF unwind metadata',
                        'JIT code and shared libraries not rewritten',
                        'AVX/AES/BMI remain behind original CPU dispatch'],
        'patches': [{'address': hex(s.ip), 'original': data[s.offset:s.offset+s.end-s.ip].hex(),
                     'stub': hex(syms[f'site_{n}']),
                     'cave': hex(s.cave) if s.cave is not None else None,
                     'instructions': [str(i) for i in s.insns],
                     'tail': str(s.tail) if s.tail is not None else None,
                     'optimization': [{'preserve_flags': h.preserve_flags,
                                       'dead_registers': [REGISTER_NAMES[r] for r in sorted(h.dead_registers)]}
                                      for h in s.hints]}
                    for n, s in enumerate(sites)]
    }
    publish(args.output, report_path, result, report, args.input.stat().st_mode)
    print(f'Wrote {args.output}: {len(hits)} instructions, {len(blob)} bytes of code and constants; report {report_path}')


if __name__ == '__main__':
    main()
