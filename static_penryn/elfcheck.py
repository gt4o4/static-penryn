"""Loader-facing validation and conservative entry-point recovery for ELF64.

Section headers describe the rewrite surface, but PT_LOAD/PT_DYNAMIC describe
what the kernel and dynamic loader actually use. Keep those two views consistent
and record relocation writes before permitting any byte replacement. This is
not control-flow recovery: packed pointers and relative jump tables remain a
limitation of the offline rewriter.

Dynamic table/RELR format: https://gabi.xinuos.com/elf/09-dynamic.html
"""
import bisect
from typing import TypedDict

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment

from .checked import iter_ints, unpack_ints


class ElfMetadata(TypedDict):
    relocation_ranges: list[tuple[int, int]]
    pointer_targets: set[int]
    # (address, file offset, size) of RX bytes outside executable sections
    uncovered_executable_ranges: list[tuple[int, int, int]]


def validate_elf(data: bytes | bytearray, elf: ELFFile) -> ElfMetadata:
    """Return pointer targets, loader relocation spans and unscanned RX ranges.

    Fail closed for malformed/ambiguous mappings; support ordinary stripped
    executables and PIEs whose section table is retained. All returned addresses
    are link-time VAs, so they work for both ET_EXEC and load-biased ET_DYN.
    """
    size = len(data)

    def file_range(start: int, count: int, what: str) -> None:
        if start < 0 or count < 0 or start > size or count > size - start:
            raise ValueError(f'{what} extends outside the input file')

    if not (elf.elfclass == 64 and elf.little_endian
            and elf['e_machine'] == 'EM_X86_64'
            and elf['e_type'] in ('ET_EXEC', 'ET_DYN')
            and elf['e_ehsize'] == 64 and elf['e_phentsize'] == 56
            and elf['e_shentsize'] == 64 and 0 < elf['e_phnum'] < 65534
            and 0 < elf['e_shnum'] < 65278
            and 0 < elf['e_shstrndx'] < elf['e_shnum']):
        raise ValueError('requires ordinary little-endian x86-64 executable/PIE with section headers')
    file_range(elf['e_phoff'], elf['e_phnum'] * 56, 'program-header table')
    file_range(elf['e_shoff'], elf['e_shnum'] * 64, 'section-header table')
    segments = list(elf.iter_segments())
    loads = [s for s in segments if s['p_type'] == 'PT_LOAD']
    if not loads:
        raise ValueError('ELF has no PT_LOAD segments')
    for seg in segments:
        file_range(seg['p_offset'], seg['p_filesz'], f"{seg['p_type']} segment")
    for seg in loads:
        if seg['p_filesz'] > seg['p_memsz']:
            raise ValueError('PT_LOAD file size exceeds its memory size')
        if seg['p_vaddr'] + seg['p_memsz'] > 1 << 64:
            raise ValueError('PT_LOAD virtual address overflows ELF64')
        alignment = seg['p_align']
        if alignment > 1 and (alignment & (alignment - 1)
                              or (seg['p_vaddr'] - seg['p_offset']) % alignment):
            raise ValueError('PT_LOAD has invalid alignment or offset/address congruence')
    def vaddr(seg: Segment) -> int:
        return seg['p_vaddr']

    ordered = sorted(loads, key=vaddr)
    for left, right in zip(ordered, ordered[1:]):
        if left['p_vaddr'] + left['p_memsz'] > right['p_vaddr']:
            raise ValueError('overlapping PT_LOAD virtual ranges are ambiguous')
    load_starts = [s['p_vaddr'] for s in ordered]
    load_ranges = [(s['p_vaddr'], s['p_vaddr'] + s['p_filesz'],
                    s['p_vaddr'] + s['p_memsz'], s['p_offset']) for s in ordered]

    def mapped(address: int, count: int = 1, *, file_backed: bool = True) -> Segment:
        index = bisect.bisect_right(load_starts, address) - 1
        if index < 0 or count < 0 or address + count > load_ranges[index][1 if file_backed else 2]:
            raise ValueError(f'address range 0x{address:x}+{count} is not uniquely PT_LOAD mapped')
        return ordered[index]

    def read_va(address: int, count: int) -> memoryview:
        index = bisect.bisect_right(load_starts, address) - 1
        if index < 0 or count < 0 or address + count > load_ranges[index][1]:
            raise ValueError(f'address range 0x{address:x}+{count} is not file-backed PT_LOAD mapped')
        start, _, _, file_offset = load_ranges[index]
        offset = file_offset + address - start
        return memoryview(data)[offset:offset + count]

    sections = list(elf.iter_sections())
    if sections[elf['e_shstrndx']]['sh_type'] != 'SHT_STRTAB':
        raise ValueError('section-name table is not SHT_STRTAB')
    executable: list[tuple[int, int]] = []
    for sec in sections:
        count = sec['sh_size']
        if sec['sh_type'] != 'SHT_NOBITS':
            file_range(sec['sh_offset'], count, f'section {sec.name}')
        if not sec['sh_flags'] & 4 or not count:
            continue
        if not sec['sh_flags'] & 2 or sec['sh_type'] != 'SHT_PROGBITS' or sec['sh_flags'] & 0x800:
            raise ValueError(f'executable section {sec.name} must be allocated, uncompressed PROGBITS')
        seg = mapped(sec['sh_addr'], count)
        if not seg['p_flags'] & 1:
            raise ValueError(f'executable section {sec.name} is not in an executable PT_LOAD')
        if sec['sh_offset'] != seg['p_offset'] + sec['sh_addr'] - seg['p_vaddr']:
            raise ValueError(f'executable section {sec.name} disagrees with its PT_LOAD file mapping')
        # One file byte can be loaded at several VAs. A rel32 patch at one
        # alias is wrong at the other, and even a non-executable alias could
        # consume the changed bytes as data. Compare declared byte ranges,
        # not rounded mmap pages: adjacent LOADs may legally share a page.
        file_start, file_end = sec['sh_offset'], sec['sh_offset'] + count
        for other in loads:
            if other is seg or not other['p_filesz']:
                continue
            if (file_start < other['p_offset'] + other['p_filesz']
                    and other['p_offset'] < file_end):
                raise ValueError(f'executable section {sec.name} has aliased PT_LOAD file bytes')
        executable.append((sec['sh_addr'], sec['sh_addr'] + count))
    executable.sort()
    if not executable:
        raise ValueError('ELF has no file-backed executable sections')
    for left_range, right_range in zip(executable, executable[1:]):
        if left_range[1] > right_range[0]:
            raise ValueError('overlapping executable sections are ambiguous')
    starts = [a for a, _ in executable]
    low, high = executable[0][0], executable[-1][1]

    def is_code(value: int) -> bool:
        if not low <= value < high:
            return False
        index = bisect.bisect_right(starts, value) - 1
        return value < executable[index][1]

    targets: set[int] = set()

    def add_target(value: int) -> None:
        if is_code(value):
            targets.add(value)

    # Static ET_EXEC function-pointer arrays lose their relocations at link
    # time; stripping symbols must not make their targets stealable. Restrict
    # discovery to aligned words in allocated, non-code, file-backed sections.
    for sec in sections:
        if (sec['sh_flags'] & 2 and not sec['sh_flags'] & (4 | 0x800)
                and sec['sh_type'] in ('SHT_PROGBITS', 'SHT_INIT_ARRAY',
                                       'SHT_FINI_ARRAY', 'SHT_PREINIT_ARRAY')):
            begin = sec['sh_offset'] + (-sec['sh_addr'] % 8)
            end = sec['sh_offset'] + sec['sh_size']
            if begin >= end:
                continue
            end -= (end - begin) % 8
            for (value,) in iter_ints('<Q', memoryview(data)[begin:end]):
                if low <= value < high:
                    add_target(value)

    relocation_ranges: set[tuple[int, int]] = set()
    dynamic = [s for s in segments if s['p_type'] == 'PT_DYNAMIC']
    if len(dynamic) > 1:
        raise ValueError('multiple PT_DYNAMIC segments are unsupported')
    tags: dict[int, int] = {}
    if dynamic:
        seg = dynamic[0]
        container = mapped(seg['p_vaddr'], seg['p_filesz'])
        if seg['p_offset'] != container['p_offset'] + seg['p_vaddr'] - container['p_vaddr']:
            raise ValueError('PT_DYNAMIC disagrees with its PT_LOAD file mapping')
        if seg['p_filesz'] % 16:
            raise ValueError('PT_DYNAMIC has a truncated entry')
        found_null = False
        for tag, value in iter_ints('<qQ', memoryview(data)[seg['p_offset']:seg['p_offset'] + seg['p_filesz']]):
            if tag == 0:
                found_null = True
                break
            # Repeatable DT_NEEDED and vendor tags do not describe ranges.
            if tag in tags and tags[tag] != value and tag in (2, 7, 8, 9, 17, 18, 19, 20, 23, 35, 36, 37):
                raise ValueError('conflicting dynamic relocation table entries')
            tags[tag] = value
        if not found_null:
            raise ValueError('PT_DYNAMIC has no DT_NULL terminator')

    symbol_cache: dict[int, tuple[int, int]] = {0: (0, 0)}

    def symbol(index: int) -> tuple[int, int]:
        if index in symbol_cache:
            return symbol_cache[index]
        if not index:
            return 0, 0
        if 6 not in tags or tags.get(11) != 24:
            raise ValueError('dynamic relocation requires a valid DT_SYMTAB/DT_SYMENT')
        _, _, _, section_index, value, sym_size = unpack_ints('<IBBHQQ', read_va(tags[6] + index * 24, 24))
        symbol_cache[index] = (value if section_index else 0), sym_size
        return symbol_cache[index]

    widths = {1: 8, 2: 4, 3: 4, 4: 4, 6: 8, 7: 8, 8: 8, 9: 4,
              10: 4, 11: 4, 12: 2, 13: 2, 14: 1, 15: 1, 16: 8, 17: 8,
              18: 8, 19: 4, 20: 4, 21: 4, 22: 4, 23: 4, 24: 8, 25: 8,
              26: 4, 27: 8, 28: 8, 29: 8, 30: 8, 31: 8, 32: 4, 33: 8,
              34: 4, 35: 0, 36: 16, 37: 8, 38: 8, 41: 4, 42: 4, 43: 4}

    def relocation(where: int, info: int, addend: int | None) -> None:
        kind, sym = info & 0xffffffff, info >> 32
        if not kind:
            return
        value, sym_size = symbol(sym)
        width = sym_size if kind == 5 else widths.get(kind)
        if width is None:
            raise ValueError(f'unsupported dynamic relocation type {kind}')
        if width:
            mapped(where, width, file_backed=False)
            relocation_ranges.add((where, where + width))
        if addend is not None:
            add_target(value + addend)
        elif kind in (1, 8, 37, 38):
            # REL stores its addend at the destination instead of in the table.
            add_target(value + unpack_ints('<Q', read_va(where, 8))[0])

    def table(address: int, count: int, entry: int, rela: bool) -> None:
        expected = 24 if rela else 16
        if entry != expected or count % entry:
            raise ValueError('dynamic relocation table has invalid entry size')
        if not count:
            return
        for fields in iter_ints('<QQq' if rela else '<QQ', read_va(address, count)):
            relocation(fields[0], fields[1], fields[2] if rela else None)

    for address_tag, size_tag, entry_tag, rela in ((7, 8, 9, True), (17, 18, 19, False)):
        if address_tag in tags:
            if size_tag not in tags or entry_tag not in tags:
                raise ValueError('incomplete dynamic relocation table metadata')
            table(tags[address_tag], tags[size_tag], tags[entry_tag], rela)
    if 23 in tags:  # DT_JMPREL
        if 2 not in tags or tags.get(20) not in (7, 17):
            raise ValueError('invalid DT_JMPREL metadata')
        rela = tags[20] == 7
        table(tags[23], tags[2], 24 if rela else 16, rela)

    if 36 in tags:  # DT_RELR: address words interspersed with 63-word bitmaps.
        if tags.get(37) != 8 or 35 not in tags or tags[35] % 8:
            raise ValueError('invalid DT_RELR metadata')
        next_address: int | None = None
        for (entry,) in iter_ints('<Q', read_va(tags[36], tags[35])):
            if not entry & 1:
                places = [entry]
                next_address = entry + 8
            else:
                if next_address is None:
                    raise ValueError('DT_RELR bitmap appears before an address')
                places = [next_address + bit * 8 for bit in range(63) if entry & (2 << bit)]
                next_address += 63 * 8
            for where in places:
                mapped(where, 8, file_backed=False)
                relocation_ranges.add((where, where + 8))
                try:
                    add_target(unpack_ints('<Q', read_va(where, 8))[0])
                except ValueError:
                    # Zero-initialized BSS has no file-backed pointer addend.
                    pass
    for tag in (12, 13):  # DT_INIT, DT_FINI
        if tag in tags:
            add_target(tags[tag])

    # Data and ELF headers may intentionally share an RX mapping (notably agy),
    # so report gaps instead of interpreting all bytes as executable code.
    uncovered: list[tuple[int, int, int]] = []
    for seg in loads:
        if not seg['p_flags'] & 1:
            continue
        cursor, stop = seg['p_vaddr'], seg['p_vaddr'] + seg['p_filesz']
        for a, b in executable:
            if b <= cursor or a >= stop:
                continue
            if cursor < a:
                uncovered.append((cursor, seg['p_offset'] + cursor - seg['p_vaddr'], a - cursor))
            cursor = max(cursor, b)
        if cursor < stop:
            uncovered.append((cursor, seg['p_offset'] + cursor - seg['p_vaddr'], stop - cursor))
    merged_ranges: list[tuple[int, int]] = []
    for start, end in sorted(relocation_ranges):
        if merged_ranges and start <= merged_ranges[-1][1]:
            merged_ranges[-1] = (merged_ranges[-1][0], max(end, merged_ranges[-1][1]))
        else:
            merged_ranges.append((start, end))
    return {'relocation_ranges': merged_ranges, 'pointer_targets': targets,
            'uncovered_executable_ranges': uncovered}
