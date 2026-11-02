"""Structured comparison of two patched outputs and their reports.

    python -m tests.structdiff A B

Prints the ELF header, program-header and section-header differences; every
differing file byte range of the common length, attributed to B's layout;
the decoded `.penryn.eh_frame` of both (FDEs by initial location, with CIE
fields and CFA/register rows); the decoded `.penryn.eh_frame_hdr` of both,
with every table entry resolved to its FDE; and the differences between
A.json and B.json as normalized key paths. Exits 1 when a structural check
fails (decoded CFI, header table, duplicate FDEs), 0 otherwise: differences
alone are information, for comparing two patchers on one input.
"""
import argparse
import collections
from collections.abc import Iterator
import io
import json
import mmap
from pathlib import Path
import re
import sys

from elftools.dwarf.callframe import FDE, CallFrameInfo
from elftools.dwarf.structs import DWARFStructs
from elftools.elf.elffile import ELFFile

from static_penryn.checked import is_list, is_object, iter_ints, load_json, unpack_ints
from static_penryn.native_frames import row_cfa, row_pc, row_rule

type Rule = tuple[int, str, int | tuple[int, ...] | None]
type Row = tuple[int, tuple[int | None, int | None, tuple[int, ...] | None], tuple[Rule, ...]]
type FDERecord = tuple[int, str, int, tuple[Row, ...]]
type Difference = tuple[str, tuple[object, object]]

STRUCTS = DWARFStructs(little_endian=True, dwarf_format=32, address_size=8)


def hexed(value: int | str) -> str:
    return f'{value:#x}' if isinstance(value, int) else str(value)


def headers(a: ELFFile, b: ELFFile) -> None:
    print('== ELF header')
    for k in a.header:
        if a.header[k] != b.header[k]:
            print(f'  {k}: {a.header[k]} -> {b.header[k]}')
    print('== program headers')
    pa, pb = list(a.iter_segments()), list(b.iter_segments())
    if len(pa) != len(pb):
        print(f'  count {len(pa)} -> {len(pb)}')
    for i, (x, y) in enumerate(zip(pa, pb)):
        d = {k: (x.header[k], y.header[k]) for k in x.header if x.header[k] != y.header[k]}
        if d:
            print(f'  [{i}] {x["p_type"]}: '
                  + ', '.join(f'{k} {hexed(v[0])}->{hexed(v[1])}' for k, v in d.items()))


def sections(a: ELFFile, b: ELFFile, ma: mmap.mmap, mb: mmap.mmap) -> None:
    print('== section headers and contents')
    sa = {s.name: s for s in a.iter_sections()}
    sb = {s.name: s for s in b.iter_sections()}
    if list(sa) != list(sb):
        print(f'  order/names differ: {list(sa)} vs {list(sb)}')
    for name, x in sa.items():
        y = sb.get(name)
        if y is None:
            print(f'  {name}: missing in B')
            continue
        d = {k: (x.header[k], y.header[k]) for k in x.header if x.header[k] != y.header[k]}
        same: bool | str | None = None
        if x['sh_type'] != 'SHT_NOBITS':
            if x['sh_size'] != y['sh_size']:
                same = False
            else:  # 16 MiB chunks: .text and .bun are hundreds of MB
                ox, oy, size, chunk, differing = x['sh_offset'], y['sh_offset'], x['sh_size'], 1 << 24, 0
                for k in range(0, size, chunk):
                    ca = ma[ox + k:ox + min(k + chunk, size)]
                    cb = mb[oy + k:oy + min(k + chunk, size)]
                    if ca != cb:
                        differing += sum(p != q for p, q in zip(ca, cb))
                same = True if not differing else f'{differing} bytes differ'
        if d or same is False or isinstance(same, str):
            fields = ', '.join(f'{k} {hexed(v[0])}->{hexed(v[1])}' for k, v in d.items())
            content = 'content differs' if same is False else (same if isinstance(same, str) else 'content same')
            print(f'  {name}: {fields or "header same"}; {content}')


def byte_ranges(b: ELFFile, ma: mmap.mmap, mb: mmap.mmap) -> None:
    print("== differing file byte ranges (common length), attributed to B's layout")
    regions = [('ELF header', 0, 64),
               ('phdr table', b['e_phoff'], b['e_phnum'] * b['e_phentsize']),
               ('shdr table', b['e_shoff'], b['e_shnum'] * b['e_shentsize'])]
    regions += [(s.name, s['sh_offset'], s['sh_size']) for s in b.iter_sections()
                if s['sh_type'] != 'SHT_NOBITS' and s['sh_size']]
    n, chunk = min(len(ma), len(mb)), 1 << 20
    ranges: list[list[int]] = []
    for off in range(0, n, chunk):
        if ma[off:off + chunk] == mb[off:off + chunk]:
            continue
        for o2 in range(off, min(off + chunk, n), 4096):
            ca, cb = ma[o2:min(o2 + 4096, n)], mb[o2:min(o2 + 4096, n)]
            if ca == cb:
                continue
            for i in range(len(ca)):
                if ca[i] != cb[i]:
                    p = o2 + i
                    if ranges and ranges[-1][1] == p:
                        ranges[-1][1] = p + 1
                    else:
                        ranges.append([p, p + 1])
    per_region = collections.Counter[str]()
    for lo, hi in ranges:
        hit = [r for r in regions if lo < r[1] + r[2] and hi > r[1]]
        for r in hit:
            per_region[r[0]] += min(hi, r[1] + r[2]) - max(lo, r[1])
        if not hit:
            per_region['(outside any section/table)'] += hi - lo
    print(f'  {len(ranges)} ranges, {sum(h - l for l, h in ranges)} bytes')
    for name, count in per_region.most_common():
        print(f'    {name}: {count} B')
    for lo, hi in ranges[:12]:
        print(f'    {lo:#x}-{hi:#x} ({hi - lo} B)')
    if len(ranges) > 12:
        print(f'    ... {len(ranges) - 12} more; last {ranges[-1][0]:#x}-{ranges[-1][1]:#x}')


def decode(elf: ELFFile, name: str, problems: list[str],
           decode_rows: bool = True) -> tuple[dict[int, FDERecord], dict[int, int]]:
    """FDEs by initial_location, and FDE address -> initial_location. The
    input's own .eh_frame is byte-compared above, so its rows are not decoded."""
    sec = elf.get_section_by_name(name)
    if sec is None:
        print(f'  ({name} absent)')
        return {}, {}
    cfi = CallFrameInfo(io.BytesIO(sec.data()), sec['sh_size'], sec['sh_addr'], STRUCTS, for_eh_frame=True)
    fdes: dict[int, FDERecord] = {}
    at: dict[int, int] = {}
    for e in cfi.get_entries():
        if not isinstance(e, FDE):
            continue
        rows: list[Row] = []
        for row in (e.get_decoded().table if decode_rows else []):
            cfa = row_cfa(row)
            rules: list[Rule] = []
            for reg in sorted(k for k in row if isinstance(k, int)):
                rule = row_rule(row, reg)
                if rule is not None:
                    rules.append((reg, rule.type, tuple(rule.arg) if isinstance(rule.arg, list) else rule.arg))
            rows.append((row_pc(row), (cfa.reg, cfa.offset, tuple(cfa.expr) if cfa.expr else None), tuple(rules)))
        aug = e.cie['augmentation']
        if e['initial_location'] in fdes and name == '.penryn.eh_frame':  # the input's own are its business
            problems.append(f'{name}: duplicate FDE at {e["initial_location"]:#x}')
        fdes[e['initial_location']] = (e['address_range'], aug if isinstance(aug, str) else aug.decode(),
                                       e.cie['return_address_register'], tuple(rows))
        at[sec['sh_addr'] + e.offset] = e['initial_location']
    return fdes, at


def eh_header(elf: ELFFile, fdes_at: dict[int, int], label: str,
              problems: list[str]) -> tuple[tuple[int, ...], list[int]] | None:
    sec = elf.get_section_by_name('.penryn.eh_frame_hdr')
    if sec is None:
        print(f'  {label}: no .penryn.eh_frame_hdr')
        return None
    d, addr = sec.data(), sec['sh_addr']
    ver, ptr_enc, cnt_enc, tab_enc, frame_rel, count = unpack_ints('<BBBBiI', d, 0)
    entries = [(addr + s, addr + f) for s, f in iter_ints('<ii', d[12:12 + 8 * count])]
    if len(d) != 12 + 8 * count:
        problems.append(f'{label}: header size {len(d)} != 12 + 8*{count}')
    starts = [start for start, _ in entries]
    if starts != sorted(starts):
        problems.append(f'{label}: table not sorted')
    unresolved = [(s, f) for s, f in entries if fdes_at.get(f) != s]
    if unresolved:
        problems.append(f'{label}: {len(unresolved)} entries do not resolve to their FDE, first '
                        f'{unresolved[0][0]:#x} -> {unresolved[0][1]:#x}')
    frame = addr + 4 + frame_rel
    print(f'  {label}: at {addr:#x}, version {ver}, enc {ptr_enc:#x}/{cnt_enc:#x}/{tab_enc:#x}, '
          f'eh_frame_ptr {frame:#x}, {count} entries, {len(entries) - len(unresolved)} resolve to their FDE')
    return (ver, ptr_enc, cnt_enc, tab_enc, frame), starts


def unwind(a: ELFFile, b: ELFFile, problems: list[str]) -> None:
    print('== decoded .penryn.eh_frame')
    fa_new, at_a = decode(a, '.penryn.eh_frame', problems)
    fb_new, at_b = decode(b, '.penryn.eh_frame', problems)
    print(f'  A: {len(fa_new)} FDEs, {sum(len(v[3]) for v in fa_new.values())} rows; '
          f'B: {len(fb_new)} FDEs, {sum(len(v[3]) for v in fb_new.values())} rows')
    if fa_new == fb_new:
        print('  DECODED CFI IDENTICAL')
    else:
        bad = [pc for pc in sorted(set(fa_new) | set(fb_new)) if fa_new.get(pc) != fb_new.get(pc)]
        problems.append(f'decoded .penryn.eh_frame differs at {len(bad)} FDEs, first {bad[0]:#x}')
        print(f'  first difference {bad[0]:#x}\n    A {fa_new.get(bad[0])}\n    B {fb_new.get(bad[0])}')
    print('== decoded .penryn.eh_frame_hdr')
    orig_a, orig_at_a = decode(a, '.eh_frame', problems, decode_rows=False)
    orig_b, orig_at_b = decode(b, '.eh_frame', problems, decode_rows=False)
    print(f'  original .eh_frame: A {len(orig_a)} FDEs, B {len(orig_b)} FDEs, '
          f'{"identical" if orig_a == orig_b else "DIFFERENT"}')
    ha = eh_header(a, {**orig_at_a, **at_a}, 'A', problems)
    hb = eh_header(b, {**orig_at_b, **at_b}, 'B', problems)
    if ha is None or hb is None:
        if (ha is None) != (hb is None):
            problems.append('only one output has .penryn.eh_frame_hdr')
        return
    (fixed_a, starts_a), (fixed_b, starts_b) = ha, hb
    print(f'  fixed fields {"identical" if fixed_a == fixed_b else "DIFFERENT"}; '
          f'table start addresses {"identical" if starts_a == starts_b else "DIFFERENT"}')
    if fixed_a != fixed_b or starts_a != starts_b:
        problems.append('eh_frame_hdr fixed fields or start addresses differ')
    if set(starts_a) != set(orig_a) | set(fa_new):
        problems.append('A: table starts are not exactly the FDEs of .eh_frame + .penryn.eh_frame')
    if set(starts_b) != set(orig_b) | set(fb_new):
        problems.append('B: table starts are not exactly the FDEs of .eh_frame + .penryn.eh_frame')


def walk(x: object, y: object, path: str) -> Iterator[Difference]:
    if type(x) is not type(y):
        yield path, (x, y)
    elif is_object(x) and is_object(y):
        for k in sorted(set(x) | set(y)):
            if k not in x or k not in y:
                yield f'{path}.{k}', ('<missing>' if k not in x else x[k], '<missing>' if k not in y else y[k])
            else:
                yield from walk(x[k], y[k], f'{path}.{k}')
    elif is_list(x) and is_list(y):
        if len(x) != len(y):
            yield f'{path}.<len>', (len(x), len(y))
        for i, (p, q) in enumerate(zip(x, y)):
            yield from walk(p, q, f'{path}[{i}]')
    elif x != y:
        yield path, (x, y)


def reports(a_path: Path, b_path: Path) -> None:
    print('== report differences (normalized key paths)')
    ja, jb = a_path.with_name(a_path.name + '.json'), b_path.with_name(b_path.name + '.json')
    if not ja.exists() or not jb.exists():
        print(f'  (no report beside {a_path.name if not ja.exists() else b_path.name})')
        return
    groups = collections.defaultdict[str, list[Difference]](list)
    for path, pair in walk(load_json(ja.read_text()), load_json(jb.read_text()), ''):
        groups[re.sub(r'\[\d+\]', '[*]', path)].append((path, pair))
    for group, items in groups.items():
        path, (x, y) = items[0]
        sx, sy = json.dumps(x)[:90], json.dumps(y)[:90]
        print(f'  {group} ({len(items)}x): e.g. {path}: {sx} -> {sy}')


class Arguments(argparse.Namespace):
    a: Path
    b: Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0] if __doc__ else None)
    parser.add_argument('a', type=Path, help='first patched output (OUTPUT.json beside it)')
    parser.add_argument('b', type=Path, help='second patched output')
    args = parser.parse_args(argv, namespace=Arguments())
    problems: list[str] = []
    with args.a.open('rb') as fa, args.b.open('rb') as fb:
        a, b = ELFFile(fa), ELFFile(fb)
        with mmap.mmap(fa.fileno(), 0, access=mmap.ACCESS_READ) as ma, \
                mmap.mmap(fb.fileno(), 0, access=mmap.ACCESS_READ) as mb:
            print(f'== sizes: {len(ma)} vs {len(mb)} ({len(mb) - len(ma):+d})')
            headers(a, b)
            sections(a, b, ma, mb)
            byte_ranges(b, ma, mb)
        unwind(a, b, problems)
    reports(args.a, args.b)
    print('== problems')
    for p in problems:
        print('  ' + p)
    print('  NONE' if not problems else f'  {len(problems)} PROBLEM(S)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
