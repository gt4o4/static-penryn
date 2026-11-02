#!/usr/bin/env python3
"""Count generated instructions under QEMU or attribute native perf samples.

Examples (Python dependencies are the same as patch.py):
  python -m static_penryn.profile count ./agy ./agy.json --work /tmp/agy-profile -- --help
  python -m static_penryn.profile count ./claude ./claude.json --argv0 rg --work /tmp/rg-profile -- -c Penryn corpus.txt
  python -m static_penryn.profile native ./agy ./agy.json --work /tmp/agy-perf -- --help

QEMU counters are execution attempts, not native cycles. Native sampling uses
perf's recorded MMAP records to normalize PIE addresses; static DSO symbol
addresses and a guessed /proc/maps snapshot are never substituted. Both
modes validate the exact executable SHA-256 against its patch report.
"""
import argparse
import bisect
from collections.abc import Sequence
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import sys
import time
from typing import Literal, NotRequired, TypedDict, Unpack

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection

from .checked import as_list, as_object, load_json, member

HERE = Path(__file__).resolve().parent

# A report address or size: a string for int(x, 0), or a JSON number.
type Number = str | int | float
type Kind = Literal['site', 'instruction', 'helper']


class ReportRange(TypedDict):
    start: Number
    end: Number
    original_address: object
    mnemonic: object


class ReportPatch(TypedDict):
    stub: Number
    stub_end: Number
    address: object
    instructions: object
    instruction_ranges: NotRequired[list[ReportRange]]


class ReportHelper(TypedDict):
    start: Number
    end: Number
    name: object


class ReportEvidence(TypedDict):
    code_bytes: Number
    function: object


class ReportInplace(TypedDict):
    address: Number
    evidence: ReportEvidence


class Load(TypedDict):
    """A PT_LOAD program header, field for field."""
    p_type: str | int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int


class Row(TypedDict):
    """One profiled range; report values carried into profiles stay unchecked."""
    kind: Kind
    start: int
    end: int
    offset: int
    original_address: NotRequired[object]  # site, instruction
    instructions: NotRequired[object]  # site
    mnemonic: NotRequired[object]  # instruction
    name: NotRequired[object]  # helper
    inplace: NotRequired[bool]  # helper replacing a whole function


class RowExtra(TypedDict, total=False):
    """A row's fields after offset, in each caller's order."""
    original_address: object
    instructions: object
    mnemonic: object
    name: object
    inplace: bool


class CountedRow(Row):
    entries: int
    generated_instructions: int


class SampledRow(Row):
    samples: int


class SiteCount(TypedDict):
    address: str
    executions: int


class Layout(TypedDict):
    """What mmap_bias reads."""
    loads: list[Load]


class Ranges(TypedDict):
    """What lookup reads."""
    rows: list[Row]


class PerfModel(Layout, Ranges):
    """What parse_perf reads."""
    binary: str


class Model(PerfModel):
    sha256: str
    input_sha256: object  # the report's value, carried into profiles unchecked
    build_ids: list[str]
    entry: int
    entry_offset: int
    code_start: int


class CountOutput(TypedDict):
    mode: str
    executable: str
    output_sha256: str
    binary_sha256: str
    input_sha256: object
    build_ids: list[str]
    load_bias: str
    command: list[str]
    elapsed_seconds: float
    stdout_sha256: str
    rows: list[CountedRow]
    site_counts: list[SiteCount]


class PerfResult(TypedDict):
    total_samples: int
    executable_outside_patch_samples: int
    other_mapping_samples: int
    rows: list[SampledRow]
    note: str


class NativeOutput(TypedDict):
    mode: str
    executable: str
    output_sha256: str
    input_sha256: object
    binary_sha256: str
    build_ids: list[str]
    frequency_hz: int
    status: Literal['unavailable', 'complete']
    reason: NotRequired[str]
    total_samples: NotRequired[int]
    executable_outside_patch_samples: NotRequired[int]
    other_mapping_samples: NotRequired[int]
    rows: NotRequired[list[SampledRow]]
    note: NotRequired[str]


def _number(value: object, what: str) -> Number:
    if not isinstance(value, (str, int, float)):
        raise ValueError(f'{what} is not a number or numeric string')
    return value


def _number_field(obj: dict[str, object], key: str, what: str) -> Number:
    return _number(member(obj, key, what), f'{what} {key}')


def _range(value: object) -> ReportRange:
    what = 'patch report instruction range'
    obj = as_object(value, what)
    return ReportRange(start=_number_field(obj, 'start', what), end=_number_field(obj, 'end', what),
                       original_address=member(obj, 'original_address', what), mnemonic=member(obj, 'mnemonic', what))


def _patch(value: object) -> ReportPatch:
    what = 'patch report patch'
    obj = as_object(value, what)
    patch = ReportPatch(stub=_number_field(obj, 'stub', what), stub_end=_number_field(obj, 'stub_end', what),
                        address=member(obj, 'address', what), instructions=member(obj, 'instructions', what))
    if 'instruction_ranges' in obj:
        patch['instruction_ranges'] = [_range(r) for r in as_list(obj['instruction_ranges'], f'{what} instruction_ranges')]
    return patch


def _helper(value: object) -> ReportHelper:
    what = 'patch report helper'
    obj = as_object(value, what)
    return ReportHelper(start=_number_field(obj, 'start', what), end=_number_field(obj, 'end', what),
                        name=member(obj, 'name', what))


def _inplace(value: object) -> ReportInplace:
    what = 'patch report in-place patch'
    obj = as_object(value, what)
    address = _number_field(obj, 'address', what)
    evidence = as_object(member(obj, 'evidence', what), f'{what} evidence')
    return ReportInplace(address=address, evidence=ReportEvidence(
        code_bytes=_number_field(evidence, 'code_bytes', f'{what} evidence'),
        function=member(evidence, 'function', f'{what} evidence')))


def number(value: Number) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def verify_identity(model: Model) -> None:
    with open(model['binary'], 'rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != model['sha256']:
        raise ValueError('executable changed during profiling')


def load_model(binary: str | Path, report_path: str | Path) -> Model:
    binary = Path(binary).resolve()
    data = binary.read_bytes()
    report = as_object(load_json(Path(report_path).read_text()), 'patch report')
    digest = hashlib.sha256(data).hexdigest()
    if digest != report.get('output_sha256'):
        raise ValueError('executable SHA-256 does not match patch report')
    elf = ELFFile(io.BytesIO(data))
    if not elf.get_section_by_name('.penryn'):
        raise ValueError('executable has no .penryn section')
    loads = [Load(p_type=s['p_type'], p_flags=s['p_flags'], p_offset=s['p_offset'], p_vaddr=s['p_vaddr'],
                  p_paddr=s['p_paddr'], p_filesz=s['p_filesz'], p_memsz=s['p_memsz'], p_align=s['p_align'])
             for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    what = 'patch report patch'

    def stub(value: object) -> int:
        return number(_number_field(as_object(value, what), 'stub', what))

    patches = sorted(as_list(member(report, 'patches', 'patch report'), 'patch report patches'), key=stub)
    rows: list[Row] = []

    def add(kind: Kind, start: Number, end: Number, **extra: Unpack[RowExtra]) -> None:
        start, end = number(start), number(end)
        if start >= end:
            raise ValueError('empty/reversed profiling range')
        mappings = [s for s in loads if s['p_flags'] & 1 and s['p_vaddr'] <= start
                    and end <= s['p_vaddr'] + s['p_filesz']]
        if len(mappings) != 1:
            raise ValueError('profiling range must have one executable file mapping')
        mapping = mappings[0]
        rows.append(Row(kind=kind, start=start, end=end,
                        offset=mapping['p_offset'] + start - mapping['p_vaddr'], **extra))

    for value in patches:
        patch = _patch(value)
        add('site', patch['stub'], patch['stub_end'], original_address=patch['address'],
            instructions=patch['instructions'])
        for ins in patch.get('instruction_ranges', []):
            add('instruction', ins['start'], ins['end'], original_address=ins['original_address'],
                mnemonic=ins['mnemonic'])
    for helper in map(_helper, as_list(report.get('helpers', []), 'patch report helpers')):
        add('helper', helper['start'], helper['end'], name=helper['name'])
    for item in map(_inplace, as_list(report.get('inplace_patches', []), 'patch report inplace_patches')):
        # A whole-function algorithm replacement has no one-to-one mapping
        # to its former POPCNT instructions. Count its real code as a helper.
        start = number(item['address'])
        evidence = item['evidence']
        add('helper', start, start + number(evidence['code_bytes']),
            name=evidence['function'], inplace=True)

    def by_start(row: Row) -> int:
        return row['start']

    for kind in ('site', 'instruction', 'helper'):
        group = sorted((r for r in rows if r['kind'] == kind), key=by_start)
        if any(a['end'] > b['start'] for a, b in zip(group, group[1:])):
            raise ValueError(f'overlapping {kind} ranges')
    build_ids: list[str] = []
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_NOTE' and isinstance(section, NoteSection):
            build_ids.extend(note['n_desc'].hex() if isinstance(note['n_desc'], bytes) else note['n_desc']
                             for note in section.iter_notes() if note['n_type'] == 'NT_GNU_BUILD_ID')
    entry_segment = next(s for s in loads if s['p_vaddr'] <= elf['e_entry'] < s['p_vaddr'] + s['p_filesz'])
    return Model(binary=str(binary), sha256=digest, input_sha256=member(report, 'input_sha256', 'patch report'),
                 build_ids=build_ids, entry=elf['e_entry'],
                 entry_offset=elf['e_entry'] - entry_segment['p_vaddr'] + entry_segment['p_offset'],
                 code_start=min(s['p_vaddr'] for s in loads if s['p_flags'] & 1), loads=loads, rows=rows)


def environment(home: str | Path) -> dict[str, str]:
    # Allowlist, rather than inheriting API keys or application configuration.
    home = Path(home).resolve()
    home.mkdir(parents=True, exist_ok=True)
    return dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), HOME=str(home),
                XDG_CONFIG_HOME=str(home / '.config'), XDG_CACHE_HOME=str(home / '.cache'),
                XDG_DATA_HOME=str(home / '.local/share'), LANG='C.UTF-8', TERM='dumb',
                AGY_CLI_DISABLE_AUTO_UPDATE='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',
                SIMDUTF_FORCE_IMPLEMENTATION='westmere')


def build_plugin(work: str | Path) -> Path:
    output = Path(work) / 'penryn-profile.so'
    # The unmodified QEMU 10.2.4 header uses GLib declarations. Nix wrappers
    # can provide exact include flags; elsewhere use GLib's pkg-config data.
    flags = os.environ.get('PENRYN_GLIB_CFLAGS')
    if flags is None:
        result = subprocess.run(['pkg-config', '--cflags', 'glib-2.0'], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('GLib development headers required (pkg-config glib-2.0 or PENRYN_GLIB_CFLAGS)')
        flags = result.stdout
    subprocess.run(['cc', '-std=c11', '-O2', '-march=core2', '-fPIC', '-shared', '-pthread',
                    '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror',
                    *shlex.split(flags), '-o', str(output), str(HERE / 'profile_plugin.c')], check=True, capture_output=True)
    return output


def original_counts(rows: Sequence[CountedRow]) -> list[SiteCount]:
    """Per original instruction, its own entry count, so fusing sites keeps
    every instruction's weight. Relocated glue appears too; layout consumers
    select the supported instruction families from the original input.
    """
    counts: dict[int, int] = {}
    for row in rows:
        if row['kind'] != 'instruction':
            continue
        address = number(_number(row['original_address'], 'profiling row original_address'))
        if address in counts:
            raise ValueError('duplicate original instruction address in profiling ranges')
        counts[address] = row['entries']
    return [SiteCount(address=hex(address), executions=entries) for address, entries in sorted(counts.items())]


def count(model: Model, args: list[str], work: str | Path, *, argv0: str | None = None,
          qemu: str = 'qemu-x86_64', timeout: float = 120) -> CountOutput:
    verify_identity(model)
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    plugin = build_plugin(work)
    manifest, counters = work / 'ranges.txt', work / 'counts.txt'
    kind_index = {'site': 0, 'instruction': 1, 'helper': 2}

    def manifest_order(pair: tuple[int, Row]) -> tuple[int, int]:
        return kind_index[pair[1]['kind']], pair[1]['start']

    ordered = sorted(enumerate(model['rows']), key=manifest_order)
    manifest.write_text(f"PENRYN1 {model['entry']:x} {model['entry_offset']:x} {model['code_start']:x} {len(ordered)}\n" + ''.join(
        f"{i} {kind_index[r['kind']]} {r['start']:x} {r['end']:x} {r['offset']:x}\n" for i, r in ordered))
    paths = [plugin, manifest, Path(model['binary']), counters]
    if any(',' in str(p) for p in paths):
        raise ValueError('QEMU plugin arguments cannot contain commas')
    plugin_option = f'{plugin},manifest={manifest},binary={model["binary"]},output={counters}'
    command = [qemu, '-cpu', 'Penryn', '-plugin', plugin_option,
               '-U', 'LD_PRELOAD', '-U', 'LD_LIBRARY_PATH']
    if argv0:
        command += ['-0', argv0]
    command += [model['binary'], *args]
    started = time.monotonic()
    result = subprocess.run(command, env=environment(work / 'home'), cwd=work,
                            capture_output=True, timeout=timeout)
    verify_identity(model)
    (work / 'stdout').write_bytes(result.stdout)
    (work / 'stderr').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'QEMU workload exited {result.returncode}: {result.stderr[-3000:].decode(errors="replace")}')
    if not counters.exists():
        raise RuntimeError('QEMU did not write counters (plugin unavailable or abnormal exit)')
    lines = counters.read_text().splitlines()
    version, bias, invalid = lines[0].split()
    if version != 'PENRYN1' or invalid != '0':
        raise RuntimeError('runtime instruction bytes or load-bias validation failed')
    rows: list[CountedRow] = [{**r, 'entries': 0, 'generated_instructions': 0} for r in model['rows']]
    seen: set[int] = set()
    for line in lines[1:]:
        index, entries, instructions = map(int, line.split())
        if not 0 <= index < len(rows) or index in seen:
            raise RuntimeError('invalid/duplicate plugin row')
        seen.add(index)
        rows[index].update({'entries': entries, 'generated_instructions': instructions})
    if len(seen) != len(rows):
        raise RuntimeError('incomplete plugin output')

    def by_instructions(row: CountedRow) -> tuple[int, int]:
        return -row['generated_instructions'], row['start']

    output = CountOutput(mode='qemu-instruction-attempts', executable=model['binary'],
                         output_sha256=model['sha256'], binary_sha256=model['sha256'],
                         input_sha256=model['input_sha256'], build_ids=model['build_ids'],
                         load_bias=hex(int(bias, 16)),
                         command=command, elapsed_seconds=time.monotonic() - started,
                         stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                         rows=sorted(rows, key=by_instructions),
                         site_counts=original_counts(rows))
    (work / 'profile.json').write_text(json.dumps(output, indent=2) + '\n')
    return output


def lookup(model: Ranges, address: int) -> Row | None:
    # Native samples belong to one region, with shared helpers kept separate.
    def by_start(row: Row) -> int:
        return row['start']

    for kind in ('helper', 'site'):
        rows = sorted((r for r in model['rows'] if r['kind'] == kind), key=by_start)
        pos = bisect.bisect_right([r['start'] for r in rows], address) - 1
        if pos >= 0 and address < rows[pos]['end']:
            return rows[pos]
    return None


def mmap_bias(model: Layout, start: int, offset: int) -> int:
    candidates = {start - (s['p_vaddr'] + offset - s['p_offset']) for s in model['loads']
                  if s['p_flags'] & 1 and
                  s['p_offset'] // 4096 * 4096 <= offset < s['p_offset'] + s['p_filesz']}
    if len(candidates) != 1:
        raise ValueError('perf MMAP does not identify a unique executable load bias')
    return candidates.pop()


def native(model: Model, args: list[str], work: str | Path, *, argv0: str | None = None, perf: str = 'perf',
           timeout: float = 120, frequency: int = 997) -> NativeOutput:
    verify_identity(model)
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    output = NativeOutput(mode='native-perf-cpu-clock', executable=model['binary'], output_sha256=model['sha256'],
                          input_sha256=model['input_sha256'], binary_sha256=model['sha256'],
                          build_ids=model['build_ids'], frequency_hz=frequency, status='unavailable')
    if not shutil.which(perf):
        output['reason'] = f'{perf} is not available; QEMU counts are not CPU-time attribution'
    else:
        # perf records MMAP2 for the actual execution, including PIE load bias.
        # exec -a preserves embedded-rg argv[0]; shell values are positional args.
        command = [perf, 'record', '-q', '-e', 'cpu-clock:u', '-F', str(frequency),
                   '-o', str(work / 'perf.data'), '--',
                   'bash', '-c', 'exec -a "$1" "$2" "${@:3}"', 'profile',
                   argv0 or model['binary'], model['binary'], *args]
        result = subprocess.run(command, env=environment(work / 'home'), cwd=work,
                                capture_output=True, timeout=timeout)
        verify_identity(model)
        (work / 'stdout').write_bytes(result.stdout)
        (work / 'stderr').write_bytes(result.stderr)
        if result.returncode:
            output['reason'] = result.stderr.decode(errors='replace')[-3000:]
        else:
            scripted = subprocess.run([perf, 'script', '-i', str(work / 'perf.data'),
                                       '--show-mmap-events', '-F', 'pid,tid,time,ip,event'],
                                      capture_output=True, text=True, check=True)
            (work / 'perf.script').write_text(scripted.stdout)
            measured = parse_perf(model, scripted.stdout)
            output.update({'total_samples': measured['total_samples'],
                           'executable_outside_patch_samples': measured['executable_outside_patch_samples'],
                           'other_mapping_samples': measured['other_mapping_samples'],
                           'rows': measured['rows'], 'note': measured['note']})
            output['status'] = 'complete'
    (work / 'profile.json').write_text(json.dumps(output, indent=2) + '\n')
    return output


def parse_perf(model: PerfModel, script: str) -> PerfResult:
    """Read chronological perf script MMAP/MMAP2 and sample records.

    Require the recorded file name to equal the hash-validated executable.
    Each MMAP interval is separate, so unrelated mappings are never charged
    to the patcher. A later overlapping MMAP replaces the older interval.
    """
    maps: dict[int, list[tuple[int, int, int]]] = {}
    counts: dict[tuple[str, int], SampledRow] = {}
    target_pids: set[int] = set()
    total = outside = unmapped = raw_samples = 0
    # Actual perf --show-mmap-events: PERF_RECORD_MMAP2 pid/tid:
    # [0xSTART(0xSIZE) @ 0xOFFSET MAJOR:MINOR INODE GENERATION]: perms PATH
    mmap = re.compile(r'PERF_RECORD_MMAP2?\s+(\d+)/\d+:\s*\[(0x[\da-f]+)\((0x[\da-f]+)\)\s*@\s*((?:0x)?[\da-f]+)[^\]]*\]:\s*(?:[rwxps-]+\s+)?(.+)$', re.I)
    sample = re.compile(r'^\s*(\d+)[ /]+(\d+)\s+([\d.]+):\s+(?:cpu-clock(?::u)?:\s+)?([\da-f]+)(?:\s+cpu-clock(?::u)?:?)?\s*$')
    for line in script.splitlines():
        if 'PERF_RECORD_LOST' in line:
            raise ValueError('perf lost samples; repeat with a larger recording buffer')
        record = mmap.search(line)
        if record:
            # Every group participates in a match: the default only types the tuple.
            pid, start_text, size_text, offset_text, path = record.groups('')
            start, size, offset = int(start_text, 16), int(size_text, 16), int(offset_text, 16)
            intervals = maps.setdefault(int(pid), [])
            replacement: list[tuple[int, int, int]] = []
            for old_start, old_end, old_bias in intervals:
                if old_end <= start or old_start >= start + size:
                    replacement.append((old_start, old_end, old_bias))
                else:
                    if old_start < start:
                        replacement.append((old_start, start, old_bias))
                    if old_end > start + size:
                        replacement.append((start + size, old_end, old_bias))
            intervals[:] = replacement
            if path == model['binary']:
                target_pids.add(int(pid))
                intervals.append((start, start + size, mmap_bias(model, start, offset)))
            continue
        if 'PERF_RECORD_MMAP' in line and model['binary'] in line:
            raise ValueError('unrecognized perf executable MMAP record')
        if 'cpu-clock' not in line:
            continue
        record = sample.match(line)
        if not record:
            raise ValueError(f'unrecognized perf sample format: {line[:200]}')
        pid, _, _, address_text = record.groups('')
        raw_samples += 1
        if int(pid) not in target_pids:
            continue  # perf's exec launcher, before the target ELF was mapped
        address = int(address_text, 16)
        total += 1
        mappings = [m for m in maps.get(int(pid), []) if m[0] <= address < m[1]]
        if len(mappings) != 1:
            unmapped += 1
            continue
        row = lookup(model, address - mappings[0][2])
        if row:
            key = (row['kind'], row['start'])
            counts.setdefault(key, {**row, 'samples': 0})['samples'] += 1
        else:
            outside += 1
    if raw_samples and not target_pids:
        raise ValueError('perf has samples but no matching executable MMAP records')

    def by_samples(row: SampledRow) -> int:
        return -row['samples']

    return PerfResult(total_samples=total, executable_outside_patch_samples=outside,
                      other_mapping_samples=unmapped,
                      rows=sorted(counts.values(), key=by_samples),
                      note='Flat statistical samples, including skid; no instruction-latency claim. Short workloads may yield zero samples.')


class Options(argparse.Namespace):
    mode: str
    binary: Path
    report: Path
    work: Path
    argv0: str | None
    qemu: str
    perf: str
    timeout: float
    frequency: int


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('mode', choices=['count', 'native'])
    parser.add_argument('binary', type=Path)
    parser.add_argument('report', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--argv0')
    parser.add_argument('--qemu', default='qemu-x86_64')
    parser.add_argument('--perf', default='perf')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--frequency', type=int, default=997, help='native sampling frequency in Hz')
    # Split explicitly: argparse REMAINDER otherwise absorbs options after report.
    cli = sys.argv[1:]
    split = cli.index('--') if '--' in cli else len(cli)
    args = parser.parse_args(cli[:split], namespace=Options())
    if args.work.exists():
        parser.error('--work must be a new directory')
    model = load_model(args.binary, args.report)
    if args.frequency <= 0:
        parser.error('--frequency must be positive')
    output: CountOutput | NativeOutput
    if args.mode == 'count':
        output = count(model, cli[split + 1:], args.work, argv0=args.argv0, timeout=args.timeout, qemu=args.qemu)
    else:
        output = native(model, cli[split + 1:], args.work, argv0=args.argv0, timeout=args.timeout,
                        perf=args.perf, frequency=args.frequency)
    summary: dict[str, object] = {k: v for k, v in output.items() if k not in ('rows', 'site_counts')}
    print(json.dumps(summary, indent=2))
    for row in output.get('rows', [])[:15]:
        print(hex(row['start']), row.get('original_address', row.get('name')),
              'entries', row.get('entries'), 'instructions', row.get('generated_instructions'),
              'samples', row.get('samples'), row.get('instructions', row.get('mnemonic', '')))


if __name__ == '__main__':
    main()
