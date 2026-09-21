#!/usr/bin/env python3
"""Count generated instructions under QEMU or attribute native perf samples.

Examples (Python dependencies are the same as patch.py):
  python profile.py count ./agy ./agy.json --work /tmp/agy-profile -- --help
  python profile.py count ./claude ./claude.json --argv0 rg --work /tmp/rg-profile -- -c Penryn corpus.txt
  python profile.py native ./agy ./agy.json --work /tmp/agy-perf -- --help

QEMU counters are execution attempts, not native cycles. Native sampling uses
perf's recorded MMAP records to normalize PIE addresses; static DSO symbol
addresses and a guessed /proc/maps snapshot are never substituted. Both
modes validate the exact executable SHA-256 against its patch report.
"""
import argparse
import bisect
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
import time

from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def verify_identity(model):
    with open(model['binary'], 'rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != model['sha256']:
        raise ValueError('executable changed during profiling')


def load_model(binary, report_path, *, legacy=False):
    binary = Path(binary).resolve()
    data = binary.read_bytes()
    report = json.loads(Path(report_path).read_text())
    digest = hashlib.sha256(data).hexdigest()
    if digest != report.get('output_sha256'):
        raise ValueError('executable SHA-256 does not match patch report')
    elf = ELFFile(io.BytesIO(data))
    code = elf.get_section_by_name('.penryn')
    if not code:
        raise ValueError('executable has no .penryn section')
    loads = [dict(s.header) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    patches = sorted(report['patches'], key=lambda p: number(p['stub']))
    rows = []

    def add(kind, start, end, **extra):
        start, end = number(start), number(end)
        if start >= end:
            raise ValueError('empty/reversed profiling range')
        mappings = [s for s in loads if s['p_flags'] & 1 and s['p_vaddr'] <= start
                    and end <= s['p_vaddr'] + s['p_filesz']]
        if len(mappings) != 1:
            raise ValueError('profiling range must have one executable file mapping')
        mapping = mappings[0]
        rows.append(dict(kind=kind, start=start, end=end,
                         offset=mapping['p_offset'] + start - mapping['p_vaddr'], **extra))

    for n, patch in enumerate(patches):
        end = patch.get('stub_end')
        if end is None:
            if not legacy:
                raise ValueError('report lacks exact stub ranges; rebuild it or use --legacy-ranges for advisory counts')
            end = patches[n + 1]['stub'] if n + 1 < len(patches) else code['sh_addr'] + code['sh_size']
        add('site', patch['stub'], end, original_address=patch['address'],
            instructions=patch['instructions'], range_accuracy='inferred' if 'stub_end' not in patch else 'exact')
        for ins in patch.get('instruction_ranges', []):
            add('instruction', ins['start'], ins['end'], original_address=ins['original_address'],
                mnemonic=ins['mnemonic'], range_accuracy='exact')
    for helper in report.get('helpers', []):
        add('helper', helper['start'], helper['end'], name=helper['name'], range_accuracy='exact')
    for kind in ('site', 'instruction', 'helper'):
        group = sorted((r for r in rows if r['kind'] == kind), key=lambda r: r['start'])
        if any(a['end'] > b['start'] for a, b in zip(group, group[1:])):
            raise ValueError(f'overlapping {kind} ranges')
    build_ids = []
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_NOTE':
            build_ids.extend(note['n_desc'].hex() if isinstance(note['n_desc'], bytes) else note['n_desc']
                             for note in section.iter_notes() if note['n_type'] == 'NT_GNU_BUILD_ID')
    entry_segment = next(s for s in loads if s['p_vaddr'] <= elf['e_entry'] < s['p_vaddr'] + s['p_filesz'])
    return dict(binary=str(binary), sha256=digest, input_sha256=report['input_sha256'], build_ids=build_ids,
                entry=elf['e_entry'], entry_offset=elf['e_entry'] - entry_segment['p_vaddr'] + entry_segment['p_offset'],
                code_start=min(s['p_vaddr'] for s in loads if s['p_flags'] & 1), loads=loads, rows=rows,
                range_accuracy='inferred' if any(r['range_accuracy'] == 'inferred' for r in rows) else 'exact')


def environment(home):
    # Allowlist, rather than inheriting API keys or application configuration.
    home = Path(home).resolve()
    home.mkdir(parents=True, exist_ok=True)
    return dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), HOME=str(home),
                XDG_CONFIG_HOME=str(home / '.config'), XDG_CACHE_HOME=str(home / '.cache'),
                XDG_DATA_HOME=str(home / '.local/share'), LANG='C.UTF-8', TERM='dumb',
                AGY_CLI_DISABLE_AUTO_UPDATE='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1',
                SIMDUTF_FORCE_IMPLEMENTATION='westmere')


def build_plugin(work):
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


def original_counts(rows):
    """Keep original instruction weights stable after several sites are fused.

    Exact instruction-entry counters take precedence over their containing
    region's entry counter. Old reports only have one entry per region, so
    those are a fallback, never additional executions for the first address.
    Ordinary relocated glue can appear too; layout consumers select addresses
    belonging to supported instruction families from the original input.
    """
    counts = {}
    for row in rows:
        if row['kind'] != 'instruction':
            continue
        address = number(row['original_address'])
        if address in counts:
            raise ValueError('duplicate original instruction address in profiling ranges')
        counts[address] = row['entries']
    for row in rows:
        if row['kind'] == 'site':
            counts.setdefault(number(row['original_address']), row['entries'])
    return [dict(address=hex(address), executions=entries) for address, entries in sorted(counts.items())]


def count(model, args, work, *, argv0=None, qemu='qemu-x86_64', timeout=120):
    verify_identity(model)
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    plugin = build_plugin(work)
    manifest, counters = work / 'ranges.txt', work / 'counts.txt'
    kind_index = {'site': 0, 'instruction': 1, 'helper': 2}
    ordered = sorted(enumerate(model['rows']), key=lambda pair: (kind_index[pair[1]['kind']], pair[1]['start']))
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
    rows = [dict(r, entries=0, generated_instructions=0) for r in model['rows']]
    seen = set()
    for line in lines[1:]:
        index, entries, instructions = map(int, line.split())
        if not 0 <= index < len(rows) or index in seen:
            raise RuntimeError('invalid/duplicate plugin row')
        seen.add(index)
        rows[index].update(entries=entries, generated_instructions=instructions)
    if len(seen) != len(rows):
        raise RuntimeError('incomplete plugin output')
    output = dict(mode='qemu-instruction-attempts', executable=model['binary'],
                  output_sha256=model['sha256'], binary_sha256=model['sha256'],
                  input_sha256=model['input_sha256'], build_ids=model['build_ids'],
                  range_accuracy=model['range_accuracy'], load_bias=hex(int(bias, 16)),
                  command=command, elapsed_seconds=time.monotonic() - started,
                  stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                  rows=sorted(rows, key=lambda r: (-r['generated_instructions'], r['start'])),
                  site_counts=original_counts(rows))
    (work / 'profile.json').write_text(json.dumps(output, indent=2) + '\n')
    return output


def lookup(model, address):
    # Native samples belong to one region, with shared helpers kept separate.
    for kind in ('helper', 'site'):
        rows = sorted((r for r in model['rows'] if r['kind'] == kind), key=lambda r: r['start'])
        pos = bisect.bisect_right([r['start'] for r in rows], address) - 1
        if pos >= 0 and address < rows[pos]['end']:
            return rows[pos]
    return None


def mmap_bias(model, start, offset):
    candidates = {start - (s['p_vaddr'] + offset - s['p_offset']) for s in model['loads']
                  if s.get('p_flags', 1) & 1 and
                  s['p_offset'] // 4096 * 4096 <= offset < s['p_offset'] + s['p_filesz']}
    if len(candidates) != 1:
        raise ValueError('perf MMAP does not identify a unique executable load bias')
    return candidates.pop()


def native(model, args, work, *, argv0=None, perf='perf', timeout=120, frequency=997):
    verify_identity(model)
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    output = dict(mode='native-perf-cpu-clock', executable=model['binary'], output_sha256=model['sha256'],
                  input_sha256=model['input_sha256'], binary_sha256=model['sha256'],
                  build_ids=model['build_ids'], frequency_hz=frequency, status='unavailable',
                  range_accuracy=model['range_accuracy'])
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
            output.update(parse_perf(model, scripted.stdout))
            output['status'] = 'complete'
    (work / 'profile.json').write_text(json.dumps(output, indent=2) + '\n')
    return output


def parse_perf(model, script):
    """Read chronological perf script MMAP/MMAP2 and sample records.

    Require the recorded file name to equal the hash-validated executable.
    Each MMAP interval is separate, so unrelated mappings are never charged
    to the patcher. A later overlapping MMAP replaces the older interval.
    """
    maps, counts, target_pids = {}, {}, set()
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
            pid, start, size, offset, path = record.groups()
            start, size, offset = map(lambda x: int(x, 16), (start, size, offset))
            intervals = maps.setdefault(int(pid), [])
            replacement = []
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
        pid, _, _, address = record.groups()
        raw_samples += 1
        if int(pid) not in target_pids:
            continue  # perf's exec launcher, before the target ELF was mapped
        address = int(address, 16)
        total += 1
        mappings = [m for m in maps.get(int(pid), []) if m[0] <= address < m[1]]
        if len(mappings) != 1:
            unmapped += 1
            continue
        row = lookup(model, address - mappings[0][2])
        if row:
            key = (row['kind'], row['start'])
            counts.setdefault(key, dict(row, samples=0))['samples'] += 1
        else:
            outside += 1
    if raw_samples and not target_pids:
        raise ValueError('perf has samples but no matching executable MMAP records')
    return dict(total_samples=total, executable_outside_patch_samples=outside,
                other_mapping_samples=unmapped,
                rows=sorted(counts.values(), key=lambda r: -r['samples']),
                note='Flat statistical samples, including skid; no instruction-latency claim. Short workloads may yield zero samples.')


def main():
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
    parser.add_argument('--legacy-ranges', action='store_true', help='allow inferred old-report ranges (advisory only)')
    # Split explicitly: argparse REMAINDER otherwise absorbs options after report.
    import sys
    cli = sys.argv[1:]
    split = cli.index('--') if '--' in cli else len(cli)
    args = parser.parse_args(cli[:split])
    if args.work.exists():
        parser.error('--work must be a new directory')
    model = load_model(args.binary, args.report, legacy=args.legacy_ranges)
    function = count if args.mode == 'count' else native
    if args.frequency <= 0:
        parser.error('--frequency must be positive')
    backend = {'qemu': args.qemu} if args.mode == 'count' else {'perf': args.perf, 'frequency': args.frequency}
    output = function(model, cli[split + 1:], args.work, argv0=args.argv0, timeout=args.timeout, **backend)
    print(json.dumps({k: v for k, v in output.items() if k not in ('rows', 'site_counts')}, indent=2))
    for row in output.get('rows', [])[:15]:
        print(hex(row['start']), row.get('original_address', row.get('name')),
              'entries', row.get('entries'), 'instructions', row.get('generated_instructions'),
              'samples', row.get('samples'), row.get('instructions', row.get('mnemonic', '')))


if __name__ == '__main__':
    main()
