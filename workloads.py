#!/usr/bin/env python3
"""Deterministic, credential-free startup/search/file-walk profile workloads.

  python workloads.py --agy ./agy --claude ./claude --work /tmp/penryn-workloads
  python workloads.py --claude ./claude --mode native --perf /path/to/perf --work /tmp/penryn-native

Reports default to BINARY.json. Every application receives a fresh HOME and
an allowlisted environment. Search expected output is computed while writing
the fixture, independently of ripgrep. No authenticated agent prompt is run.
Profiles rank measured sites; never treat an unobserved site as unreachable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource

import profile as profiler


def fixture(directory, *, files=64, lines=512):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True)
    expected, hashes = {}, {}
    matches = []
    for f in range(files):
        relative = f'd{f % 8:02d}/f{f:03d}.txt'
        path = directory / relative
        path.parent.mkdir(exist_ok=True)
        content = []
        for n in range(lines):
            index = f * lines + n
            token = 'Penryn' if index % 97 == 0 else 'scalar'
            text = f'{index:08d} {token} café Ελληνικά 中文 🙂 alpha beta gamma {index * index:016x}\n'
            content.append(text)
            if token == 'Penryn':
                matches.append((relative, n + 1, text.rstrip('\n')))
        data = ''.join(content).encode()
        path.write_bytes(data)
        hashes[relative] = hashlib.sha256(data).hexdigest()
    matches.sort(key=lambda m: (m[0], m[1]))
    expected['rg-search'] = ''.join(f'{directory / f}:{n}:{line}\n' for f, n, line in matches).encode()
    expected['rg-utf8'] = ''.join(f'{directory / f}:{lines}\n' for f in sorted(hashes)).encode()
    expected['rg-files'] = ''.join(f'{directory / f}\n' for f in sorted(hashes)).encode()
    return dict(files=files, lines_per_file=lines, total_lines=files * lines,
                bytes=sum((directory / f).stat().st_size for f in hashes),
                files_sha256=hashes, matching_lines=len(matches)), expected


def merge_counts(profiles, model):
    merged = {}
    for report in profiles:
        if report['input_sha256'] != model['input_sha256'] or report['output_sha256'] != model['sha256']:
            raise ValueError('cannot merge profiles of different executable revisions')
        for row in report['site_counts']:
            merged[row['address']] = merged.get(row['address'], 0) + row['executions']
    return dict(mode='qemu-instruction-attempts', input_sha256=model['input_sha256'],
                output_sha256=model['sha256'], binary_sha256=model['sha256'],
                workloads=len(profiles), aggregation='unweighted sum of the recorded workloads',
                site_counts=[dict(address=k, executions=v) for k, v in sorted(merged.items(), key=lambda p: -p[1])])


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--agy', type=Path)
    parser.add_argument('--agy-report', type=Path)
    parser.add_argument('--claude', type=Path)
    parser.add_argument('--claude-report', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--mode', choices=['count', 'native'], default='count')
    parser.add_argument('--qemu', default='qemu-x86_64')
    parser.add_argument('--perf', default='perf')
    parser.add_argument('--files', type=int, default=64)
    parser.add_argument('--lines', type=int, default=512)
    parser.add_argument('--legacy-ranges', action='store_true')
    args = parser.parse_args()
    if not args.agy and not args.claude:
        parser.error('supply at least one application')
    if args.work.exists():
        parser.error('--work must be a new directory')
    if args.files <= 0 or args.lines <= 0:
        parser.error('fixture dimensions must be positive')
    work = args.work.resolve()
    work.mkdir(parents=True)
    corpus = work / 'corpus'
    description, expected = fixture(corpus, files=args.files, lines=args.lines)
    (work / 'fixture.json').write_text(json.dumps(description, indent=2) + '\n')
    results = {}
    for app in ('agy', 'claude'):
        binary = getattr(args, app)
        if not binary:
            continue
        report_path = getattr(args, app + '_report') or Path(str(binary) + '.json')
        model = profiler.load_model(binary, report_path, legacy=args.legacy_ranges)
        jobs = [('version', ['--version'], app), ('help', ['--help'], app)]
        if app == 'claude':
            jobs += [('rg-search', ['-n', '--sort', 'path', r'Penryn.*中文.*alpha', str(corpus)], 'rg'),
                     ('rg-utf8', ['-c', '--sort', 'path', r'\p{Greek}+.*中文.*🙂', str(corpus)], 'rg'),
                     ('rg-files', ['--files', '--sort', 'path', str(corpus)], 'rg')]
        profiles = []
        for name, command, argv0 in jobs:
            target = work / f'{app}-{name}'
            if args.mode == 'count':
                result = profiler.count(model, command, target, argv0=argv0, qemu=args.qemu)
                profiles.append(result)
            else:
                result = profiler.native(model, command, target, argv0=argv0, perf=args.perf)
            stdout = (target / 'stdout').read_bytes() if (target / 'stdout').exists() else b''
            if result.get('status') != 'unavailable':
                if name in expected:
                    if stdout != expected[name]:
                        raise RuntimeError(f'{app} {name} output differs from independently generated expected output')
                elif not stdout.strip() and not (target / 'stderr').read_bytes().strip():
                    raise RuntimeError(f'{app} {name} produced no output')
            results[f'{app}-{name}'] = dict(profile=str(target / 'profile.json'),
                                            status=result.get('status', 'complete'),
                                            output_verified=result.get('status') != 'unavailable',
                                            active_sites=sum(r.get('entries', r.get('samples', 0)) > 0
                                                             for r in result.get('rows', []) if r['kind'] == 'site'))
            print(f'{app}-{name}: {results[f"{app}-{name}"]}', flush=True)
        if profiles:
            (work / f'{app}-combined.json').write_text(json.dumps(merge_counts(profiles, model), indent=2) + '\n')
    (work / 'results.json').write_text(json.dumps(dict(fixture=description, results=results), indent=2) + '\n')


if __name__ == '__main__':
    main()
