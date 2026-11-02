#!/usr/bin/env python3
"""Deterministic, credential-free startup/search/file-walk profile workloads.

  python -m static_penryn.workloads --agy ./agy --claude ./claude --work /tmp/penryn-workloads
  python -m static_penryn.workloads --claude ./claude --mode native --perf /path/to/perf --work /tmp/penryn-native

Reports default to BINARY.json. Every application receives a fresh HOME and
an allowlisted environment. Search expected output is computed while writing
the fixture, independently of ripgrep. No authenticated agent prompt is run.
Profiles rank measured sites; never treat an unobserved site as unreachable.
"""
import argparse
from collections.abc import Sequence
import hashlib
import json
from pathlib import Path
import resource
from typing import TypedDict

from . import profile as profiler
from .checked import as_int, as_str


class Fixture(TypedDict):
    files: int
    lines_per_file: int
    total_lines: int
    bytes: int
    files_sha256: dict[str, str]
    matching_lines: int


class Combined(TypedDict):
    mode: str
    input_sha256: object
    output_sha256: str
    binary_sha256: str
    workloads: int
    aggregation: str
    site_counts: list[profiler.SiteCount]


class WorkloadResult(TypedDict):
    profile: str
    status: str
    output_verified: bool
    active_sites: int


class Results(TypedDict):
    fixture: Fixture
    results: dict[str, WorkloadResult]


def fixture(directory: str | Path, *, files: int = 64, lines: int = 512) -> tuple[Fixture, dict[str, bytes]]:
    directory = Path(directory).resolve()
    directory.mkdir(parents=True)
    expected: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    matches: list[tuple[str, int, str]] = []
    for f in range(files):
        relative = f'd{f % 8:02d}/f{f:03d}.txt'
        path = directory / relative
        path.parent.mkdir(exist_ok=True)
        content: list[str] = []
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

    def by_path_line(match: tuple[str, int, str]) -> tuple[str, int]:
        return match[0], match[1]

    matches.sort(key=by_path_line)
    expected['rg-search'] = ''.join(f'{directory / f}:{n}:{line}\n' for f, n, line in matches).encode()
    expected['rg-utf8'] = ''.join(f'{directory / f}:{lines}\n' for f in sorted(hashes)).encode()
    expected['rg-files'] = ''.join(f'{directory / f}\n' for f in sorted(hashes)).encode()
    return Fixture(files=files, lines_per_file=lines, total_lines=files * lines,
                   bytes=sum((directory / f).stat().st_size for f in hashes),
                   files_sha256=hashes, matching_lines=len(matches)), expected


def merge_counts(profiles: Sequence[profiler.CountOutput], model: profiler.Model) -> Combined:
    merged: dict[str, int] = {}
    for report in profiles:
        if report['input_sha256'] != model['input_sha256'] or report['output_sha256'] != model['sha256']:
            raise ValueError('cannot merge profiles of different executable revisions')
        for row in report['site_counts']:
            merged[row['address']] = merged.get(row['address'], 0) + row['executions']

    def by_executions(item: tuple[str, int]) -> int:
        return -item[1]

    return Combined(mode='qemu-instruction-attempts', input_sha256=model['input_sha256'],
                    output_sha256=model['sha256'], binary_sha256=model['sha256'],
                    workloads=len(profiles), aggregation='unweighted sum of the recorded workloads',
                    site_counts=[profiler.SiteCount(address=k, executions=v)
                                 for k, v in sorted(merged.items(), key=by_executions)])


class Options(argparse.Namespace):
    agy: Path | None
    agy_report: Path | None
    claude: Path | None
    claude_report: Path | None
    work: Path
    mode: str
    qemu: str
    perf: str
    files: int
    lines: int


def main() -> None:
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
    args = parser.parse_args(namespace=Options())
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
    results: dict[str, WorkloadResult] = {}
    for app in ('agy', 'claude'):
        binary = args.agy if app == 'agy' else args.claude
        if not binary:
            continue
        report_path = (args.agy_report if app == 'agy' else args.claude_report) or Path(str(binary) + '.json')
        model = profiler.load_model(binary, report_path)
        jobs = [('version', ['--version'], app), ('help', ['--help'], app)]
        if app == 'claude':
            jobs += [('rg-search', ['-n', '--sort', 'path', r'Penryn.*中文.*alpha', str(corpus)], 'rg'),
                     ('rg-utf8', ['-c', '--sort', 'path', r'\p{Greek}+.*中文.*🙂', str(corpus)], 'rg'),
                     ('rg-files', ['--files', '--sort', 'path', str(corpus)], 'rg')]
        profiles: list[profiler.CountOutput] = []
        for name, command, argv0 in jobs:
            target = work / f'{app}-{name}'
            result: profiler.CountOutput | profiler.NativeOutput
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
            # Over the count/native union these .get()s type as object; the values are str and int.
            results[f'{app}-{name}'] = WorkloadResult(
                profile=str(target / 'profile.json'),
                status=as_str(result.get('status', 'complete'), 'profile status'),
                output_verified=result.get('status') != 'unavailable',
                active_sites=sum(as_int(r.get('entries', r.get('samples', 0)), 'profile row count') > 0
                                 for r in result.get('rows', []) if r['kind'] == 'site'))
            print(f'{app}-{name}: {results[f"{app}-{name}"]}', flush=True)
        if profiles:
            (work / f'{app}-combined.json').write_text(json.dumps(merge_counts(profiles, model), indent=2) + '\n')
    (work / 'results.json').write_text(json.dumps(Results(fixture=description, results=results), indent=2) + '\n')


if __name__ == '__main__':
    main()
