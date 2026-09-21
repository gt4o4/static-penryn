#!/usr/bin/env python3
"""Paired warm native application timings, with output and identity checks.

  python bench_apps.py --agy-before /tmp/agy-old --agy-after /tmp/agy-new \
    --claude-before /tmp/claude-old --claude-after /tmp/claude-new \
    --work /tmp/penryn-app-benchmark

Each executable must have its adjacent .json patch report. Variants must
share the same original input SHA-256. No kernel/emulator settings change.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import statistics
import subprocess
import time

import profile as profiler
import workloads


def cpu_snapshot():
    values = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
    return sum(values), values[3] + values[4]


def busy_fraction(seconds=1):
    total0, idle0 = cpu_snapshot()
    time.sleep(seconds)
    total1, idle1 = cpu_snapshot()
    return 1 - (idle1 - idle0) / max(1, total1 - total0)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for app in ('agy', 'claude'):
        for variant in ('before', 'after'):
            parser.add_argument(f'--{app}-{variant}', type=Path)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=21)
    parser.add_argument('--files', type=int, default=64)
    parser.add_argument('--lines', type=int, default=8192)
    parser.add_argument('--max-background-busy', type=float, default=.15,
                        help='refuse timing if this fraction of total CPU is busy before the run')
    args = parser.parse_args()
    if args.work.exists():
        parser.error('--work must be a new directory')
    if args.runs < 3 or args.files < 1 or args.lines < 1 or not 0 <= args.max_background_busy <= 1:
        parser.error('invalid sample count, fixture dimensions or CPU threshold')
    pairs = {}
    for app in ('agy', 'claude'):
        paths = {v: getattr(args, app + '_' + v) for v in ('before', 'after')}
        if not any(paths.values()):
            continue
        if not all(paths.values()):
            parser.error(f'{app} needs both before and after')
        models = {v: profiler.load_model(path, str(path) + '.json', legacy=True) for v, path in paths.items()}
        if len({m['input_sha256'] for m in models.values()}) != 1:
            parser.error(f'{app} variants came from different original payloads')
        pairs[app] = models
    if not pairs:
        parser.error('supply at least one application pair')
    work = args.work.resolve()
    work.mkdir(parents=True)
    corpus, expected = workloads.fixture(work / 'corpus', files=args.files, lines=args.lines)
    busy = busy_fraction()
    if busy > args.max_background_busy:
        raise RuntimeError(f'background CPU busy {busy:.1%} exceeds {args.max_background_busy:.1%}; choose another new work directory and retry when quiet')
    processes = subprocess.run(['ps', '-eo', 'pid,pcpu,comm', '--sort=-pcpu'], capture_output=True, text=True, check=True).stdout.splitlines()[:12]
    results = {}
    for app, models in pairs.items():
        jobs = [('version', ['--version'], app), ('help', ['--help'], app)]
        if app == 'claude':
            jobs += [('rg-search', ['-n', '--sort', 'path', 'Penryn.*中文.*alpha', str(work / 'corpus')], 'rg')]
        for name, argv, argv0 in jobs:
            envs = {v: profiler.environment(work / f'{app}-{name}-{v}-home') for v in models}
            captured = {}
            for variant, model in models.items():
                for _ in range(2):
                    result = subprocess.run([argv0, *argv], executable=model['binary'], env=envs[variant],
                                            cwd=work, capture_output=True, check=True, timeout=120)
                captured[variant] = result.stdout, result.stderr
                if name in expected and result.stdout != expected[name]:
                    raise RuntimeError(f'{app} {name} {variant} search output mismatch')
            if captured['before'] != captured['after']:
                raise RuntimeError(f'{app} {name} before/after output mismatch')
            wall = {v: [] for v in models}
            cpu = {v: [] for v in models}
            for repeat in range(args.runs):
                for variant in (('before', 'after') if repeat % 2 == 0 else ('after', 'before')):
                    usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
                    started = time.perf_counter_ns()
                    subprocess.run([argv0, *argv], executable=models[variant]['binary'], env=envs[variant],
                                   # PIPE makes communicate wait on EOF, avoiding
                                   # wait(timeout)'s exponential sleep quantization
                                   # on short version/search commands.
                                   cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                   check=True, timeout=120)
                    elapsed = time.perf_counter_ns() - started
                    usage1 = resource.getrusage(resource.RUSAGE_CHILDREN)
                    wall[variant].append(elapsed / 1e6)
                    cpu[variant].append(1000 * (usage1.ru_utime + usage1.ru_stime - usage0.ru_utime - usage0.ru_stime))
            label = f'{app}-{name}'
            results[label] = dict(
                wall_ms={v: dict(median=statistics.median(samples), samples=samples) for v, samples in wall.items()},
                cpu_ms={v: dict(median=statistics.median(samples), samples=samples) for v, samples in cpu.items()},
                median_paired_wall_speedup=statistics.median(a / b for a, b in zip(wall['before'], wall['after'])),
                stdout_sha256=hashlib.sha256(captured['before'][0]).hexdigest(),
                stderr_sha256=hashlib.sha256(captured['before'][1]).hexdigest())
            print(label, {v: round(statistics.median(samples), 3) for v, samples in wall.items()}, flush=True)
    # load_model checked every file before the run; bind all samples to the
    # same bytes afterwards without repeatedly hashing 200+MB between pairs.
    for models in pairs.values():
        for model in models.values():
            profiler.verify_identity(model)
    summary = dict(method='Two warmups, paired alternating order; native payload ELF, allowlisted environment, unisolated desktop',
                   runs=args.runs, initial_background_cpu_busy_fraction=busy, initial_process_snapshot=processes,
                   variants={app: {v: dict(path=m['binary'], output_sha256=m['sha256'], input_sha256=m['input_sha256'])
                                   for v, m in models.items()} for app, models in pairs.items()},
                   fixture=corpus, results=results)
    (work / 'benchmark.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
