# Profiling and reproducible workloads

`profile.py` verifies the executable's SHA-256 against the patch report,
then counts actual generated instruction attempts under QEMU Penryn or
attributes native `perf` samples. It never uses a zero count as evidence
that code is unreachable. Reports retain the input/output hashes, exact
original/generated addresses and invocation. ELF build IDs are descriptive:
the patcher retains the input build ID, so the output SHA-256 is authoritative.

The QEMU plugin uses per-vCPU inline scoreboards rather than a callback or
shared atomic increment for every instruction. Site-entry counts and dynamic
generated-instruction counts are separate; instruction ranges and shared
helpers have their own counters. Counts describe attempted executions, not
retirement or cycles. CPU time must come from native measurements.

PIE load bias comes from QEMU's main executable `start_code` and the ELF's
minimum executable LOAD address. `entry_code` can refer to the interpreter
and must not be used for this. The original entry instruction must be seen
with matching file bytes, and every counted instruction is byte-checked.
Wrong bias cannot silently turn into an all-zero profile.

## Dependencies and commands

From the checkout root, use the same Python environment as `patch.py`, plus
`cc`, QEMU user-mode with plugins, and GLib development headers. `profile_plugin.c` includes the
**unmodified QEMU v10.2.4 `qemu-plugin.h`**, API version 5, from
[upstream](https://gitlab.com/qemu-project/qemu/-/blob/v10.2.4/include/qemu/qemu-plugin.h).
The vendored header SHA-256 is
`aebc639d01685893a9d71b9ef3afa7ea67e0be6a8959781c4057bd4974d05d4d`.
The header retains its GPL-2.0-or-later license and copyright notices;
the plugin uses the same license. QEMU rejects incompatible plugin API
versions. GLib include flags come from `pkg-config --cflags glib-2.0`, or
the explicit `PENRYN_GLIB_CFLAGS` environment variable in Nix wrappers.
The corresponding upstream license is retained as `qemu-plugin.LICENSE`.

```sh
python -m static_penryn.profile count /tmp/agy /tmp/agy.json --work /tmp/agy-profile -- --help
python -m static_penryn.profile count /tmp/claude /tmp/claude.json --argv0 rg \
  --work /tmp/rg-profile -- -c Penryn /tmp/corpus.txt
python -m static_penryn.profile native /tmp/agy /tmp/agy.json --perf /path/to/perf \
  --work /tmp/agy-native -- --help
python -m static_penryn.workloads --agy /tmp/agy --claude /tmp/claude \
  --work /tmp/penryn-workloads
python -m tests.test_profile
```

The Nix package supplies these dependencies and exposes the same commands
as `static-penryn profile`, `static-penryn workloads` and
`static-penryn bench`; the wrapper provides the GLib include flags.

Work directories must be new. Application arguments follow `--`. Native
mode uses `perf record -e cpu-clock:u`; recording preserves MMAP events and
includes threads. Parsing uses the executable's actual recorded mappings,
accounts for mappings that partially replace earlier ones, and keeps DSO
samples separate. It excludes the exec launcher's samples before the target
mapping. Missing `perf` or denied events produce an explicit `unavailable`
report, never a fabricated timing result. Short runs may collect too few
samples to rank individual sites reliably; increase the workload or repeat
it. Flat samples include sampling skid and do not measure exact instruction
latency.

`workloads.py` builds a deterministic tree with UTF-8 text, computes hashes
and expected search results while creating it, then runs version/help,
Claude's embedded ripgrep regex search, Unicode-property search and file
walk. Every application gets an empty HOME and an environment allowlist,
including `SIMDUTF_FORCE_IMPLEMENTATION=westmere`; credentials and preloads
are not inherited. These workflows do not send authenticated agent prompts.
The fixture dimensions are adjustable with `--files` and `--lines`.
`--mode native` runs the same workloads through native sampling.

For paired native wall/CPU timings, `bench_apps.py` accepts before/after
executables (each with an adjacent patch report), verifies that both came
from the same input, checks matching outputs, and alternates execution
order over 21 pairs after two warmups. It refuses to start when a one-second
CPU sample is more than 15% busy. The default regex fixture is 64 × 8,192
lines; raw samples and executable hashes are retained in `benchmark.json`.
The desktop remains active, so small differences require cautious reading.

```sh
python -m static_penryn.bench_apps --agy-before /tmp/agy-old --agy-after /tmp/agy-new \
  --claude-before /tmp/claude-old --claude-after /tmp/claude-new \
  --work /tmp/penryn-native-timings

# Equivalent with the Nix package:
static-penryn bench --agy-before /tmp/agy-old --agy-after /tmp/agy-new \
  --claude-before /tmp/claude-old --claude-after /tmp/claude-new \
  --work /tmp/penryn-native-timings
```

Outputs include `fixture.json`, each workload's `profile.json`, stdout and
stderr, and combined per-application `site_counts` suitable for profile-guided
layout. Combined counts are an **unweighted sum** of those particular
workloads. A production workload may have a different hot set.

Older patch reports can be inspected using `--legacy-ranges`. Their missing
stub ends are inferred from the next stub and final code-section end; this
can charge shared helper code to the last site. Those profiles are explicitly
marked advisory. Rebuild the executable/report to obtain exact ranges.

## Initial hot-site selection, 2026-09-21

The first profiles used the committed optimized binaries from `d8610a54`
and old reports with inferred ends. They establish an optimization target;
final comparisons should use freshly generated exact reports.

For agy `--version`, the hottest original POPCNT site was `0x683bb58`
(55,548 entries, 1,388,700 generated instruction attempts), followed by
`0x68117bd` (16,329 entries), `0x683ba90` and `0x683b7c5` (9,149 each).
Native help sampling found only 3 of 157 target samples in replacements,
147 elsewhere in the executable and 7 in other mappings. Startup work
outside the replacements dominates this workload.

Claude's deterministic regex search found a much more concentrated region:

| Original address | Instruction | Entries, 64 × 512 lines |
|---|---|---:|
| `0x3a2dacc` | `popcnt esi,esi` | 43,213 |
| `0x3a2dae1` | `popcnt r8d,r8d` | 43,213 |
| `0x3a2daf4` | `popcnt r9d,r9d` | 43,213 |
| `0x3a2db0c` | `popcnt r8d,esi` | 43,213 |

The pattern is `Penryn.*中文.*alpha`; expected matching lines are generated
independently. With the larger 64 × 8,192-line fixture, native search
collected 31 target samples, 8 inside replacements in this region (including
the subsequent `0x3a2db3c` site). This supports concentrating optimization
here; the small sample count does not establish precise per-site costs.
The Unicode-property search had 234 samples and none in replacements.

Raw initial artifacts are under `/tmp/static-penryn-next/`:
`workloads-initial2/agy-combined.json`,
`claude-workloads-initial/claude-combined.json`, and
`claude-native-large/`. Each profile binds to its exact output SHA-256;
input hashes identify which original binary supplied the sites.

## Measured profile-guided outputs

The new agy and Claude outputs passed all seven QEMU workloads with exact
instruction ranges. The final unwind-metadata outputs retained identical
`.penryn` code bytes; their SHA-bound final smoke profiles also passed agy
version and Claude regex search. Every original instruction in the fused
Claude region still has its own entry count: profiling a grouped binary
does not discard the later instructions' weights or double the first one.

Counting both original hot-region bytes and generated code gives a fair
before/after comparison. The four-POPCNT region at `0x3a2dacc` executes
**104 → 86 guest instructions per iteration**, a **17.3% reduction**.
At 43,213 iterations this is 4,494,152 → 3,716,318 instruction attempts.
Counting only appended code would understate the improvement, because
ordinary glue moved from its original address into the new region.

Native timings on iMacGBC used 21 alternating pairs after two warmups and
verified identical outputs. Background CPU was 5.05% busy at the start;
the desktop was active. Both columns run statically patched payloads.

| Workload | Previous optimized output | Profile-guided output |
|---|---:|---:|
| agy `--version` | 185.15 ms | 178.74 ms |
| agy `--help` | 185.62 ms | 177.08 ms |
| Claude `--version` | 12.44 ms | 12.29 ms |
| Claude `--help` | 251.87 ms | 251.99 ms |
| Claude regex search, 44.56 MB | 60.58 ms | 59.30 ms |

Observed agy startup medians improve 3.5–4.6%, and the regex-search median
improves 2.1%; the median of paired search speedup ratios is 1.016×.
Claude help is effectively unchanged. These gains are smaller than the
hot-region instruction reduction because application work outside that
region remains. GC also changes agy's dynamic startup counts between runs,
so differing totals there are not a pure measure of instruction optimization.

Artifacts under `/tmp/static-penryn-next/`:

- `workloads-exact/`: seven validated exact-range workloads.
- `region-whole-counts.json` and `region-whole-{before,after}/`: original
  code plus generated-code instruction accounting.
- `final-profile-validation.json`, `agy-final-profile/` and
  `claude-final-profile/`: final executable SHA checks and QEMU profiles.
- `native-paired-final2/benchmark.json`: all native wall/CPU samples,
  fixture hashes, executable identities and output checks.

Profile-guided baseline output SHA-256 values:

```
agy:    ebebb78e825527af24199242e32678d79f5ebefe2da52a19db2caf4d647df004
claude: 98a73111068079ebdc04b37b6304acbdc9803e0ec35c15c9ff3cb9d2d40b0036
```


The subsequent runtime revision adds the pinned SSE2 Count replacement,
partial Go metadata registration, and inferred native unwind coverage.
Final native measurements again used 21 alternating pairs after two warmups,
with identical output checks and fresh credential-free homes. Initial
background CPU was 2.53% busy. The same 44.56 MB regex fixture was used.

| Workload | Earlier profile-guided baseline | Current output |
|---|---:|---:|
| agy `--version` | 177.20 ms | 174.57 ms |
| agy `--help` | 180.59 ms | 174.79 ms |
| Claude `--version` | 12.80 ms | 12.95 ms |
| Claude `--help` | 243.53 ms | 244.77 ms |
| Claude regex search, 44.56 MB | 58.18 ms | 58.04 ms |

Agy's observed startup medians improve 1.5–3.2%; medians of paired speedup
ratios are 1.019× for version and 1.025× for help. Claude's differences are
small: version is 0.15 ms slower, help is 0.5% slower, and regex is 0.3%
faster. These measurements do not establish a further Claude speedup.
The active desktop and short processes limit precision.

The registration path was validated in the actual agy payload. GDB observed
its original `runtime.moduledataverify1` consume the synthetic module, with
both registration pointers correctly linked, followed by normal exit.
All seven final QEMU Penryn workloads passed; search, Unicode and file-list
outputs matched the independently generated 8 × 32-line fixture. Additional
agy version/help runs with `GOGC=1` produced byte-identical stdout and stderr
to normal GC, using fresh allowlisted environments and no memory limit.
The initializer executes once, with 37 guest instruction attempts. The
in-place Count function executes 17,841 times in each startup workload.
Its whole-function instruction total cannot be compared directly with the
old profiles' totals for the seven isolated POPCNT lowerings.

The performance check caught an otherwise unnecessary registration cost.
A second, typeless module initially caused `runtime.typelinksinit` to hash
the original module's types: its local instruction count rose from 11 to
3,161,814. A paired diagnostic using identical lowerings and code layout
measured about 8.5–9.6 ms additional startup time when registration ran.
The [upstream type initialization code](https://go.dev/src/runtime/type.go)
explains this extra work. The pinned correction redirects the existing
single-module guard to the synthetic module's `next` pointer. Because the
synthetic module contributes no types, the fast path remains valid while
that pointer is nil; later appended modules retain the original slow path.
Final counters confirm 11 local instructions with the initializer still
active. This removes the observed regression while retaining registration.

These are experimental outputs with the Go and native unwind coverage gaps
reported by the patcher; successful workloads do not close those gaps.

Reproduce the native comparison with the prepared artifacts:

```sh
python -m static_penryn.bench_apps \
  --agy-before /tmp/static-penryn-next/agy-profiled-final \
  --agy-after /tmp/static-penryn-runtime/agy-final-v4 \
  --claude-before /tmp/static-penryn-next/claude-regions-final \
  --claude-after /tmp/static-penryn-runtime/claude-final \
  --work /tmp/penryn-runtime-timings
```

Evidence under `/tmp/static-penryn-runtime/`:

- `native-paired-final-v4/benchmark.json`: all wall/CPU samples, fixture
  hashes, input/output identities, output checks and CPU-load snapshot.
- `workloads-final-v4/`: seven final QEMU profiles and verified outputs.
- `gdb-final-v4/`: original-runtime module verification and normal exit.
- `gogc-final-v4/`: bounded `GOGC=1` commands, allowlisted environments and
  exact output comparisons; `check-gogc.py` reproduces these checks.
- `typeguard-final-v4-profile/`: final initializer and type-init counters.
- `type-init-isolation/` and `native-registration-isolation/`: diagnosis
  using an explicitly unregistered development prototype.

Current output SHA-256 values:

```
agy:    20e93e15bd444f4f2589ded9f78321eb8582cd9a538496c92fdb1f478bea51bd
claude: c8eae7ef9fb28de5ac47f347f59293d16b7bca3793bd3531f5c5db10bdb83fd5
```
