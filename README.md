# Static Penryn patcher — experimental

This is an offline ELF64 rewriter for iMacGBC's Core 2 Duo. It replaces
legacy POPCNT, CRC32, PCMPGTQ and PCMPxSTRx instructions with direct jumps
to equivalent scalar/SSE2 code appended to the same executable. The result
needs no kernel opemu, SIGILL handler, preload, decoder, or sidecar library.
The packed-string arithmetic is compiled from the existing validated MIT
core at `gt4o4/opemu-linux` revision
`6641be603e64c14127542865d777907544ab739f`; its two source hashes are checked.
Only arithmetic is reused, not the emulator's runtime machinery.

**An experiment, not enabled in `penryn-overlays.nix`.** Both current
applications pass the no-emulator startup tests below. General indirect
control-flow recovery, fault-context equivalence and asynchronous unwinding
remain unresolved. The host's kernel and installed packages are unchanged.

## Optimization pass, 2026-09-21

The lowerings support operand forms rather than application-specific byte
patterns. This pass improves their execution cost and the rewriter's checks:

- POPCNT uses fixed-work SWAR, with SAHF to synthesize its status flags.
- CRC32C uses eight shared slicing tables (8 KiB) and restores arithmetic
  flags without POPFQ. Unused tables are discarded at link time.
- PCMPGTQ uses flag-free SSE2; comparing a register with itself becomes PXOR.
- A bounded, conservative fall-through analysis skips register saves and
  flag restoration only when old values are proven dead. Reads, partial or
  conditional writes, variable shifts, memory, control flow and privileged
  operations are handled conservatively. `--no-dataflow` preserves all
  non-output state at each replacement boundary for comparison.
- String helpers specialize on mode, immediate and output form, sharing
  equivalent controls. Compiler output must pass leaf, relocation,
  vector-register and static-stack audits before use. They save four XMM
  registers instead of sixteen; the enforced total stack budget is 512 B.
- Relocated tails occupy their exact encoded size, removing executed NOP
  reserves. Code and constants have separate ELF section flags.
- ELF validation rejects ambiguous mappings and executable file aliases;
  loader REL/RELA/RELR write spans protect patch sites and caves. Known
  entries include stripped absolute pointers and MOV/PUSH immediates.
  Far RIP-relative moves that would lose PIE load bias are refused.
  Only padding after real control-flow terminators can become a cave.
- Output and report are published from complete temporary files with
  exclusive creation. Existing paths are never overwritten.

Native instruction microbenchmarks on iMacGBC, median of five runs of one
million iterations, including loop and preservation overhead:

| Replacement | Previous prototype | Improved, preserving state | Speedup |
|---|---:|---:|---:|
| POPCNT64, dense input | 38.77 ns | 4.53 ns | 8.6× |
| CRC32, byte | 40.43 ns | 10.52 ns | 3.8× |
| CRC32, dword | 126.99 ns | 10.25 ns | 12.4× |
| CRC32, qword | 237.90 ns | 11.95 ns | 19.9× |
| PCMPGTQ | 17.74 ns | 4.60 ns | 3.9× |

Proven-dead flags and scratch registers further reduce POPCNT64 to 2.67 ns
and CRC64 to 5.98 ns in the corresponding microbenchmarks. Seven string
cases improve 1.36–1.99× (median seven runs of 300,000 iterations), including
explicit ranges 92.12 → 56.98 ns and implicit equal-each 71.98 → 36.15 ns.
These measure replacement sequences; dormant CPU-dispatch paths and other
application work limit whole-program gains. Faster fixed-work sequences
also increase injected code size, especially CRC32C.

## Application validation

| Input | POPCNT | CRC32 | PCMPGTQ | PCMPESTRI | Code + constants |
|---|---:|---:|---:|---:|---:|
| agy 1.2.7 | 115 | 1,329 | 54 | 2 | 194,416 B |
| Claude Code 2.1.278 | 1,300 | 0 | 423 | 6 | 156,736 B |

There are no PCMPISTRI/M or PCMPESTRM instructions in these particular
binaries; all forms, including REX.W explicit lengths, are implemented and
tested. Scanning the final executable finds zero remaining decoded
instructions in the supported families. This does not prove every possible
execution path has been decoded.

- `qemu-x86_64 -cpu Penryn`, with **no preload**: both patched payloads pass
  `--version` and `--help`. Both original payloads die with SIGILL under the
  same CPU model. QEMU tests the actual ELF, never the exec wrapper.
- Claude reaches its theme-picker TUI in a pseudo-terminal and its embedded
  `rg` searches both an exact text fixture and a 10.88 MB UTF-8 corpus
  correctly (65,536 lines; 833 expected matching lines). Preserve
  `SIMDUTF_FORCE_IMPLEMENTATION=westmere`: the bundled scalar simdutf path
  still hangs independently of instruction lowering.
- agy version/help and its interactive login-method selector also pass
  with `GOGC=1`; this exercises aggressive GC during startup, not a
  sustained authenticated agent session. No login was performed.
- On lix-ory's actual modern CPU: **439,680** scalar/vector comparisons
  across 2,748 forms and four preservation modes; **153,600** packed-string
  arithmetic comparisons; **43,200** further string register/flags/red-zone/
  memory comparisons. All pass. The hardware tests refuse CPUs without
  the real features, avoiding an opemu oracle.
- **34** ELF/rewriting tests and **13** dataflow counterexample tests pass,
  covering PIE/ET_EXEC, stripping, relocation writes, aliases, branches,
  address-size truncation, resumable traps, source preservation and outputs.
- The current app inputs prove flags dead at 739 agy and 833 Claude sites,
  and identify dead GPRs at 445 and 122 sites respectively. Every decision
  is recorded beside the original bytes and generated stub address.

Native warm application timings, median of 15 interleaved runs after one
warmup for each variant/workload on the iMac. The desktop was not isolated.
The original uses the host opemu; both static versions use the rewritten ELF.

| Workload | Original + opemu | First patcher | Improved |
|---|---:|---:|---:|
| agy `--version` | 206.35 ms | 184.48 ms | 179.74 ms |
| agy `--help` | 206.27 ms | 184.48 ms | 178.78 ms |
| Claude `--version` | 12.98 ms | 12.37 ms | 12.15 ms |
| Claude `--help` | 252.52 ms | 249.93 ms | 250.70 ms |
| Claude embedded rg, 14.60 MB count | 10.91 ms | 10.44 ms | 10.55 ms |

agy startup improves about 3% over the first patcher and 13% over the
original in this run. Claude changes little: help and search are slightly
slower than the first patcher in these samples, so no whole-program Claude
speedup is established. The native search checks exactly 1,770 matching
lines in a 200,000-line corpus; all variants also produce identical help
and version output. These are startup/search tests, not authenticated
sessions or a throughput guarantee.

Current artifacts are in `/tmp/static-penryn-opt/`: `agy-final`,
`claude-final`, their JSON patch reports and retained build directories,
`qemu-validation.json`, TUI/help/search logs, `apps-benchmark.json`,
`strings-benchmark.json`, and `sahf-both-bench/report.json` (scalar timings).
The previous prototype and negative controls remain in `/tmp/static-penryn/`.

Input SHA-256 values:

```
agy:    baff3db5e4c09635709fa9838e4038c9b4f2c164ce7a80a18059393797d6802c
claude: b03ee84fce76643c414d868815ad3b74bfa856dda17bc0eb0da39d982213c1f7
```

## Run it

From the repository root, build only the tool (no system toplevel build):

```sh
nix build --impure --expr '
  let f = builtins.getFlake "git+file:///home/wenri/.config/nix-configs";
  in f.nixosConfigurations.iMacGBC.pkgs.callPackage
    ./hosts/iMacGBC/static-penryn { }
' --out-link /tmp/static-penryn-tool --max-jobs 0
```

The Nix package supplies the compiler, binutils, Python dependencies and
pinned arithmetic source. Its build and a packaged-tool PIE fixture containing
POPCNT, CRC32C, PCMPGTQ and PCMPESTRI passed on the Penryn model. It does not
build the kernel/emulator. Alternatively:

```sh
python3 -m venv /tmp/static-penryn-venv
/tmp/static-penryn-venv/bin/pip install -r hosts/iMacGBC/static-penryn/requirements.txt
/tmp/static-penryn-venv/bin/python hosts/iMacGBC/static-penryn/patch.py --help
```

The Python route needs `cc` and `ld` on PATH and the pinned opemu checkout
under `submodules/opemu-linux`; `--core /path/to/core` overrides that location.

Pass the **payload ELF**, not its small launcher. For the measured versions:

```sh
tool=/tmp/static-penryn-tool/bin/static-penryn
agy=/nix/store/dgdfa5jsmp1rf8b9rm69vzi7yykvz8w6-antigravity-cli-1.2.7/libexec/antigravity-cli/agy
claude=/nix/store/hmvhip68hbn4mshzblpji6634gzslh00-claude-code-2.1.278/bin/.claude-wrapped

# Without an output argument, only inventory the binary.
"$tool" "$agy"

# New files only. Existing input/output/report paths cannot be overwritten.
"$tool" "$agy" /tmp/agy-static --allow-relocate
"$tool" "$claude" /tmp/claude-static --allow-relocate

# No global opemu toggle; these test guest instructions under TCG.
ulimit -c 0
env -u LD_PRELOAD AGY_CLI_DISABLE_AUTO_UPDATE=1 \
  qemu-x86_64 -cpu Penryn /tmp/agy-static --version
env -u LD_PRELOAD SIMDUTF_FORCE_IMPLEMENTATION=westmere \
  qemu-x86_64 -cpu Penryn /tmp/claude-static --version
```

The installed agy already has `antigravity-cpuid-gate.py`'s two gate fixes.
A fresh upstream agy needs those applied to a writable copy first. This
patcher does not spoof CPUID or remove startup gates. Disabling auto-update
keeps agy from replacing the rewritten image with an upstream binary.
The examples invoke payloads directly; normal wrappers also carry PATH and
library settings that a packaged deployment must retain.

## How replacement works

A five-byte relative JMP replaces each sufficiently long instruction, with
NOPs filling its remaining bytes. A new read/execute LOAD segment contains
all replacement code. Original LOAD addresses, original sections and the
`.bun` embedded application remain intact. The program-header table moves
into the added mapping; no NOTE or other loader metadata is sacrificed.
The `.penryn` section contains only code; `.penryn.rodata` describes
constants without the executable section flag. Their LOAD mapping is RX.

Four-byte POPCNT cannot hold that JMP. The tool first tries a two-byte JMP
to unused nearby padding after a terminating instruction, then a full JMP
from that padding to the replacement. It reserves caves and rejects any
padding run containing a known entry point.

Without `--allow-relocate`, remaining short sites make the entire patch
fail. The option permits moving one following complete instruction too.
It refuses known incoming branches, symbols, relocation targets,
absolute code pointers, RIP-relative address-taken entries and loader writes,
and never moves CALL/interrupt/exception instructions. iced-x86 relocates
the moved instruction, including branches and RIP-relative addressing.
Some adjacent POPCNT pairs share a stub.
For the measured binaries, agy uses 28 caves and 17 moved tails; Claude
uses 69 caves and 162 moved tails/pairs. Every site and original byte span
is recorded in the JSON report beside the new ELF.

The linker must place code at the exact requested address. This has a
regression test: agy's program-header size left only 16-byte alignment,
while the C helper wanted 32, initially shifting all linked addresses by
16 bytes. The linker script now fixes the section address explicitly and
the patcher verifies it before publishing output.

## Boundaries before production use

- Linear executable-section disassembly and known-entry checks cannot
  recover every indirect branch or distinguish arbitrary embedded data.
  `--allow-relocate` acknowledges this limitation; default mode refuses
  missing caves. Relative jump tables and packed pointers remain examples
  of unrecovered entries. Sectionless ELF files are refused. RX bytes
  outside executable sections are reported rather than decoded as code;
  agy's large RX metadata area is one such range. A new binary version
  needs renewed runtime validation.
- The patcher does not touch JIT code, shared libraries, VEX/AVX, AES-NI,
  PCLMULQDQ or BMI. Honest CPU dispatch keeps unused ISA paths dormant in
  these tested programs. Do not combine this experiment with CPUID spoofing.
- Scalar/vector stubs use at most 176 bytes below original RSP, including
  the untouched 128-byte SysV red zone. Stack pages must exist, and an
  operand must not alias the new scratch area below that red zone.
  RSP/ESP/SP destinations and EIP-relative addressing are explicitly refused.
- String helpers have an audited 512-byte stack budget, including the
  protected red zone; the full hardware harness observed a maximum of
  431 bytes. This is not a Go stack-growth check. agy's two string sites
  are behind its feature dispatcher on honest Penryn; do not assume they
  are safe on a tiny Go stack merely because startup works.
- No DWARF/Go unwind or safepoint metadata is generated for appended code.
  Go refuses unknown PCs as async safe points, but faults/profilers/signals
  can observe a temporary stack/register state. Exact original fault PC
  and signal-context semantics are not preserved. Sustained real workloads
  and runtime metadata support remain prerequisites for replacing the
  installed packages or retiring opemu.

## Regression commands

```sh
python=/tmp/static-penryn-venv/bin/python
"$python" hosts/iMacGBC/static-penryn/test_dataflow.py
"$python" hosts/iMacGBC/static-penryn/test_patch.py
"$python" hosts/iMacGBC/static-penryn/test_lower.py --remote lix-ory
"$python" hosts/iMacGBC/static-penryn/test_strings.py --remote lix-ory
```

In preservation mode, the differential harnesses compare all GPRs, XMM
registers, architectural status flags, DF and red zone against hardware.
Dataflow modes exclude the declared-dead GPRs and status flags from the
comparison. The string test also checks all 256 control bytes, 32/64-bit
signed length boundaries and unaligned memory. They use temporary test
artifacts; no app credentials or kernel settings are changed.

To compare generated code on Penryn without executing unsupported hardware
instructions:

```sh
"$python" hosts/iMacGBC/static-penryn/bench_lower.py \
  --baseline /path/to/previous/lower.py --output /tmp/leaf.json
"$python" hosts/iMacGBC/static-penryn/bench_strings.py \
  --baseline /path/to/previous/string-sources --json /tmp/strings.json
```

Preserve the previous `strings.py` and `strings.c` together for the latter.
Benchmark scripts never change opemu.

References: [iced relocation API](https://github.com/icedland/iced/blob/master/src/rust/iced-x86-py/README.md),
[Go async safe-point checks](https://go.dev/src/runtime/preempt.go).
