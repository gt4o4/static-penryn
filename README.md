# static-penryn

An offline ELF64 rewriter for iMacGBC's Core 2 Duo (Penryn: no SSE4.2, no
POPCNT). It replaces POPCNT, CRC32, PCMPGTQ and PCMPxSTRx with jumps to
scalar/SSE2 code appended to the same executable, which then needs no opemu,
SIGILL handler or preload. The string arithmetic is compiled from the MIT
core of `gt4o4/opemu-linux`: `CORE_HASHES` pins its two files, validated at
`6641be6` and unchanged at nix-configs' pin `2a5ee2d3` (checked 2026-11-01).

**Packaged by nix-configs since 2026-11-02** as `pkgs.custom.static-penryn`
(`common/pkgs/static-penryn.nix`, pinned by rev).
- `hosts/iMacGBC/penryn-overlays.nix` rewrites Claude Code and agy with it
  at build time, with the options validated below, and antigravity-hub's
  `language_server` and `webm_encoder` with agy's.
- It checks Claude and agy on a QEMU Penryn model with no emulator, and
  keeps each report under `share/static-penryn/`. The hub's
  `language_server` hashes strings with compiled-in AES-NI, which this tool
  does not rewrite, so its check keeps an emulator.
- iMacGBC has run the rewritten Claude and agy since generation 486, and
  the hub's binaries since 488 (both 2026-11-02).
- Everything else still runs on opemu, so don't retire it, and don't combine
  this with CPUID spoofing.

It has been its own repository since 2026-09-29, checked out gitignored at
nix-configs' `submodules/static-penryn/`.

## Status

- Validated under QEMU Penryn:
  - agy 1.2.7 and Claude Code 2.1.278 (2026-09-21);
  - the latest releases, agy 1.4.12 and Claude Code 2.1.316 (2026-11-02):
    version and help, the seven workloads, and Claude's TUI.

  Neither has run sustained.
- Strict mode refuses both full applications: both fail `--require-unwind`,
  agy also `--require-runtime`.
- agy 1.2.7: 31 of its 52 Go sites are handled (seven in place, 18 left
  behind verified CPU dispatch, six registered with Go metadata); 21 lack a
  proven stack-neutral scratch register, and two native ranges cannot
  reconstruct the caller's RBX.
- Claude Code 2.1.278: 243 ranges have inferred native unwind rows; 1,630
  generated ranges stay uncovered.
- agy 1.4.12 is built with `go1.28-20261025-RC00`, so `--go-inplace`,
  `--go-dispatch` and `--go-runtime` refuse it. Its 52 Go sites run on
  plain native stubs, which is not safe on goroutine stacks.

## Build

From the checkout root, with iMacGBC's x86-64 package set (its plain `pkgs`
is x32 since 2026-10-28) and off-box per the fleet rule:

```sh
nix build --impure --expr '
  let f = builtins.getFlake "git+file:///home/wenri/.config/nix-configs";
  in f.nixosConfigurations.iMacGBC.pkgs.x86_64.callPackage ./. { }
' --out-link /tmp/static-penryn-tool --max-jobs 0
```

The wrapper supplies GCC/binutils, the Python dependencies, QEMU, perf, the
pinned opemu core and `PENRYN_GOMETA`, `PENRYN_LIBTCC` and
`PENRYN_GLIB_CFLAGS`; `static-penryn profile|workloads|bench …` run the
profiling tools.

Without Nix, use a host whose `python3`, `cc` and `ld` are x86-64 (lix-ory,
not iMacGBC). Install the `static-penryn` command with
`pip install git+https://github.com/gt4o4/static-penryn` (Python 3.12+;
`-c requirements.txt` pins the tested versions). It then needs:
- TinyCC's x86-64 `libtcc.so` as `PENRYN_LIBTCC` (AGENTS.md builds the
  package's);
- the Go helper as `PENRYN_GOMETA`, built with `go build -o
  /tmp/penryn-go-metadata` from the package's `go_metadata.go`;
- opemu-linux's `core/` as `PENRYN_CORE` or `--core` (a checkout defaults to
  `../opemu-linux/core`).

## Run

```sh
static-penryn INPUT                          # inventory only
static-penryn INPUT OUTPUT --allow-relocate  # writes OUTPUT and OUTPUT.json
static-penryn INPUT OUTPUT --allow-relocate --regions --region-loads \
  --profile COMBINED.json --infer-unwind
static-penryn AGY OUTPUT --allow-relocate --unwind \
  --go-inplace --go-dispatch --go-runtime    # agy 1.2.7 only
env -u LD_PRELOAD qemu-x86_64 -cpu Penryn OUTPUT --version
```

- OUTPUT and its report must be new; the input is never written. `--help`
  lists the options.
- Pass the payload ELF, not its launcher. Run Claude with
  `SIMDUTF_FORCE_IMPLEMENTATION=westmere` (its scalar simdutf path hangs
  regardless of this tool) and agy with `AGY_CLI_DISABLE_AUTO_UPDATE=1`.
- A fresh upstream agy first needs the CPUID-gate fixes of nix-configs'
  `hosts/iMacGBC/antigravity-cpuid-gate.py`; this tool removes no gate.
- A 4-byte site takes a 2-byte jump to padding after a terminator, or, with
  `--allow-relocate`, the following instruction too. Without that option,
  a short site with no cave fails the run. Code goes into a new RX
  `PT_LOAD` (`.penryn`, `.penryn.rodata`). Original segments and sections
  keep their addresses. The report records every site with its original
  bytes, stub, proofs and gaps.

## Boundaries

- Linear disassembly and known entries cannot recover every indirect entry;
  `--allow-relocate` accepts that risk.
- Scalar/vector stubs use at most 176 B below RSP, including the untouched
  128 B red zone. Fused regions use at most 376 B
  (`shared_frame.maximum_stack_bytes`). String helpers have an audited 512 B
  budget, of which the hardware harness observed at most 431 B. Stack pages
  must exist, and no operand may alias the scratch area. This is not a Go
  stack-growth check.
- Fault PCs, signal contexts and C++ landing pads are not remapped. JIT code
  and shared libraries are not rewritten. AVX, AES-NI, PCLMULQDQ and BMI
  are left as they are: behind the program's own CPU dispatch, or, compiled
  in, to opemu.
- Rewrite last. A later `patchelf` or `strip` that rewrites program headers
  breaks the output: antigravity-hub's autoPatchelf did, and the binary
  died of SIGSEGV.
- Replacing an installed package or retiring opemu needs sustained real
  workloads and complete runtime metadata first.

## Profiling

- `static-penryn profile count|native BINARY REPORT --work NEW -- ARGS`
  needs the executable's SHA-256 to equal the report's `output_sha256`.
  - **QEMU plugin:** counts instruction *attempts* per site, instruction and
    helper. These are not cycles or retirements. The PIE bias comes from
    QEMU's `start_code`, never `entry_code`, and every counted instruction
    is byte-checked.
  - **perf:** attributes samples through the recorded MMAP events.
- `static-penryn workloads` runs seven deterministic, credential-free
  workloads whose expected output is computed independently. Their combined
  counts go to `--profile` on the *original* input. Profiles order and
  select work; a zero count never proves a site unreachable.
- `static-penryn bench` makes paired native timings: alternating order, two
  warmups, and it refuses to start on a busy machine.
- `profile_plugin.c` includes QEMU v10.2.4's unmodified `qemu-plugin.h`
  (API 5, SHA-256 `aebc639d…5d4d`). Both are GPL-2.0-or-later
  (`qemu-plugin.LICENSE`).

## Records

**2026-09-21, applications on QEMU Penryn.** Two outputs passed all seven
workloads:
- agy 1.2.7 with `--allow-relocate --unwind --go-inplace --go-dispatch
  --go-runtime` and its startup profile: `20e93e15…51bd`. It also passed
  with `GOGC=1`.
- Claude Code 2.1.278 with `--allow-relocate --regions --region-loads
  --infer-unwind` and its profile: `c8eae7ef…3fd5`.

Native medians: agy version/help were 1.5–3.2% faster than the previous
static patch, Claude unchanged. Claude's hot regex region went from 104 to
86 guest instructions per iteration.

**2026-11-01, patcher comparison.** `b87e00c` against the pwntools, llvmlite
and typing pass, on the installed versions:
- agy 1.4.12 (input `4f542cf0…0722e`):
  - `--allow-relocate`: identical output, `95db5acd…036e`.
  - `--allow-relocate --unwind`, without the Go metadata helper: GNU as gave
    `ce352cc7…f294`, LLVM gives `f65d219a…c2f3`. The 1,314 new FDEs decode
    identically: LLVM repeats
    the opening CFI rules in each FDE where GNU as shares them in the CIE.
    That was accepted; correct CFI is the criterion.
- Claude Code 2.1.316 (input `0f5efad9…a95a`) with `--allow-relocate
  --regions --region-loads --infer-unwind`: GNU as `8cdfa21c…226d`, LLVM
  `a2ffdb40…a371`. The 337 new FDEs decode identically, and code and
  original sections are unchanged.

**2026-11-02, setjmp/longjmp shim, then cleanup.**
- Both left agy's `--unwind` output and report byte-identical
  (`f65d219a…c2f3`).
- The cleanup removed dead code, legacy-report support and unused stubs.
- Every suite passed, as did all four hardware oracles on lix-ory:
  465,280 lowering, 153,600 + 43,200 string, 31,000 region and 124,800 Go
  comparisons.

**2026-11-02, the latest releases under QEMU Penryn.** The packaged tool
patched both installed payloads; both originals die of SIGILL there.
- **Claude Code 2.1.316** (input `0f5efad9…a95a`) with `--allow-relocate
  --regions --region-loads --infer-unwind`: `a2ffdb40…a371`, the 2026-11-01
  result again.
  - `--version` and `--help` passed, as did its five workloads; the search
    outputs were verified.
  - The TUI drew its welcome screen and theme picker.
  - 3,790 sites, 494 of them fused regions; 337 ranges have unwind rows
    (325 inferred) and 3,743 do not.
- **agy 1.4.12** (input `4f542cf0…0722e`) with `--allow-relocate --unwind`
  and the Go helper: `3f549ea2…f70c`.
  - `--version` and `--help` passed, also with `GOGC=1`, as did its two
    workloads.
  - 1,355 sites; the 52 Go sites have no runtime metadata, and 56 ranges
    lack unwind rows.

**2026-11-02, installed on iMacGBC (generation 486, boot `527a5808`).**
The installed payloads are the two outputs above. On silicon, after the
reboot, opemu's global counters read exactly:
- 0 emulated instructions over an idle minute of a Claude Code session
  running on the rewritten binary. The unrewritten one had kept opemu at
  1,600–2,000 a second.
- 0 per `claude --version` (about 520 before) and 0 per `agy --version`
  (91,000–114,000 before).
- 0 in 30 s of `agy --hub` with the IDE's environment, the Antigravity
  IDE's agent, which served HTTP 200.

The boot's only emulated instructions were two POPCNTs in pyright's
language server, outside this tool's inputs.

**2026-11-02, antigravity-hub 2.28.2 (generation 488, `3a106be`).** Both
binaries were rewritten with `--allow-relocate --unwind` after their gate
patch: `language_server` has 1,414 sites (1,262 CRC32, 117 POPCNT, 33
PCMPGTQ, 2 PCMPESTRI) and `webm_encoder` 38. Exact opemu counts on
silicon, before → after:
- `language_server --stamp`: 85,407 POPCNT, 1,558 CRC32, 310 PCMPGTQ and
  758 AES → 758 AES. `--help` gave the same.
- 30 s of the hub's own invocation: 162,296 POPCNT, 1,558 CRC32, 310
  PCMPGTQ and 758 AES → 758 AES.
- `webm_encoder --help`: 158 POPCNT → 0.

The AES is an AESENC/AESDEC string hash compiled in with `-maes` (1,344
instructions), so on QEMU Penryn without an emulator the rewritten server
still dies of SIGILL. Claude Code's and agy's payloads are unchanged by
`3a106be` (`a2ffdb40…`, `3f549ea2…`).

## Development

[AGENTS.md](AGENTS.md) has the commands, tests, architecture, invariants,
runtime contracts and library decisions.

## License

GPL-2.0-or-later ([LICENSE](LICENSE)), as QEMU's `qemu-plugin.h`, which the
profiler plugin includes, requires. The string helpers compile at run time
from opemu-linux's MIT core, which is not part of this package.
