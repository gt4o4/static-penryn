# Runtime metadata and validation

`--unwind` adds native backtrace information for supported generated ranges.
`--require-unwind` additionally refuses incomplete native coverage and Go
patch sites whose runtime metadata cannot be relocated. Neither option
certifies arbitrary asynchronous signal handlers or exception propagation.

`unwind.py` asks **pyelftools** for the original `.eh_frame` row at each
original instruction. It follows stack adjustments and saved register
locations in the emitted instructions, then asks **GNU as and ld** to emit
the corresponding CFI. A jump-entered stub inherits the original function's
caller frame; it is not described as an independently called function.
Register saves below the red zone and the string trampoline's temporary
R12-based stack alignment are represented. String arithmetic helpers reuse
the CFI emitted by **GCC**, including compiler-authored branch-specific rows.

The added GNU EH header indexes both untouched original FDEs and new FDEs.
The loader finds it through `PT_GNU_EH_FRAME`. Original `.eh_frame` data
remains in place. Unsupported rules, original signal-frame CIEs, unknown
original frames and untracked stack transformations become explicit coverage gaps rather than guessed
unwind rules. The new metadata describes backtraces; original C++ landing
pads are not remapped to replacement PCs; compiler helpers with
LSDA/personality metadata are refused.

## Original coverage baseline

`go_metadata.go` uses the standard library's **debug/elf, debug/gosym and
debug/buildinfo**. It validates Go 1.20+ pclntab candidates and recovers
function names and bounds even from stripped C-archive links. Such links
can leave `pcHeader.textStart` zero: six matching table pointers plus
`moduledata.minpc`, `maxpc` and `text` must agree before accepting a text
base. The helper resolves ELF RELATIVE relocations and raw ET_EXEC pointers.
Earlier table layouts and unresolved candidates remain explicit audit gaps.

For agy 1.2.7, its runtime text starts at **0x67fe080**, 128 bytes after
the ELF `.text` section begins. The standard-library parser recovers
**157,480 Go functions**. Exactly **52** patched instructions are inside
these functions: 34 POPCNT, 16 CRC32 and 2 PCMPESTRI. Its other **1,448**
original patch sites have native `.eh_frame` records. Claude 2.1.278 has
native records for only **6 of 1,725** original patch sites; the rest already
lack usable original native unwind rules. The strict mode therefore refuses
both full applications for different reasons.

The earlier profiled artifacts generated on 2026-09-21 had this native
coverage. Counts include relocated tails and compiler helper functions,
so they differ from the instruction counts above.

| Artifact | Added unwind bytes | New FDEs | Uncovered ranges |
| --- | ---: | ---: | ---: |
| `agy-profiled-final` | 200,116 | 1,462 | 56 |
| `claude-regions-final` | 26,280 | 11 | 1,873 |

agy's gaps comprise 54 ranges without original native FDEs (the Go sites
and borrowed tails), plus two POPCNT-to-EBX replacements where the inherited
caller RBX value cannot be reconstructed during the replacement. Claude's
gaps all lack original FDEs, including both fused regions. The generator
does not guess those frames. A separate native fixture with complete input
CFI verifies unwinding through a fused region with a shared scratch frame.

Those baseline artifacts did **not** extend Go runtime metadata. The new
opt-in backend below handles a restricted stack-neutral contract. Extra scratch
stack in unsupported lowerings still needs mapped space, and fault handlers
observe replacement PCs and temporary state. `runtime.production_ready`
remains false.

## Implemented runtime repair, 2026-09-21

The new options are independent, so each proof and its remaining gaps can be
reviewed in the JSON report:

| Option | Contract |
| --- | --- |
| `--infer-unwind` | Recover missing native frames from trusted entries and bounded whole-function CFG analysis; implies `--unwind` |
| `--go-dispatch` | Retain 18 exact agy Go SSE4.2 sites behind verified CPU-feature guards |
| `--go-inplace` | Replace the exact agy `countbody` with a stack-neutral SSE2 algorithm inside its existing function |
| `--go-runtime` | Register supported stack-neutral Go POPCNT stubs; report every unsupported site |
| `--require-runtime` | Refuse unresolved Go metadata or any unhandled patched Go site |
| `--require-unwind` | Additionally require complete native metadata for emitted lowering/helper/initializer ranges |

Scalar scratch allocation excludes RBP. String trampolines preserve the
frame-pointer chain, use saved R12 for their private aligned stack, and compile
helpers with frame pointers. Timer tests exercise both ordinary RBP-chain walks
and libgcc DWARF unwinding through the helpers.

`native_frames.py` starts from function symbols, decoded direct CALL targets,
and narrowly verified indirect-call dispatch slots. It propagates stack depth,
frame anchors and saved caller registers through every reachable successor.
Predecessor states must agree; stack pivots, ambiguous entries, unknown branches,
corrupted saves and bounded-analysis exhaustion reject the function. A balanced
constant-target tail dispatch can establish another function entry. Reports
separate inferred rules from original FDEs and state the SysV ABI and unknown
alias/indirect-entry assumptions. Unsupported original CFI is never replaced by
an inference. Go functions are excluded from SysV inference.

`--go-dispatch` binds the complete agy SHA, feature initialization, monotone
feature-disable options and guarded call/entry paths. It retains 16 CRC32 and
two PCMPESTRI sites. Every function used by this proof is protected from cave
reuse and rechecked after rewriting. The AVX512 POPCNT remains outside this
proof because an address reference is unresolved. Zero profile counts are
never treated as reachability evidence.

The initial in-place recipe is pinned to the complete agy input SHA and the
original `countbody`, `Count` and `CountString` bytes. Its 203-byte SSE2 body
plus constants fits the original 448-byte function, replaces seven POPCNT sites,
and retains the original zero-stack-delta Go assembly metadata. It introduces
no call or stack use. Short loads are page-safe and masks exclude bytes outside
the input. Profiling counts the new function as a whole; it does not invent a
one-to-one correspondence with removed POPCNTs.

`go_runtime.py` has explicit module-layout profiles for verified Go 1.26 amd64
fixtures and the exact agy development runtime. The latter uses
`go1.28-20260721-RC03` and a different module layout; a pclntab version alone
cannot establish its private compiler ABI. Ordinary Go 1.26 ABIInternal
functions may borrow XMM registers unused throughout the function. agy requires
local liveness proof. Both paths reserve RSP, RBP, R14 and XMM15.

`go_lower.py` reuses the existing SWAR implementation. A proven-dead GPR needs
no save; otherwise it parks one GPR in a proven-dead XMM. Final linked bytes
must contain no stack mutation, calls, memory writes or unverified memory
reads. A separate contiguous Go-only code interval receives new `moduledata`,
`ftab`/`findfunctab`, names, lines and PC tables. Each stub inherits the original
frame's pcsp, stack-map index and FUNCDATA base: a JMP does not create a call
frame. Stubs are assembly-marked and unsafe for asynchronous Go preemption
while scratch pointer values may be hidden. This adds no stack-growth demand.

Metadata resides in a separate writable, non-executable PT_LOAD. A small
position-independent initializer links the module before the Go runtime starts,
using a verified first preinit callback, DT_INIT route or raw ELF entry path.
agy's pinned preinit recipe redirects the first callback's unique RELATIVE
relocation addend, then tail-jumps to that callback; subsequent callbacks retain
their original order. A DT_INIT-only prototype passed startup but never ran
the initializer because agy's legacy libc callback bypassed that tag. Hooking
preinit also avoids running too late for earlier constructors. Generic dynamic
profiles reject preinit arrays and require proof that their libc entry uses the
normal null-init-callback route. The initializer's native CFI is merged with the
other emitted FDEs. Existing Go module chains, unsupported
layouts, special function/defer metadata and unsafe instruction shapes are
rejected. Unreferenced pclntab-like magic is distinguished from a referenced,
unhandled module candidate; that classification does not certify arbitrary
modules constructed later by application code.

Real Go fixtures validate `runtime.FuncForPC`, file/line lookup, original
stack depths 0 and 72, concurrent GC, stack growth and named CPU profiles.
The executable, internal PIE and external PIE/DT_INIT paths each complete
48 GC rounds and 9.6 million forced POPCNT calls without `_ExternalCode`
attribution. This is a tested narrow backend, not complete support for arbitrary
Go instruction expansion, exceptions or all agy sites. Detailed layout and
registration rules are in [GO-RUNTIME.md](GO-RUNTIME.md).

Registering a second module initially made agy's `runtime.typelinksinit`
execute 3,161,814 local guest instructions instead of 11, even though the
synthetic module adds no types. The pinned optimization retargets its existing
nil-next guard to the synthetic module's `next` field. With one original
module and an empty synthetic type domain, this retains the original fast
path. A later normal module append sets that field and restores the unchanged
deduplication path. Only the RIP-relative displacement changes; instruction
addresses, branch destinations and original stack metadata remain intact.
The backend checks the original topology, empty type fields, exact guard and
return bytes, and the tail-registration invariant. This optimization is not
assumed for unknown runtimes.

### Application coverage after repair

The agy build uses `--go-inplace --go-dispatch --go-runtime --unwind` and
its recorded startup profile. The Claude build retains its prior profile and
region options, adding `--infer-unwind`.

| Input | Code + constants | Native unwind bytes | Go metadata bytes | New native FDEs | Uncovered ranges |
| --- | ---: | ---: | ---: | ---: | ---: |
| agy 1.2.7 | 187,584 | 200,092 | 2,137 | 1,462 | 23 |
| Claude 2.1.278 | 154,176 | 37,964 | 0 | 254 | 1,630 |

The code column is `added_payload_bytes` for lowerings, arithmetic helpers and
constants. agy additionally has a 245-byte initializer; ELF alignment and
program headers also contribute to the output size.

agy's 52 original Go sites now comprise seven in-place sites, 18 proven
dormant sites, six registered sites and **21 unresolved sites**. Every remaining
Go rejection needs a proven scratch register without using the goroutine stack;
several execute during version/help startup. These remain experimental
lowerings. Its 23 uncovered ranges are those 21 sites plus two native
replacements that cannot reconstruct the caller's RBX.

Claude's additional **243 inferred ranges** include the hot four-POPCNT regex
region. Remaining refusals include unknown CFG edges, indexed stack accesses,
ambiguous interior entries and stack pivots. Inference does not turn missing
input metadata into unconditional proof. Both full applications still fail
`--require-unwind`; agy also fails `--require-runtime`.

Final artifacts are `/tmp/static-penryn-runtime/agy-final-v4` and
`claude-final`, each with an adjacent JSON report. Their SHA-256 values are:

```
agy:    20e93e15bd444f4f2589ded9f78321eb8582cd9a538496c92fdb1f478bea51bd
claude: c8eae7ef9fb28de5ac47f347f59293d16b7bca3793bd3531f5c5db10bdb83fd5
```

The packaged tool was built independently with `--max-jobs 0`; all 19 packaged
source files match the reviewed working tree. The agy artifact was generated
by that CLI on lix-ory and its bytes were verified after copying to iMacGBC.
The older DT_INIT-only and legacy-CALL artifacts are diagnostic history, not
the final runtime-registration result.

All seven deterministic QEMU Penryn workloads pass on the final artifacts.
agy's initializer executes exactly once in both startup profiles; GDB confirms
that the original Go runtime validates its module. Version/help also pass with
`GOGC=1` and byte-identical output. Native comparisons and workload details are
recorded in [PROFILING.md](PROFILING.md).

## Reproduce the runtime tests

With the patcher's Python dependencies, GCC/binutils, Go and QEMU on PATH:

```sh
go build -o /tmp/penryn-go-metadata ./go_metadata.go
PENRYN_GOMETA=/tmp/penryn-go-metadata \
  python test_runtime.py
PENRYN_GOMETA=/tmp/penryn-go-metadata \
  python test_native_frames.py
python test_go_runtime.py
python test_go_inplace.py
python test_go_lower.py --remote lix-ory
```

The native fixtures compile without frame pointers and sample the running
replacement code with timer signals. The real libgcc unwinder must recover
a known caller frame from scalar replacements, fused regions with shared
scratch frames, and specialized string helpers. A QEMU Penryn fixture verifies the original instruction raises
SIGILL, then checks the patched memory fault retains its fault address and
can unwind through the replacement. Core dumps are disabled for these
negative controls. The tests also cover dynamic stack anchors, unknown
stack writes, missing original FDEs, stripped Go metadata and strict Go
refusal before output publication.

Regression validation covers **181 cases**: a 177-test full run followed by
the expanded 13-test Go metadata suite, which adds the preinit and conditional
type-guard counterexamples.
This includes 13 native runtime cases and the profiler's pre-entry-initializer
regression. The latest signal runs observed 92 scalar, 119 string, 85
fused-region and 78 inferred-frame samples inside appended code, plus 100
direct frame-pointer walks; every sample recovered its expected caller.
Native backtrace
success does not imply preservation of the interrupted machine context.

The bounded Go fixture is separately available for exploratory stress:

```sh
GO111MODULE=off GOAMD64=v1 go build -o /tmp/go-runtime-original \
  ./runtime-fixtures/go
static-penryn /tmp/go-runtime-original /tmp/go-runtime-patched \
  --allow-relocate --no-dataflow
GOGC=1 GOMEMLIMIT=16MiB PENRYN_STRESS_ROUNDS=1200 qemu-x86_64 -cpu Penryn \
  /tmp/go-runtime-patched /tmp/go-runtime.cpu.pprof
go tool pprof -top /tmp/go-runtime-patched /tmp/go-runtime.cpu.pprof
```

By default it performs 480 forced GC rounds in four goroutines, keeps
allocated objects live through collections, executes 24,122,880 forced
POPCNT calls and can enable Go CPU profiling. The command above increases
both counts tenfold. The original hits SIGILL under the Penryn model.
The experimental patched fixture completed both with and without profiling
on 2026-09-21. Successful stress execution is evidence for those workloads;
it does not remove the strict metadata gate.

The longer configured workload also completed **4,800 GC rounds and
241,228,800 forced POPCNT calls**, with CPU profiling enabled, both on the
physical Penryn CPU and under QEMU Penryn (5.23 s and 24.56 s respectively
in those validation runs). These timings include concurrent validation
activity and are not benchmark results.

The native CPU-profile comparison demonstrated a concrete remaining gap:
the original fixture with kernel opemu attributed its hot loop to
`main.forcedPopcnt`; the patched fixture attributed 140 ms of 410 ms sampled
CPU time to `runtime._ExternalCode`. Both completed correctly. Thus the
profiler cannot reliably attribute the appended Go instruction replacements
even when GC and computation pass. These are bounded test observations,
not an application speedup claim.

Implementation references: [GNU assembler CFI directives](https://sourceware.org/binutils/docs/as/CFI-directives.html),
[Go debug/gosym](https://pkg.go.dev/debug/gosym),
[Go asynchronous preemption checks](https://go.dev/src/runtime/preempt.go).
