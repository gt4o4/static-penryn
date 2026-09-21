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
RBP-based stack alignment are represented. String arithmetic helpers reuse
the CFI emitted by **GCC**, including compiler-authored branch-specific rows.

The added GNU EH header indexes both untouched original FDEs and new FDEs.
The loader finds it through `PT_GNU_EH_FRAME`. Original `.eh_frame` data
remains in place. Unsupported rules, original signal-frame CIEs, unknown
original frames and untracked stack transformations become explicit coverage gaps rather than guessed
unwind rules. The new metadata describes backtraces; original C++ landing
pads are not remapped to replacement PCs; compiler helpers with
LSDA/personality metadata are refused.

## Go is a separate runtime contract

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

The final profiled artifacts generated on 2026-09-21 have this native
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

The patcher does **not** extend Go `moduledata`, pc-value tables, stack maps,
safe points, stack-growth checks or the runtime's function lookup tables.
DWARF CFI cannot substitute for these structures. Extra scratch stack must
still be mapped, and fault handlers still observe the replacement PC and
temporary register/stack state. `runtime.production_ready` remains false.

## Reproduce the runtime tests

With the patcher's Python dependencies, GCC/binutils, Go and QEMU on PATH:

```sh
go build -o /tmp/penryn-go-metadata ./hosts/iMacGBC/static-penryn/go_metadata.go
PENRYN_GOMETA=/tmp/penryn-go-metadata \
  python hosts/iMacGBC/static-penryn/test_runtime.py
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

All twelve runtime regression cases passed on 2026-09-21: the nine-test
suite followed by the added fused-region case and two focused signal-frame
and helper-LSDA refusal tests. The final signal runs observed
94 scalar, 123 string and 94 fused-region samples inside appended code;
every such sample recovered the expected caller frame. Native backtrace
success does not imply preservation of the interrupted machine context.

The bounded Go fixture is separately available for exploratory stress:

```sh
GO111MODULE=off GOAMD64=v1 go build -o /tmp/go-runtime-original \
  ./hosts/iMacGBC/static-penryn/runtime-fixtures/go
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
