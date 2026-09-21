# Go runtime metadata

`--go-runtime` can register a separate Go text module for selected,
stack-neutral POPCNT replacements. This is opt-in and reports every site it
cannot support. `--require-runtime` refuses a result with unresolved Go sites.
`--go-inplace` is independent: its pinned countbody replacement preserves the
original code range and its existing metadata.

The backend uses Go's standard `debug/elf`, `debug/gosym` and `debug/buildinfo`
packages to recover functions, then checks the original runtime's private
layout and decodes its PC-value tables. Native DWARF unwind metadata does not
substitute for this information.

## Supported replacement contract

A registered stub replaces one register-only, 32- or 64-bit POPCNT. It enters
and exits with direct jumps. It does not call, spill to the stack, write memory,
or change RSP, RBP, R14 (the goroutine register) or XMM15 (Go's zero register).
Constant reads must refer to the emitted, mapped constant pool. Memory-source
POPCNT and instructions borrowed from the following code are excluded.

Scratch registers need separate liveness evidence. A dead GPR can be used
directly. Otherwise, a GPR can temporarily be saved in a proven-dead XMM
register. All replacement PCs have `UnsafePointUnsafe` and `FuncFlagAsm`, so
Go cannot asynchronously stop the goroutine while a pointer is temporarily
hidden. The bounded, call-free replacement uses no additional goroutine stack
space. Unsafe-point marking by itself would not make a stack spill safe.

Each synthetic function inherits the original PC's `pcsp`, stack-map index,
argument size and FUNCDATA pointers. A jump adds no return address: the original
frame remains the frame described by the new metadata. Runtime special
functions, SP-writing functions, unknown argument sizes, defer-return and
open-coded defer metadata are rejected. The original name, source file and
line are retained; synthetic PCs do not claim the original inline tree.

## Registration and relocation

The patcher appends a separate writable `PT_LOAD` containing the module,
function tables, PC tables, findfunc buckets and empty GC programs. Its text
range contains only contiguous registered Go stubs. It does not extend the
original Go text range across unrelated native code, or register new Go roots,
types or initialization tasks.

An initializer fills pointer fields using RIP-relative addresses, then links
`moduledata.next` and updates `runtime.lastmoduledatap`. This preserves ELF PIE
load bias without adding dynamic relocations.

The pinned agy recipe registers through its **first preinit callback**. It
checks both array slots and their RELATIVE relocations, then replaces the first
relocation's addend at file offset 0xa9a8. The initializer tail-jumps to the
original callback at 0x9c0ffa0; the loader then invokes the unchanged second
callback at 0x9c741b0. The raw array slots, DT_INIT and legacy CRT callback are
unchanged. This preserves the original callback order and registers before
both executable preinit callbacks. agy's non-null legacy CRT callback bypasses
DT_INIT, and preinit arrays execute earlier still: neither DT_INIT nor the
legacy callback alone proves sufficiently early registration.
[glibc's initializer ordering](https://codebrowser.dev/glibc/glibc/elf/dl-init.c.html)
places the executable's preinit array before ordinary dependency constructors.

Generic dynamic Go executables use DT_INIT only when they have no nonempty
preinit array and their entry proves a null init-callback argument at a near,
unsegmented GOT call to `__libc_start_main`. The inspected entry cannot write
memory outside its original stack setup or replace that stack. Nonempty or
ambiguous preinit arrays outside the pinned recipe are rejected. Static Go
executables use ELF entry; an internal-link Go PIE can use ELF entry only when
it has no constructor arrays or linked libraries. Existing module chains,
ambiguous module pointers and registration slots protected by RELRO are refused.

Even a zero-length Go data/BSS range needs an explicit empty GC program:
`runtime.modulesinit` still executes those programs. Null GC program pointers
are not valid. The initializer also has assembler-emitted native CFI, merged
into the executable's native unwind index when `--unwind` is enabled. Preinit
and DT_INIT have an ordinary SysV caller; raw ELF entry has no return address.

## Empty type-module fast path

Registering a text-only module must not force agy to deduplicate its entire
original type table. The pinned optimization changes only the four-byte
RIP-relative displacement of the original comparison at 0x6884f9d. Its opcode,
zero immediate, conditional branch and return epilogue remain unchanged. The
comparison reads the synthetic module's `next`, rather than the original
module's `next`.

The builder requires one original module, an initially null synthetic `next`,
and empty synthetic type fields, auxiliary type/link tables and typemap. It
checks the actual metadata bytes and initializer fixups; a caller's assertion
that a module is empty is insufficient. Both publication writes must make the
synthetic module the tail, including `runtime.lastmoduledatap`.

With only the original type-bearing module and this empty module, the original
slow path would collect all original types and create an unused empty typemap.
The conditional fast path avoids that work. A later module appended through
`runtime.lastmoduledatap` sets the synthetic module's `next`; the unchanged slow
path then processes the original module, empty module and new module normally.
No Go PC, frame or stack-map entry moves. Other Go versions receive no such
optimization.

The algorithm follows `runtime/type.go:typelinksinit` and the ordinary
`runtime/asm_amd64.s:addmoduledata` append protocol in the installed Go sources.
For agy's different private layout, its actual `runtime.moduleTypelinks` at
0x68855a0 reads the type area at offsets 0x128/0x130, and the exact original
nil-next comparison, JE and return bytes are checked against the pinned input.
A native fixture executes those exact guard bytes and confirms that a later
non-null `next` still selects the slow path. Counterexamples cover populated
types, pointer fixups, changed module topology, incorrect tail publication,
altered guard/branch/epilogue and an unreachable RIP-relative target.

On the final artifact, QEMU's local instruction count for
`runtime.typelinksinit` returns from 3,161,814 to the original 11, while module
verification and the initializer's single execution remain intact. End-to-end
timings belong in the main runtime report, since instruction counts alone do
not establish a wall-clock improvement.

## Layout scope

- Go 1.26 amd64: the binary's own DWARF must confirm the private `moduledata`
  size and relevant member offsets. The documented Go 1.26 ABIInternal permits
  borrowing XMM0–14 that the complete, ordinary compiler-generated function
  does not use. Assembly and special runtime functions do not receive this
  ABI-based liveness shortcut.
- agy 1.2.7: the complete original SHA-256 is pinned to
  `baff3db5e4c09635709fa9838e4038c9b4f2c164ce7a80a18059393797d6802c`.
  Its embedded version is `go1.28-20260721-RC03`, with a different module layout:
  `next` is at 0x230, and `gofunc` is at 0x158. The binary's actual `findfunc`,
  `modulesinit` and `getStackMap` consumers establish these fields. This profile
  permits metadata construction, but does **not** approve a development
  compiler's caller-clobber ABI. agy scratch registers therefore require local
  liveness evidence.

The source metadata checks accept 26 of agy's 52 previously relocated Go
instruction sites. That count does not mean all 26 have usable scratch
registers. The countbody assembly recipe and dormant feature-dispatch paths
are handled separately; the report records the remaining gaps.

An extra pclntab magic sequence is not automatically a live module. The audit
reports whether allocated, aligned pointer words or RELATIVE relocations refer
to each rejected candidate. agy's extra 0xd4143a2 candidate has no such static
reference. Referenced or unclassified candidates still fail the strict gate.
This classification concerns the initial linked image, not arbitrary modules
created dynamically by an application.

## Validation

Run `python test_go_runtime.py -v` with Go, GCC/binutils, iced-x86, pyelftools and
QEMU available. The thirteen tests cover PC-table encoding and malformed inputs,
forbidden stack/call operations, and real Go runtime execution through:

- ELF entry in a static executable;
- ELF entry in an internal-link PIE;
- DT_INIT in an external-link PIE;
- QEMU's Penryn CPU model, with an original-binary SIGILL negative control;
- a real legacy CRT callback that demonstrably bypasses DT_INIT until its
  direct initializer call is redirected, plus rejection of an unproved init
  argument, segmented/far call, GOT write or unexpected import;
- checked first-preinit relocation with the second callback preserved, and
  rejection of a real executable with an unhandled nonempty preinit array.

The fixtures register both a zero-sized frame and an original 72-byte frame.
They query `runtime.FuncForPC` and source locations, perform 48 concurrent GC
rounds and 9,600,048 patched counts, and enter a 64-level recursive function
with live stack pointers. Native CPU profiles identify the original Go
functions without `_ExternalCode`. The same fixture layout includes the native
initializer CFI merger and independently writable/executable ELF segments.
On the final `agy-final-v4` artifact, QEMU records the Go initializer executing
exactly once (37 instructions) in both version and help workloads. A GDB breakpoint in the original
`runtime.moduledataverify1` confirms that Go validates the synthetic module and
that both the original module's `next` and `runtime.lastmoduledatap` point to it;
`--version` then prints 1.2.7 and exits normally. Both startup workloads also
pass with `GOGC=1`, with stdout and stderr identical to their normal-GC runs.

Core dumps are disabled for negative controls. No kernel emulation or GPU
configuration is changed.

The tests validate this narrow replacement contract. They do not certify
arbitrary Go code relocation, memory faults inside a replacement, user signal
handlers that require the exact original register context, or undeclared
compiler/runtime versions.
