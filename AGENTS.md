# AGENTS.md

Guidance for AI coding agents in this repository.

static-penryn is an experimental offline ELF64 rewriter for iMacGBC's Core 2
Duo (Penryn: no SSE4.2, no POPCNT); README.md has its status, usage,
boundaries and records. It is its own repository (`gt4o4/static-penryn`), checked
out gitignored at nix-configs' `submodules/static-penryn/`, so nix-configs'
AGENTS.md and its fleet rules load here too.

nix-configs uses the tool as follows:
- It packages it as `pkgs.custom.static-penryn`
  (`common/pkgs/static-penryn.nix`, the one recipe, pinned by rev).
  `default.nix` here is only a shim that builds a checkout with that
  recipe.
- iMacGBC's `hosts/iMacGBC/penryn-overlays.nix` rewrites Claude Code and agy
  with it at build time (since generation 486, 2026-11-02). The
  Antigravity IDE's agent is that agy (`agy --hub`).
- The hub's own `language_server` and `webm_encoder` have been rewritten
  since 488. That rewrite is their last fixup hook, after autoPatchelf; the
  language_server's compiled-in AES-NI stays on opemu.
- A pushed change reaches iMacGBC only when the pin moves (rev and hash in
  `common/pkgs/default.nix`; `docs/bumping/static-penryn.md` there).
- opemu stays for everything else: don't retire it, and don't combine this
  with CPUID spoofing.

## Toolchain: x86-64 only

The package runs `cc` (the string helpers, the profiler's QEMU plugin) and
`ld`, the tests also `gcc`, all expecting x86-64 ELF64 output. Assembly needs
no assembler program (`assembler.py`). iMacGBC is native x32 since
2026-10-28: its `pkgs`, its profile's `cc` (ELF32 output) and its `python3`
(no pip, no iced_x86) are x32, unsupported here. On iMacGBC, patch with the
packaged tool built from `pkgs.x86_64`; run the tests and the venv route
where `python3`, `cc` and `ld` are x86-64 (lix-ory). iMacGBC's `go` and
`qemu-x86_64` are x86-64.

## Commands

From the checkout root, off-box with `--max-jobs 0`:

```sh
nix build --impure --expr '
  let f = builtins.getFlake "git+file:///home/wenri/.config/nix-configs";
  in f.nixosConfigurations.iMacGBC.pkgs.x86_64.callPackage ./. { }
' --out-link /tmp/static-penryn-tool --max-jobs 0
# Append .libtcc, .devPython or .tests.typecheck to the callPackage
# expression for TinyCC's library, the dev Python (with mypy) or the type
# check; --no-link where no out-link is wanted.
export PENRYN_LIBTCC=$(nix build --impure --no-link --print-out-paths --max-jobs 0 --expr '
  let f = builtins.getFlake "git+file:///home/wenri/.config/nix-configs";
  in (f.nixosConfigurations.iMacGBC.pkgs.x86_64.callPackage ./. { }).libtcc
')/lib/libtcc.so
```

- `PENRYN_LIBTCC` is needed by every patch run, so by every patching test
  (an x32 libtcc fails to load).
- `PENRYN_GOMETA` names the Go helper (`go build -o /tmp/penryn-go-metadata
  ./static_penryn/go_metadata.go`). Without it, every `--go-*` option
  refuses and `--require-unwind`/`--require-runtime` fail ("Go metadata was
  not audited").
- `PENRYN_GLIB_CFLAGS` replaces `pkg-config --cflags glib-2.0` for the
  profiler's plugin.
- `PENRYN_CORE` names opemu-linux's `core/` (`--core` overrides it; a
  checkout defaults to `../opemu-linux/core`).
- The wrapper sets all four.

Tests run one module per command. They need `cc`, `gcc`, `ld` and
`qemu-x86_64`. Fixtures run under `qemu-x86_64 -cpu Penryn`, where the
original must die of SIGILL and the rewritten one pass; core dumps are off.
The Go tests need Go 1.26.

```sh
python -m tests.test_patch     # likewise test_dataflow, test_controlflow,
                               # test_integration, test_profile, test_go_runtime,
                               # test_go_inplace, test_assembler
PENRYN_GOMETA=/tmp/penryn-go-metadata python -m tests.test_runtime
PENRYN_GOMETA=/tmp/penryn-go-metadata python -m tests.test_native_frames
python -m unittest tests.test_regions         # unit tests only
python -m unittest tests.test_patch -k cave   # a subset
```

The hardware oracles compare generated code with real SSE4.2/POPCNT. Their
worker refuses a CPU without the instructions, and opemu is never the oracle
(it shares the arithmetic core). Generation runs locally. `--remote HOST`
runs only the worker over SSH, which needs nothing but `python3` there.
`test_lower` and `test_strings` are argparse scripts, so `unittest` collects
nothing from them.

```sh
python -m tests.test_lower [--remote lix-ory]
python -m tests.test_strings [--remote lix-ory]
python -m tests.test_regions [--remote lix-ory]
python -m tests.test_go_lower [--remote lix-ory]   # its unit tests run first
```

The type check is mypy over `static_penryn/` and `tests/` (`mypy.ini`; stubs
in `typings/`). Run it from the Nix environment, the `tests.typecheck`
derivation or `devPython`'s `mypy`, never a venv: `default.nix` patches
iced-x86's stub, whose `Register` and `RepPrefixKind` enums declare one
member each.

`python -m tests.structdiff A B` compares two patched outputs of one input,
each with its `OUTPUT.json`. It prints the header, section and byte
differences, both `.penryn.eh_frame` sections decoded, and every
`.penryn.eh_frame_hdr` entry resolved. Exit 1 means a structural check
failed, not that the files differ. Use it after a pipeline change, with the
old output regenerated from a `git archive` of the old commit.

## Architecture

`patch.main` is the pipeline: load (pwntools), validate, scan, plan, group,
lower, assemble and link, unwind, Go metadata, rewrite, then re-parse,
re-validate and re-scan, then publish.

- `elfcheck`: the loader's view: PT_LOAD/PT_DYNAMIC consistency, relocation
  write spans, pointer targets, unscanned RX ranges.
- `controlflow`: function bounds (symbols, FDEs, Go), guarded relative jump
  tables, the instruction-start bitmap, block leaders.
- `dataflow`: bounded proofs that flags, GPRs and XMMs are dead after a site.
- `lower`: POPCNT/CRC32/PCMPGTQ. `strings` and `strings.c`: PCMPxSTRx
  trampolines into helpers compiled from the opemu core.
- `regions`: fusion of adjacent sites under one shared scratch frame.
- `assembler`: LLVM assembly through llvmlite, behind the libtcc shim.
- `unwind` and `native_frames`: CFI from original rows; CFG-based frame
  inference.
- `go_metadata.go` and `gometa`: the Go helper and its checked report.
- `go_runtime`, `go_lower`, `go_inplace`: Go module registration,
  stack-neutral Go POPCNT, and the pinned agy recipes.
- `profile`, `workloads`, `bench_apps` and `profile_plugin.c`: profiling and
  timing.
- `checked`: the typed boundaries for JSON, `struct`, iced constants and
  `required`.

The JSON report (`schema_version` 2) is itself an input. `profile.load_model`
binds a profile to its `output_sha256` and exact stub ranges, and
`bench_apps` requires both variants to share `input_sha256`.

## Invariants

- **Never overwrite.** The input is only read; the output, report and
  `--work-dir` must be new, and `publish` links them in exclusively.
- **Refuse or report, never guess.** An unknown case is a refusal or an
  explicit report gap (`uncovered_ranges`, `go_unhandled_sites`,
  `strict_runtime_reasons`). Both full applications failing the strict gates
  is the recorded status, not a gate to loosen.
- **Profiles select and order work.** A zero count never proves a site
  unreachable or safe.
- **The agy recipes are pinned.** `go_inplace.PINNED`, `DISPATCH_PINNED`,
  and `go_runtime`'s preinit, typelinks and `AGY_PROFILE` are bound to agy
  1.2.7's SHA-256 (`go_runtime.AGY_SHA256`) and exact bytes: don't
  generalize them.
- **Lowerings preserve state.** Every GPR, XMM, flag, DF and red-zone byte
  that is not an output or proven dead is preserved, within README's stack
  budgets. A change to `lower.py`, `strings.py`, `regions.py` or
  `go_lower.py` needs its hardware oracle.
- **Only opemu's arithmetic is reused.** `CORE_HASHES` pins its two files,
  and a mismatch fails any input containing PCMPxSTRx. A core change means
  new hashes, README's revision and a `test_strings` oracle run.
- **The package is `static_penryn/`.** nix-configs' recipe packages exactly
  that directory minus `__pycache__`, so anything placed there ships, and at
  the next pin bump it changes iMacGBC's Claude Code and agy.
  - `pyproject.toml` makes it a Python package with the `static-penryn`
    command (`static_penryn.cli`, also `python -m static_penryn`).
  - Its package-data patterns must cover every non-Python file the code
    opens beside itself.
  - Its version is set by hand, there and in nix-configs' recipe.
- **Correct output is the criterion, not byte equality with GNU tools.**
  Check equivalence by decoded content (`tests.structdiff`).
- **The assembler shim is undefined behaviour by the C standard**, the
  owner's choice (2026-11-02); `assembler.py`'s docstring is its contract.
  - It was verified on glibc 2.42, LLVM 20.1.8, llvmlite 0.46.0 and TinyCC
    0.9.27-unstable-2025-01-06; rerun `test_assembler` after any of them
    changes.
  - Never put a Python frame between `setjmp` and LLVM.
  - Never `tcc_delete` the shim's state.
  - `abort()` is not caught.
- **Typing.** mypy strict plus every `disallow_any_*` flag: no `Any`,
  written or inferred, and no `type: ignore`.
  - `typing.cast` appears only behind a check: `checked.unpack_ints` and
    `iter_ints`, and `re` match results in `go_runtime` and `go_inplace`.
  - JSON enters through `checked` or `gometa.parse`, so malformed input
    raises `ValueError`.
  - A third-party gap gets a stub in `typings/` describing only what is
    used.
  - `patch.py` runs as `__main__`, so other modules import its types only
    under `TYPE_CHECKING`.
- **Tests.**
  - Narrow with `assert` or `test_controlflow.present`.
  - A helper shared between test classes declares `self:` as a Protocol.
  - A literal passed to `assertEqual` goes into an annotated variable first.
  - argparse goes through `Namespace` subclasses.
  - A missing tool raises `SkipTest` in `setUpClass`.

## Runtime contracts

### Native unwind

- `--unwind` gives each generated range the original `.eh_frame` row of
  its original PC, following the stub's stack and register moves. A merged
  EH header indexes the original and the new FDEs.
- String helpers keep GCC's CFI. Scalar lowerings never use RBP, and string
  trampolines keep the RBP chain.
- These become reported gaps: unsupported rules, signal-frame CIEs, missing
  original FDEs, untracked stack changes and helpers with an LSDA.
- The metadata serves backtraces only: landing pads and fault contexts are
  not remapped.
- `--infer-unwind` takes its entries from symbols, direct CALL targets and
  verified indirect-call slots. It runs a fixed point over every reachable
  predecessor, which fails shut on pivots, unknown edges, disagreeing stack
  depths and known interior entries.
- Inference assumes the SysV convention and that unrelated stores leave
  saved state alone. Undiscovered indirect entries cannot be excluded, and
  Go functions are excluded.

### Go stubs (`--go-runtime`)

- Each replaces one register-only 32/64-bit POPCNT: no call, no stack, no
  memory writes. RSP, RBP, R14 (the goroutine register) and X15 (the zero
  register) stay untouched.
- Scratch is a proven-dead GPR, or a GPR parked in a proven-dead XMM.
- Stub PCs are `UnsafePointUnsafe` and `FuncFlagAsm`. Each inherits its
  original PC's pcsp, stack map, arguments and FUNCDATA, since a jump adds
  no frame.
- A writable `PT_LOAD` holds the module and its GC programs, which are empty
  but never null (`runtime.modulesinit` runs them).
- A RIP-relative initializer links `moduledata.next` and
  `runtime.lastmoduledatap`.
- Refused: existing module chains, ambiguous module pointers,
  RELRO-protected slots.
- Only a referenced, unhandled pclntab candidate fails the strict gate;
  unreferenced magic does not.

### Go startup and layouts

- agy's non-null legacy CRT callback bypasses DT_INIT, and preinit runs
  earlier still. So the agy recipe registers from the first preinit
  callback, rewriting its RELATIVE addend, and keeps the callback order.
- A generic dynamic binary uses DT_INIT only with no nonempty preinit array
  and a proven null init argument to `__libc_start_main`.
- Static executables use the ELF entry, as do internal PIEs that have no
  constructors.
- Go 1.26 amd64: the binary's own `moduledata` DWARF must confirm the
  layout. ABIInternal functions may borrow XMM0–14 that the whole function
  never uses.
- agy 1.2.7 (`go1.28-20260721-RC03`): its layout comes from its `findfunc`,
  `modulesinit` and `getStackMap`. Its compiler's ABI is not assumed, so its
  scratch registers need local liveness proof.

### Pinned agy recipes

- **Type-link fast path:** a second, typeless module made
  `runtime.typelinksinit` hash every original type, 11 → 3,161,814 guest
  instructions (about 9 ms of startup). The fix retargets the nil-`next`
  guard's displacement to the synthetic module's `next`. A module appended
  later restores the slow path.
- **`--go-inplace`:** `countbody`'s seven POPCNTs become a PSADBW body
  inside the original 448-byte function, keeping zero pcsp and page-safe
  short loads.
- **`--go-dispatch`:** 18 SSE4.2 sites stay. They are unreachable because
  the flag is loader-zeroed BSS, set only by CPUID ECX bit 20, and the
  options loop can only clear it. The AVX512 FilterNil POPCNT is excluded:
  its address literal is unresolved.

### Validation (2026-09-21)

Static, internal-PIE and external-PIE (DT_INIT) Go fixtures passed:
- `FuncForPC` and file/line lookups;
- stack depths 0 and 72, concurrent GC and stack growth;
- CPU profiles without `_ExternalCode`.

On agy 1.2.7 the initializer ran once (37 instructions), and
`runtime.moduledataverify1` accepted the module.

## Decisions

- **Rewrite, not recompile.** Neither GCC nor LLVM recompiles a stripped
  ELF without a lifter. A C ABI cannot host the replacements: flags, live
  registers, the red zone, aliases and faults are observable.
- **A data word is a pointer target only in an ET_EXEC image
  (2026-11-02).**
  - A static executable's pointer arrays lose their relocations at link
    time, so `elfcheck` protects every aligned data word that falls in
    code.
  - A PIE's code pointers all carry RELA, REL or RELR relocations, so its
    unrelocated words are numbers.
  - antigravity-hub 2.28.2's `language_server` keeps 32-bit hashes beside
    relocated pointers in `.data.rel.ro`. One of them, `0x7fd9436`, fell
    inside a CRC32 and refused the whole run.
  - `test_unrelocated_pie_word_is_not_a_pointer` holds the rule.
- **pwntools 4.15.0 loads the input.** Its `write()` silently skips an
  address with no file bytes, hence `patch.write_image`. Its GOT pass costs
  about 18 s on agy 1.4.12 and 3.3 s on Claude Code 2.1.316.
- **llvmlite 0.46.0 (LLVM 20.1.8) assembles.**
  - It replaced four `cc -c` calls and is no faster: agy's `compile` stage
    took 8.5–8.8 s with GNU as and 9.6–9.9 s with LLVM.
  - Its CFI repeats each FDE's opening rules; accepted on 2026-11-01.
  - llvmlite installs no diagnostic handler, so LLVM calls `exit(1)` on an
    invalid source
    ([`LLVMContext::diagnose`](https://llvm.googlesource.com/llvm/+/refs/heads/release_38/lib/IR/LLVMContext.cpp),
    [bug 27809](https://lists.llvm.org/pipermail/llvm-bugs/2016-June/047445.html)).
- **The setjmp/longjmp shim (2026-11-02)** turns that `exit` into a
  `ValueError`. It was chosen over a forked child to keep one process.
  Hooking libllvmlite's `exit`/`abort` PLT slots (`JUMP_SLOT`, RELRO,
  `BIND_NOW`) would also catch `abort()`.
- **Not adopted:**
  - LIEF 0.17.0 moves content and crashed on Claude.
  - LLDB 21.1.8 exposes no raw headers, flags, tags or relocations.
  - capstone 5.0.7 only decodes, stops at invalid bytes and is untyped.
  - `pwnlib.asm` returns no relocatable object.
  - A Python exit handler swallows exceptions and crashes normal exits.
  - An LLVM-IR shim was replaced by C for readability. libclang stops at
    the AST, and cppyy is not in nixpkgs.
  - BOLT needs symbols, relocations and separated code and data, which agy
    lacks.

## Docs

README.md and this file are the only docs. They hold what the code cannot
say: decisions and their reasons, pins, boundaries and the latest records,
dated, with input/output SHA-256. Superseded results are deleted, not
accumulated.
