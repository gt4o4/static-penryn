# Reusing compiler and binary-tool infrastructure

The patcher keeps application-specific policy small and delegates decoding,
relocation, arithmetic compilation, frame parsing and profiling to existing
implementations. It does not translate a whole executable back into C/LLVM IR.

| Component | Reused implementation | Responsibility retained here |
|---|---|---|
| x86 decode/encode | iced-x86 instruction metadata and block encoder | Supported-family selection, protected entries, preservation contract |
| String arithmetic | Pinned MIT opemu core, compiled with GCC | Immediate specialization and wrapper/state/stack audits |
| ELF/native frames | pyelftools ELF and DWARF parsers | Map generated PCs to original frame rows, reject unknown transformations |
| Machine code and CFI | GNU assembler/linker; GCC helper CFI | Link addresses, frame-state translation and ELF publication |
| Go function recovery | Go `debug/elf`, `debug/gosym`, `debug/buildinfo` | Validate stripped/C-archive candidates and audit unsupported runtime metadata |
| Dynamic counts | QEMU's official plugin API/header and inline scoreboards | Exact binary/range/byte attribution and workload validation |
| Native samples | Linux perf record/script | Map sampled PCs to generated sites and distinguish other mappings |

GCC's `-march` chooses the ISA of code being compiled; `-mtune` controls
scheduling/tuning within that ISA. We already use these facilities on helper
source. They do not provide a command to recompile an arbitrary stripped
ELF for an older CPU. Likewise, LLVM's code generator legalizes operations
from its compiler IR; feeding it an ELF requires an additional lifting layer
that recovers register/flag state, control flow and memory semantics.
[GCC x86 options](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html),
[LLVM code generator](https://llvm.org/docs/CodeGenerator.html).

For short instruction replacements, a normal C function ABI is insufficient:
flags, every live register, the red zone, unusual operand aliases and memory
fault behavior are observable. The existing audited lowerings retain this
contract. Region fusion composes those same lowerings and shares their scratch
saves; it introduces no second POPCNT/CRC32/PCMPGTQ arithmetic implementation.
Future compiler-generated region candidates should pass the same hardware
state oracle and native timing harness before selection.

## LLVM BOLT assessment

BOLT is relevant to profile-guided binary layout and CFG recovery. Its
documented input contract expects an unstripped symbol table; emitted static
relocations improve function movement. Its indirect-branch recovery relies
on compiler patterns and separated code/data. It is not a ready-made pass
for replacing these instructions while repairing Go runtime metadata.
[BOLT input requirements](https://github.com/llvm/llvm-project/blob/main/bolt/README.md#input-binary-requirements).

Inspection of the measured payloads found:

- agy has neither `.symtab` nor `.rela.text`; Go metadata supplies many of
  its function bounds, but does not repair native/Go runtime relocation rules.
- Claude has `.symtab`, but most internal patch sites and its hot regex loop
  lack usable symbol/FDE bounds; it also lacks `.rela.text`.

Therefore this pass does not add BOLT as a dependency or assume its recovery
would make either application safe to rewrite wholesale. A useful later
experiment is BOLT on a source-built native fixture with `--emit-relocs`,
comparing its recovered blocks and layout against the same workload/oracle.
That is an evaluation path, not a tested performance claim for these binaries.

## Runtime limitation remains explicit

Native DWARF CFI cannot express Go's function lookup, pc-value tables, stack
maps, safe points or stack-growth protocol. Using the official Go parsers
improves identification and refusal; it does not make appended Go code safe
under all runtime operations. The strict gate and observed CPU-profile gap
are described in [RUNTIME.md](RUNTIME.md).
