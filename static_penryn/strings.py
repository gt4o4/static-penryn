"""Specialized PCMPxSTRx leaf helpers and their preserving trampolines.

``lower(ins)`` returns a GAS Intel-syntax body with no label/final jump.
``build_helpers`` compiles the matching immediate-specialized arithmetic,
then checks its leaf, register and bounded-stack contract before use.  The
pinned core's arithmetic is unchanged.  Ordinary SysV stack requirements
still apply: this is not a Go stack-growth check or unwind implementation.
"""

import json
from pathlib import Path
import subprocess

from iced_x86 import Code, Decoder, FlowControl, InstructionInfoFactory, Mnemonic, OpKind, Register

from .lower import memory_load


SUPPORTED = frozenset(
    {
        Mnemonic.PCMPISTRI,
        Mnemonic.PCMPISTRM,
        Mnemonic.PCMPESTRI,
        Mnemonic.PCMPESTRM,
        Mnemonic.PCMPESTRI64,
        Mnemonic.PCMPESTRM64,
    }
)

_SAVE = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12")
_WIDE = frozenset({Code.PCMPESTRI64_XMM_XMMM128_IMM8, Code.PCMPESTRM64_XMM_XMMM128_IMM8})
_FRAME = 144  # 80-byte C frame plus the four explicitly clobbered XMMs
_ORIGINAL_RSP = 128 + 8 + 8 * len(_SAVE) + _FRAME
_SAVED_FLAGS = _FRAME + 8 * len(_SAVE)
_SAVED_RAX = _SAVED_FLAGS - 8
_SAVED_RCX = _SAVED_RAX - 8
_SAVED_RDX = _SAVED_RCX - 8
_FLAGS = 56
_INDEX = 48

# CALL adds 8 bytes after at most 15 bytes of dynamic alignment.  Helpers
# are audited leaf functions; GCC's .su count includes their return address.
STACK_BYTES_BEFORE_HELPER = _ORIGINAL_RSP + 15 + 8
MAX_STACK_BYTES = 512


def specialization(ins):
    if ins.mnemonic not in SUPPORTED:
        raise ValueError(f"not a PCMPxSTRx instruction: {ins}")
    explicit = ins.mnemonic in (
        Mnemonic.PCMPESTRI, Mnemonic.PCMPESTRM,
        Mnemonic.PCMPESTRI64, Mnemonic.PCMPESTRM64,
    )
    mode = 2 if ins.code in _WIDE else int(explicit)
    mask = ins.mnemonic in (
        Mnemonic.PCMPISTRM, Mnemonic.PCMPESTRM, Mnemonic.PCMPESTRM64,
    )
    # Hardware ignores bit 7.  Signedness affects only Ranges; polarity 2
    # equals polarity 0 for every aggregation, so share those helpers too.
    control = ins.immediate8 & 127
    if control & 12 != 4:
        control &= ~2
    if control & 48 == 32:
        control &= ~32
    return mode, int(mask), control


def helper_name(key):
    mode, mask, control = key
    return f"penryn_pcmp_{mode}_{mask}_{control:02x}"


def build_helpers(instructions, core, work):
    """Return (object path, audit report) for the referenced specializations.

    The caller validates the pinned core hashes.  This function also serves
    the native differential harness, which accepts an explicit --core path.
    No unchecked compiler ABI assumption is used to drop register saves.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    keys = sorted({specialization(ins) for ins in instructions if ins.mnemonic in SUPPORTED})
    work, core = Path(work), Path(core)
    source = work / "strings-specialized.c"
    source.write_text(
        '#include ' + json.dumps(str(Path(__file__).with_name("strings.c").resolve())) + '\n'
        + ''.join(f'PENRYN_HELPER({helper_name(key)}, {key[2]}, {key[0]}, {key[1]})\n'
                  for key in keys)
    )
    obj = work / "strings.o"
    subprocess.run([
        "cc", "-O2", "-march=core2", "-mgeneral-regs-only", "-fPIC", "-ffreestanding",
        "-fno-stack-protector", "-mno-red-zone", "-ffunction-sections", "-fdata-sections",
        "-fasynchronous-unwind-tables", "-funwind-tables", "-fvisibility=hidden",
        "-fno-omit-frame-pointer", "-mno-omit-leaf-frame-pointer",
        "-fstack-usage", "-I" + str(core), "-c", str(source), "-o", str(obj),
    ], check=True)
    usages = {}
    for line in obj.with_suffix(".su").read_text().splitlines():
        function, size, kind = line.rsplit("\t", 2)
        usages[function.rsplit(":", 1)[-1]] = (int(size), kind)
    helpers = []
    info_factory = InstructionInfoFactory()
    with obj.open("rb") as handle:
        elf = ELFFile(handle)
        for key in keys:
            name = helper_name(key)
            section = elf.get_section_by_name(".text." + name)
            if section is None:
                raise ValueError(f"missing specialized string helper {name}")
            # A relocation in an apparent local JMP could conceal a tail
            # call until link time.  Only read-only, non-executable constants
            # are permitted outside the already audited helper section.
            section_index = elf.get_section_index(section.name)
            for relocations in elf.iter_sections():
                if not isinstance(relocations, RelocationSection) or relocations["sh_info"] != section_index:
                    continue
                symbols = elf.get_section(relocations["sh_link"])
                for relocation in relocations.iter_relocations():
                    symbol = symbols.get_symbol(relocation["r_info_sym"])
                    target_index = symbol["st_shndx"]
                    if not isinstance(target_index, int):
                        raise ValueError(f"external dependency in string helper {name}: {symbol.name}")
                    target = elf.get_section(target_index)
                    if target["sh_flags"] & 5 or not target["sh_flags"] & 2:
                        raise ValueError(f"non-constant reference in string helper {name}: {symbol.name}")
            code = section.data()
            for ins in Decoder(64, code):
                if ins.is_invalid:
                    raise ValueError(f"invalid instruction in {name}")
                if ins.flow_control in (FlowControl.CALL, FlowControl.INDIRECT_CALL,
                                        FlowControl.INDIRECT_BRANCH):
                    raise ValueError(f"string helper is not an auditable leaf: {name}: {ins}")
                if ins.flow_control in (FlowControl.UNCONDITIONAL_BRANCH, FlowControl.CONDITIONAL_BRANCH):
                    if not 0 <= ins.near_branch_target < len(code):
                        raise ValueError(f"string helper leaves its audited body: {name}: {ins}")
                for used in info_factory.info(ins).used_registers():
                    register = used.register
                    if ((Register.XMM0 <= register <= Register.ZMM31
                         and not Register.XMM12 <= register <= Register.XMM15)
                            or Register.ST0 <= register <= Register.MM7):
                        raise ValueError(f"unexpected compiler vector/FP clobber: {name}: {ins}")
            if name not in usages or usages[name][1] != "static":
                raise ValueError(f"missing static string helper stack bound: {name}")
            stack = STACK_BYTES_BEFORE_HELPER + usages[name][0] - 8
            if stack > MAX_STACK_BYTES:
                raise ValueError(f"string helper exceeds {MAX_STACK_BYTES}-byte stack budget: {name}: {stack}")
            helpers.append({"name": name, "code_bytes": len(code), "max_stack_bytes": stack})
    return obj, {"specializations": helpers, "saved_xmm_registers": [12, 13, 14, 15],
                 "max_stack_bytes": max((h["max_stack_bytes"] for h in helpers), default=0)}


def lower(ins):
    """Return a preserving body for legacy PCMPISTRI/M or PCMPESTRI/M."""
    key = specialization(ins)
    mode, mask, _ = key
    if ins.op_count != 3 or ins.op0_kind != OpKind.REGISTER:
        raise ValueError(f"unsupported PCMPxSTRx operand shape: {ins}")
    source_a = ins.op0_register - Register.XMM0
    if not 0 <= source_a < 16:
        raise ValueError(f"unsupported PCMPxSTRx source register: {ins}")

    lines = ["lea rsp, [rsp - 128]", "pushfq"]
    lines += [f"push {reg}" for reg in _SAVE]
    lines += [f"lea rsp, [rsp - {_FRAME}]"]
    lines += [f"movdqu [rsp + {80 + 16 * (i - 12)}], xmm{i}" for i in range(12, 16)]
    # Capture A before loading B through xmm12, including aliased xmm12
    # operands.  All address GPRs still contain their original values.
    lines += [f"movdqu [rsp], xmm{source_a}"]
    if ins.op1_kind == OpKind.MEMORY:
        lines += [memory_load(ins, "xmm12", stack_delta=_ORIGINAL_RSP, mnemonic="movdqu")]
        lines += ["movdqu [rsp + 16], xmm12"]
    elif ins.op1_kind == OpKind.REGISTER:
        source_b = ins.op1_register - Register.XMM0
        if not 0 <= source_b < 16:
            raise ValueError(f"unsupported PCMPxSTRx source register: {ins}")
        lines += [f"movdqu [rsp + 16], xmm{source_b}"]
    else:
        raise ValueError(f"unsupported PCMPxSTRx memory form: {ins}")

    # Both lengths are initialized, including implicit forms: the wrapper's
    # source is valid C even before constant folding removes those arguments.
    # Preserve the original frame-pointer chain throughout the trampoline.
    # R12 is saved above and preserved by the helper's SysV calling convention.
    # The helper itself builds a conventional frame (compiler flags above).
    lines += ["mov [rsp + 64], rax", "mov [rsp + 72], rdx", "mov r12, rsp",
              "mov rdi, rsp", "and rsp, -16", "cld", f"call {helper_name(key)}"]
    lines += [f"mov rax, [r12 + {_SAVED_FLAGS}]", "and rax, -2262",
              f"or rax, [r12 + {_FLAGS}]", f"mov [r12 + {_SAVED_FLAGS}], rax"]
    if not mask:
        lines += [f"mov eax, [r12 + {_INDEX}]", f"mov [r12 + {_SAVED_RCX}], rax"]
    else:
        lines += ["movdqu xmm0, [r12 + 32]"]
    lines += ["mov rsp, r12"]
    lines += [f"movdqu xmm{i}, [rsp + {80 + 16 * (i - 12)}]" for i in range(12, 16)]
    lines += [f"lea rsp, [rsp + {_FRAME}]"]
    lines += [f"pop {reg}" for reg in reversed(_SAVE)]
    lines += ["popfq", "lea rsp, [rsp + 128]"]
    return "\n".join(lines)
