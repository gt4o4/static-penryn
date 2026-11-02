#!/usr/bin/env python3
"""Differential-test leaf lowerings against SSE4.2 hardware.

Run with the patcher's Python dependencies installed:
  python -m tests.test_lower --remote lix-ory
The generated shared library has no external dependencies.  The remote
worker needs only Python 3, and must have real SSE4.2/POPCNT hardware.
"""
# Unevaluated annotations keep this file, which is the remote worker, free
# of typing names its python3 may lack.
from __future__ import annotations

import argparse
import ctypes
import json
import pathlib
import random
import resource
import shlex
import subprocess
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import TypeIs


# static_penryn.checked's JSON checks; the remote worker cannot import it.
def is_object(value: object) -> TypeIs[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)


def is_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def worker(library: pathlib.Path, iterations: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cpu_flags = set(pathlib.Path("/proc/cpuinfo").read_text().split("flags", 1)[1].split("\n", 1)[0].split())
    if not {"sse4_2", "popcnt"} <= cpu_flags:
        raise RuntimeError("hardware oracle requires real SSE4.2/POPCNT; opemu is not an oracle")
    manifest: object = json.loads(library.with_suffix(".json").read_text())
    if not is_list(manifest):
        raise ValueError(f"{library.with_suffix('.json')} is not a JSON array")
    lib = ctypes.CDLL(str(library.resolve()))
    State = ctypes.c_uint64 * 65
    Pointer = ctypes.POINTER(State)
    memory = (ctypes.c_uint64 * 8).in_dll(lib, "test_memory")
    randomizer = random.Random(0x50454E52594E)
    flags_mask = 0xCD5  # Six arithmetic flags plus DF.
    checked = 0
    edges = [0, 1, (1 << 64) - 1, 1 << 63, (1 << 63) - 1, 0xAAAAAAAAAAAAAAAA]
    for index, case in enumerate(manifest):
        if not is_object(case):
            raise ValueError(f"manifest entry {index} is not a JSON object")
        native = lib[f"native_{index}"]
        lowered = lib[f"lowered_{index}"]
        native.argtypes = lowered.argtypes = [Pointer, Pointer]
        native.restype = lowered.restype = None
        for trial in range(iterations):
            values = [randomizer.getrandbits(64) for _ in range(65)]
            if trial < len(edges):
                values = [edges[trial]] * 65
            if trial % 4 == 3:
                # Equal high dwords with arbitrary low halves exercise unsigned
                # low-dword comparison, which uniform random vectors almost miss.
                for k in range(17, 49):
                    values[k] = (0x87654321 << 32) | randomizer.getrandbits(32)
            # Do not set trap, alignment-check, privileged or reserved flags.
            values[16] = 0x202 | (randomizer.getrandbits(12) & flags_mask)
            if case["mode"] in ("base", "indexed"):
                values[7] = ctypes.addressof(memory)
            if case["mode"] == "indexed":
                values[1] = 2
            for k in range(8):
                memory[k] = randomizer.getrandbits(64) if trial >= len(edges) else edges[trial]
            initial, native_state, lowered_state = State(*values), State(), State()
            native(ctypes.byref(initial), ctypes.byref(native_state))
            lowered(ctypes.byref(initial), ctypes.byref(lowered_state))
            # ctypes types array items as Any; read the slots through the buffer.
            expected, actual = (memoryview(state).cast("B").cast("Q").tolist()
                                for state in (native_state, lowered_state))
            # Both wrappers use the same C ABI stack depth; RSP must also match.
            if not case.get("preserve_flags", True):
                expected[16] &= ~0x8d5
                actual[16] &= ~0x8d5
            ignored = case.get("dead_slots", [])
            if not is_list(ignored):
                raise ValueError(f"{case}: dead_slots is not a JSON array")
            differences = [(k, hex(expected[k]), hex(actual[k])) for k in range(65)
                           if k not in ignored and expected[k] != actual[k]]
            if differences:
                raise AssertionError(f"{case}, trial={trial}: slots(native,lowered)={differences}")
            checked += 1
    print(f"PASS: {checked} native/lowered comparisons across {len(manifest)} forms/liveness modes; "
          "live GPRs/status flags, DF, 16 XMM registers and 128-byte red zone compared")



def state_wrapper(name: str, body: str) -> str:
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
    lines = [f".global {name}", f".type {name}, @function", f"{name}:"]
    for register in ("rbx", "rbp", "r12", "r13", "r14", "r15"):
        lines.append(f"push {register}")
    lines += ["sub rsp, 2056", "lea rsp, [rsp + 1024]", "mov [rsp + 768], rdi", "mov [rsp + 776], rsi"]
    # Fill the red zone before any target registers or flags are loaded.
    for k in range(16):
        lines += [f"mov rax, [rdi + {392 + k * 8}]", f"mov [rsp - {128 - k * 8}], rax"]
    for k in range(16):
        lines.append(f"movdqu xmm{k}, XMMWORD PTR [rdi + {136 + k * 16}]")
    lines += ["lea rsp, [rsp - 128]", "push QWORD PTR [rdi + 128]", "popfq", "lea rsp, [rsp + 128]", "mov rdx, rdi"]
    for k, register in enumerate(names):
        if register not in ("rsp", "rdx"):
            lines.append(f"mov {register}, [rdx + {k * 8}]")
    lines += ["mov rdx, [rdx + 16]", body]
    for k, register in enumerate(names):
        lines.append(f"mov [rsp + {k * 8}], {register}")
    lines += ["lea rsp, [rsp - 128]", "pushfq", "pop QWORD PTR [rsp + 256]", "lea rsp, [rsp + 128]"]
    for k in range(16):
        lines.append(f"movdqu XMMWORD PTR [rsp + {136 + k * 16}], xmm{k}")
    for k in range(16):
        lines += [f"mov rax, [rsp - {128 - k * 8}]", f"mov [rsp + {392 + k * 8}], rax"]
    lines += ["cld", "mov rdi, [rsp + 776]", "mov rsi, rsp", "mov ecx, 65", "rep movsq", "lea rsp, [rsp + 1032]"]
    for register in ("r15", "r14", "r13", "r12", "rbp", "rbx"):
        lines.append(f"pop {register}")
    return "\n".join(lines + ["ret", f".size {name}, .-{name}"]) + "\n"


def generate(directory: pathlib.Path) -> pathlib.Path:
    import iced_x86 as ix
    from static_penryn import lower
    from static_penryn.checked import constants

    def as_register(value: int) -> ix.Register_:
        # iced's Register type is a plain int at runtime (ix.Register_ is int).
        if not isinstance(value, ix.Register_):
            raise TypeError(f"not a register: {value!r}")
        return value

    register_names = constants(ix.Register)
    names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"] + [f"r{i}" for i in range(8, 16)]
    registers = [as_register(register_names[n.upper()]) for n in names]
    xmms = [as_register(r) for r in range(ix.Register.XMM0, ix.Register.XMM15 + 1)]
    formatter = ix.Formatter(ix.FormatterSyntax.INTEL)
    formatter.hex_prefix, formatter.hex_suffix = "0x", ""
    formatter.uppercase_hex = False
    cases: list[tuple[ix.Instruction, str]] = []
    codes = [(ix.Code.POPCNT_R16_RM16, 2, 2), (ix.Code.POPCNT_R32_RM32, 4, 4),
             (ix.Code.POPCNT_R64_RM64, 8, 8), (ix.Code.CRC32_R32_RM8, 4, 1),
             (ix.Code.CRC32_R32_RM16, 4, 2), (ix.Code.CRC32_R32_RM32, 4, 4),
             (ix.Code.CRC32_R64_RM8, 8, 1), (ix.Code.CRC32_R64_RM64, 8, 8)]

    def sized(register: ix.Register_, size: int) -> ix.Register_:
        name = lower._reg(register, size).upper()
        if name.startswith("R") and name.endswith("B"):
            name = name[:-1] + "L"
        return as_register(register_names[name])

    def add(ins: ix.Instruction, mode: str = "register") -> None:
        # Normalize synthetic instructions exactly as the patcher's decoder does.
        encoder = ix.Encoder(64)
        encoder.encode(ins, 0x2000000)
        decoded = ix.Decoder(64, encoder.take_buffer(), ip=0x2000000).decode()
        if decoded.is_invalid:
            return  # For example, AH with a REX destination has no encoding.
        cases.append((decoded, mode))

    for code, dst_size, src_size in codes:
        for destination in registers:
            if destination == ix.Register.RSP:
                continue
            for source in registers:
                add(ix.Instruction.create_reg_reg(code, sized(destination, dst_size), sized(source, src_size)))
            if src_size == 1 and destination in registers[:8]:
                for source in (ix.Register.AH, ix.Register.CH, ix.Register.DH, ix.Register.BH):
                    # CRC32 r64 requires REX.W and cannot encode high-byte sources.
                    if dst_size == 4:
                        add(ix.Instruction.create_reg_reg(code, sized(destination, dst_size), source))
            for mode, operand in [
                ("base", ix.MemoryOperand(ix.Register.RDI)),
                ("indexed", ix.MemoryOperand(ix.Register.RDI, ix.Register.RCX, 4, -8, 1)),
                ("stack", ix.MemoryOperand(ix.Register.RSP, displ=-16, displ_size=1)),
                ("rip", ix.MemoryOperand(ix.Register.RIP, displ=0x4000000, displ_size=4)),
            ]:
                add(ix.Instruction.create_reg_mem(code, sized(destination, dst_size), operand), mode)
    for destination in xmms:
        for source in xmms:
            add(ix.Instruction.create_reg_reg(ix.Code.PCMPGTQ_XMM_XMMM128, destination, source))
        for mode, operand in [
            ("base", ix.MemoryOperand(ix.Register.RDI)),
            ("indexed", ix.MemoryOperand(ix.Register.RDI, ix.Register.RCX, 4, -8, 1)),
            ("stack", ix.MemoryOperand(ix.Register.RSP, displ=-16, displ_size=1)),
            ("rip", ix.MemoryOperand(ix.Register.RIP, displ=0x4000000, displ_size=4)),
        ]:
            add(ix.Instruction.create_reg_mem(ix.Code.PCMPGTQ_XMM_XMMM128, destination, operand), mode)

    wrapper = state_wrapper

    assembly = [".intel_syntax noprefix\n.text\n"]
    manifest: list[dict[str, object]] = []
    dead = frozenset(r for r in registers if r != ix.Register.RSP)
    variants = [(True, frozenset()), (False, frozenset()), (True, dead), (False, dead)]
    all_xmms = frozenset(range(ix.Register.XMM0, ix.Register.XMM15 + 1))
    configurations: list[tuple[ix.Instruction, str, bool, frozenset[int], frozenset[int]]] = [
        (ins, mode, flags, dead, frozenset())
        for ins, mode in cases for flags, dead in variants]
    configurations += [(ins, mode, flags, dead_regs, all_xmms)
                       for ins, mode in cases if ins.mnemonic == ix.Mnemonic.PCMPGTQ
                       for flags, dead_regs in ((True, frozenset()), (False, dead))]
    for index, (ins, mode, preserve_flags, dead_registers, dead_xmms) in enumerate(configurations):
        if ins.op1_kind == ix.OpKind.MEMORY:
            native = lower.memory_load(ins, lower.reg_name(ins.op0_register), mnemonic=formatter.format_mnemonic(ins))
        else:
            native = formatter.format(ins)
        assembly += [wrapper(f"native_{index}", native), wrapper(f"lowered_{index}", lower.lower(
            ins, preserve_flags=preserve_flags, dead_registers=dead_registers, dead_xmms=dead_xmms))]
        manifest.append({"instruction": formatter.format(ins), "mode": mode,
                         "preserve_flags": preserve_flags,
                         "dead_slots": [k for k, r in enumerate(registers)
                                        if r in dead_registers and r != ix.RegisterExt.full_register(ins.op0_register)]
                                       + [17 + (r - ix.Register.XMM0) * 2 + half
                                          for r in sorted(dead_xmms) if r != ins.op0_register for half in (0, 1)]})
    assembly.append(lower.support_assembly())
    assembly.append('.section .testdata,"aw"\n.balign 16\n.global test_memory\ntest_memory:\n.zero 64\n.section .note.GNU-stack,"",@progbits\n')
    source_file = directory / "lower_test.s"
    source_file.write_text("".join(assembly))
    library = directory / "lower_test.so"
    subprocess.run(["cc", "-shared", "-nostdlib", "-Wl,--section-start=.testdata=0x4000000", "-o", str(library), str(source_file)], check=True)
    library.with_suffix(".json").write_text(json.dumps(manifest))
    return library


class Arguments(argparse.Namespace):
    remote: str | None
    run: pathlib.Path | None
    iterations: int


def main() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", help="SSH host with real SSE4.2/POPCNT hardware")
    parser.add_argument("--run", type=pathlib.Path, help=argparse.SUPPRESS)
    parser.add_argument("--iterations", type=int, default=40)
    args = parser.parse_args(namespace=Arguments())
    if args.run:
        worker(args.run, args.iterations)
        return
    with tempfile.TemporaryDirectory(prefix="static-penryn-test-") as temporary:
        library = generate(pathlib.Path(temporary))
        if args.remote:
            remote = subprocess.check_output(["ssh", args.remote, "mktemp -d /tmp/static-penryn-lower.XXXXXXXX"], text=True).strip()
            try:
                subprocess.run(["scp", "-q", str(library), str(library.with_suffix(".json")), __file__, f"{args.remote}:{remote}/"], check=True)
                subprocess.run(["ssh", args.remote, "python3", f"{remote}/test_lower.py", "--run", f"{remote}/lower_test.so", "--iterations", str(args.iterations)], check=True)
            finally:
                subprocess.run(["ssh", args.remote, "rm -rf -- " + shlex.quote(remote)], check=True)
        else:
            worker(library, args.iterations)


if __name__ == "__main__":
    main()
