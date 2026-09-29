#!/usr/bin/env python3
"""Compare static PCMPxSTRx lowerings with SSE4.2 hardware.

    python -m tests.test_strings --remote lix-ory

Generation needs iced-x86 and a local C compiler; the remote machine needs
only Python and native SSE4.2.  Do not use an opemu-enabled Penryn as the
oracle: it executes the same arithmetic core on both sides.  --run is the
stdlib-only worker copied to the remote host.  Temporary artifacts are kept
to make a failure inspectable.
"""

import argparse
import ctypes
from pathlib import Path
import random
import resource
import shlex
import subprocess
import tempfile


GPRS = ("rax", "rcx", "rdx", "rbp", "rsi", "rdi", "r8", "r9",
        "r10", "r11", "r12", "r13", "r14", "r15")
XMM = 128
FLAGS = 384
REDZONE = 400
STATE_SIZE = 528
CONTROLS = (0, 1, 4, 8, 12, 16, 18, 32, 48, 64, 127, 255)
LENGTHS = (-(1 << 63), -(1 << 32), -(1 << 31), -17, -16, -9, -8,
           -1, 0, 1, 7, 8, 9, 15, 16, 17, 1 << 31, 1 << 32, (1 << 63) - 1)


def machine(form, imm, shape="ordinary"):
    """Six length/output forms, with five source/destination shapes."""
    opcode = (0x63, 0x62, 0x61, 0x60, 0x61, 0x60)[form]
    dest, src = {"ordinary": (0, 1), "high": (13, 15),
                 "alias": (0, 0), "memory": (7, 6),
                 "stack": (14, 4), "scratch_alias": (12, 12),
                 "scratch_memory": (12, 6)}[shape]
    rex = 0x40 | (8 if form >= 4 else 0) | (4 if dest >= 8 else 0)
    if shape not in ("memory", "scratch_memory", "stack") and src >= 8:
        rex |= 1
    code = [0x66] + ([rex] if rex != 0x40 else []) + [0x0f, 0x3a, opcode]
    if shape in ("memory", "scratch_memory"):
        code += [0x46 | ((dest & 7) << 3), 1]  # [rsi + 1], unaligned
    elif shape == "stack":
        code += [0x44 | ((dest & 7) << 3), 0x24, 0xc0]  # [rsp - 64]
    else:
        code += [0xc0 | ((dest & 7) << 3) | (src & 7)]
    return bytes(code + [imm])


def generate(directory, core):
    # Deferred so a hardware worker has no third-party Python dependency.
    from iced_x86 import Decoder
    from static_penryn.strings import build_helpers, lower

    lines = [".intel_syntax noprefix", ".text"]
    instructions = []
    for form in range(6):
        for imm in range(256):
            raw = machine(form, imm)
            instruction = Decoder(64, raw).decode()
            instructions.append(instruction)
            for kind in ("native", "static"):
                name = f"{kind}_{form}_{imm}"
                lines += [f".global {name}", f"{name}:", "push rbx", "mov rbx, r8",
                          "mov rax, rdx", "mov rdx, rcx", "movdqu xmm0, [rdi]",
                          "movdqu xmm1, [rsi]", "push 0x602", "popfq"]
                lines += [".byte " + ",".join(hex(x) for x in raw)
                          if kind == "native" else lower(instruction)]
                lines += ["pushfq", "pop r9", "cld", "mov [rbx], rcx",
                          "movdqu [rbx + 8], xmm0", "mov [rbx + 24], r9", "pop rbx", "ret"]

    # Full register/red-zone snapshots with high, aliased, unaligned memory
    # and original-RSP-relative operands.  RSP/RBX are the wrapper's stack
    # and state pointer; correct return and captures also check their survival.
    for form in range(6):
        for imm in CONTROLS:
            for shape in ("high", "alias", "memory", "stack", "scratch_alias", "scratch_memory"):
                raw = machine(form, imm, shape)
                instruction = Decoder(64, raw).decode()
                for kind in ("native", "static"):
                    name = f"state_{kind}_{form}_{imm}_{shape}"
                    lines += [f".global {name}", f"{name}:"]
                    lines += [f"push {reg}" for reg in ("rbx", "rbp", "r12", "r13", "r14", "r15")]
                    lines += ["mov rbx, rdi", f"push QWORD PTR [rbx + {FLAGS}]", "popfq"]
                    for i in range(8):
                        lines += [f"movdqu xmm0, [rbx + {REDZONE + i * 16}]",
                                  f"movdqu [rsp - {128 - i * 16}], xmm0"]
                    lines += [f"movdqu xmm{i}, [rbx + {XMM + i * 16}]" for i in range(16)]
                    lines += [f"mov {reg}, [rbx + {i * 8}]" for i, reg in enumerate(GPRS)]
                    lines += [".byte " + ",".join(hex(x) for x in raw)
                              if kind == "native" else lower(instruction)]
                    lines += [f"mov [rbx + {i * 8}], {reg}" for i, reg in enumerate(GPRS)]
                    lines += ["lea rsp, [rsp - 128]", "pushfq",
                              f"pop QWORD PTR [rbx + {FLAGS}]", "lea rsp, [rsp + 128]"]
                    lines += [f"movdqu [rbx + {XMM + i * 16}], xmm{i}" for i in range(16)]
                    for i in range(8):
                        lines += [f"movdqu xmm0, [rsp - {128 - i * 16}]",
                                  f"movdqu [rbx + {REDZONE + i * 16}], xmm0"]
                    lines += ["cld"]
                    lines += [f"pop {reg}" for reg in ("r15", "r14", "r13", "r12", "rbp", "rbx")]
                    lines += ["ret"]
    lines += ['.section .note.GNU-stack,"",@progbits']
    assembly = directory / "checks.s"
    assembly.write_text("\n".join(lines) + "\n")
    helper, report = build_helpers(instructions, core, directory)
    print(f"Specialized helpers: {len(report["specializations"])}, "
          f"maximum stack: {report["max_stack_bytes"]} bytes", flush=True)
    library = directory / "checks.so"
    subprocess.run(["cc", "-shared", "-nostdlib", "-Wl,--gc-sections,--no-undefined",
                    str(assembly), str(helper), "-o", str(library)], check=True)
    return library


def run(library, iterations):
    flags = Path("/proc/cpuinfo").read_text().split("flags", 1)[1].split("\n", 1)[0]
    if "sse4_2" not in flags.split():
        raise SystemExit("Hardware oracle requires native SSE4.2; refusing an opemu-only CPU")
    lib = ctypes.CDLL(str(library))
    rng = random.Random(13)
    count = 0
    for form in range(6):
        for imm in range(256):
            funcs = [getattr(lib, f"{kind}_{form}_{imm}") for kind in ("native", "static")]
            for func in funcs:
                func.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64,
                                 ctypes.c_int64, ctypes.c_void_p]
                func.restype = None
            for case in range(iterations):
                a, b = (bytes(rng.randrange(8 if case % 2 else 256) for _ in range(16)) for _ in range(2))
                la, lb = rng.choice(LENGTHS), rng.choice(LENGTHS)
                observed = []
                for func in funcs:
                    result = ctypes.create_string_buffer(32)
                    func(a, b, la, lb, result)
                    data = bytes(result)
                    observed.append((data[:24], int.from_bytes(data[24:], "little") & 0xed5))
                if observed[0] != observed[1]:
                    raise AssertionError((form, imm, case, a.hex(), b.hex(), la, lb, observed))
                count += 1
    print(f"PCMPxSTRx native arithmetic comparisons: {count}", flush=True)

    count = 0
    memory = ctypes.create_string_buffer(32)
    for form in range(6):
        for imm in CONTROLS:
            for shape in ("high", "alias", "memory", "stack", "scratch_alias", "scratch_memory"):
                funcs = [getattr(lib, f"state_{kind}_{form}_{imm}_{shape}") for kind in ("native", "static")]
                for func in funcs:
                    func.argtypes = [ctypes.c_void_p]
                    func.restype = None
                for case in range(iterations):
                    initial = bytearray(rng.randbytes(STATE_SIZE))
                    for index in (0, 2):  # RAX, RDX: signed length boundaries
                        value = rng.choice(LENGTHS) & ((1 << 64) - 1)
                        initial[index * 8:index * 8 + 8] = value.to_bytes(8, "little")
                    memory.raw = rng.randbytes(32)
                    initial[32:40] = ctypes.addressof(memory).to_bytes(8, "little")  # RSI
                    initial[FLAGS:FLAGS + 8] = (0x602 | (rng.randrange(4096) & 0x8d5)).to_bytes(8, "little")
                    observed = []
                    for func in funcs:
                        state = ctypes.create_string_buffer(bytes(initial), STATE_SIZE)
                        func(state)
                        observed.append(bytes(state))
                    if observed[0] != observed[1]:
                        diff = [i for i in range(STATE_SIZE) if observed[0][i] != observed[1][i]]
                        raise AssertionError(("state", form, imm, shape, case, diff))
                    count += 1
    print(f"PCMPxSTRx full GPR/XMM/flags/red-zone comparisons: {count}", flush=True)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", help="native SSE4.2 SSH host, e.g. lix-ory")
    parser.add_argument("--core", type=Path, help="opemu-linux/core checkout directory")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    if args.run:
        run(args.run, args.iterations)
        return
    if args.core is None:
        from static_penryn.patch import OPEMU_CORE
        args.core = OPEMU_CORE
    directory = Path(tempfile.mkdtemp(prefix="static-penryn-strings."))
    library = generate(directory, args.core)
    print(f"Artifacts: {directory}", flush=True)
    if not args.remote:
        run(library, args.iterations)
        return
    remote_dir = subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", args.remote,
         "mktemp -d /tmp/static-penryn-strings.XXXXXX"], text=True).strip()
    subprocess.run(["scp", str(library), str(Path(__file__).resolve()),
                    f"{args.remote}:{remote_dir}/"], check=True)
    command = ["python3", remote_dir + "/test_strings.py", "--run", remote_dir + "/checks.so",
               "--iterations", str(args.iterations)]
    subprocess.run(["ssh", "-o", "BatchMode=yes", args.remote, shlex.join(command)], check=True)
    print(f"Remote artifacts: {args.remote}:{remote_dir}")


if __name__ == "__main__":
    main()
