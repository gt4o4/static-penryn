#!/usr/bin/env python3
"""Measure generated leaf sequences on the target CPU, without an emulator.

  python bench_lower.py --baseline /path/to/old/lower.py --output /tmp/bench.json

Each timed call runs a million lowerings in a native assembly loop. Reports
include loop overhead and save/restore cost; they are microbenchmarks rather
than application performance predictions. No unsupported opcode is executed.
"""

import argparse
import ctypes
import importlib.util
import json
import pathlib
import resource
import statistics
import subprocess
import tempfile
import time


def generate(directory, baseline):
    import iced_x86 as ix
    import lower

    variants = [("preserved", lower.lower, {}),
                ("flags_dead", lower.lower, {"preserve_flags": False}),
                ("scratch_dead", lower.lower, {"preserve_flags": False,
                    "dead_registers": frozenset((ix.Register.R8, ix.Register.R9, ix.Register.R10))})]
    if baseline:
        spec = importlib.util.spec_from_file_location("baseline", baseline)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        variants.insert(0, ("baseline", old.lower, {}))
    samples = [
        ("popcnt32_sparse", ix.Code.POPCNT_R32_RM32, ix.Register.EAX, ix.Register.EBX, 0x4001),
        ("popcnt32_dense", ix.Code.POPCNT_R32_RM32, ix.Register.EAX, ix.Register.EBX, 0xAAAAAAAA),
        ("popcnt64_sparse", ix.Code.POPCNT_R64_RM64, ix.Register.RAX, ix.Register.RBX, 0x400000001),
        ("popcnt64_dense", ix.Code.POPCNT_R64_RM64, ix.Register.RAX, ix.Register.RBX, 0xAAAAAAAAAAAAAAAA),
        ("crc32_byte", ix.Code.CRC32_R32_RM8, ix.Register.EAX, ix.Register.BL, 0x9D),
        ("crc32_dword", ix.Code.CRC32_R32_RM32, ix.Register.EAX, ix.Register.EBX, 0xE7BC579D),
        ("crc32_qword", ix.Code.CRC32_R64_RM64, ix.Register.RAX, ix.Register.RBX, 0x921CF585E7BC579D),
        ("pcmpgtq", ix.Code.PCMPGTQ_XMM_XMMM128, ix.Register.XMM0, ix.Register.XMM1, 0),
    ]
    assembly = [".intel_syntax noprefix\n.text\n"]
    manifest = []
    for name, code, dst, src, seed in samples:
        ins = ix.Instruction.create_reg_reg(code, dst, src)
        for variant, lowering, options in variants:
            function = f"bench_{name}_{variant}"
            lines = [f".global {function}", f".type {function}, @function", f"{function}:",
                     "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
                     "mov r12, rdi", f"mov rbx, 0x{seed:x}", "mov eax, 0x1658432a",
                     "pxor xmm0, xmm0", "pcmpeqd xmm1, xmm1", ".balign 32", f".L{function}_loop:",
                     lowering(ins, **options), "dec r12", f"jnz .L{function}_loop",
                     "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx", "ret",
                     f".size {function}, .-{function}"]
            assembly.append("\n".join(lines) + "\n")
            manifest.append({"case": name, "variant": variant, "function": function})
    assembly += [lower.support_assembly(), '.section .note.GNU-stack,"",@progbits\n']
    source = directory / "bench.s"
    library = directory / "bench.so"
    source.write_text("".join(assembly))
    subprocess.run(["cc", "-shared", "-nostdlib", "-o", str(library), str(source)], check=True)
    return library, manifest


def measure(library, manifest, iterations, repeats):
    lib = ctypes.CDLL(str(library.resolve()))
    results = []
    for case in manifest:
        function = getattr(lib, case["function"])
        function.argtypes, function.restype = [ctypes.c_uint64], ctypes.c_uint64
        function(min(iterations, 10000))
        samples = []
        for _ in range(repeats):
            start = time.perf_counter_ns()
            function(iterations)
            samples.append((time.perf_counter_ns() - start) / iterations)
        result = {**case, "median_ns": statistics.median(samples), "min_ns": min(samples),
                  "samples_ns": samples}
        results.append(result)
        print(f"{case['case']:20} {case['variant']:14} {result['median_ns']:9.3f} ns/op", flush=True)
    return results


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=pathlib.Path)
    parser.add_argument("--iterations", type=int, default=1_000_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.iterations < 1 or args.repeats < 1:
        parser.error("iterations and repeats must be positive")
    with tempfile.TemporaryDirectory(prefix="static-penryn-bench-") as temporary:
        library, manifest = generate(pathlib.Path(temporary), args.baseline)
        results = measure(library, manifest, args.iterations, args.repeats)
    report = {"cpu": next((line.split(":", 1)[1].strip() for line in pathlib.Path('/proc/cpuinfo').read_text().splitlines()
                            if line.startswith('model name')), "unknown"),
              "iterations": args.iterations, "repeats": args.repeats, "results": results}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
