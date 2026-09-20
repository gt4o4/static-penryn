#!/usr/bin/env python3
"""Benchmark old/new lowered PCMPxSTRx paths, with no unsupported opcode.

  python bench_strings.py --baseline /path/to/old/strings-sources --json result.json

The baseline directory must contain an earlier strings.py and strings.c.
This benchmark executes only scalar/SSE2 generated code, so it can run on
Penryn without using opemu as either a reference or a performance oracle.
It measures repeated calls with fixed inputs, not application performance.
"""
import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import resource
import statistics
import subprocess
import tempfile
import time

from iced_x86 import Decoder

import strings
from test_strings import machine


CASES = (("explicit_ranges", 2, 4), ("explicit_negative_ranges", 2, 20),
         ("explicit_ordered", 2, 12), ("implicit_each", 0, 8),
         ("implicit_any", 0, 0), ("explicit_expanded_mask", 3, 64),
         ("wide_ordered", 4, 12))


def build(directory, baseline, core):
    spec = importlib.util.spec_from_file_location("baseline_strings", baseline / "strings.py")
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    asm = [".intel_syntax noprefix", ".text"]
    instructions = []
    for case, form, control in CASES:
        ins = Decoder(64, machine(form, control)).decode()
        instructions.append(ins)
        for version, lowering in (("baseline", old.lower), ("specialized", strings.lower)):
            name = version + "_" + case
            body = lowering(ins)
            if version == "baseline":
                body = body.replace("call sse42emu_", "call baseline_sse42emu_")
            asm += [f".global {name}", f"{name}:", "push rbx", "mov rbx, rdi",
                    f".L{name}:", "movdqu xmm0, [rsi]", "movdqu xmm1, [rsi + 16]",
                    "mov eax, 12", "mov edx, 15", body,
                    "dec rbx", f"jnz .L{name}", "pop rbx", "ret"]
    asm += ['.section .note.GNU-stack,"",@progbits']
    assembly = directory / "bench.S"
    assembly.write_text("\n".join(asm) + "\n")
    new_obj, report = strings.build_helpers(instructions, core, directory)
    baseline_obj = directory / "baseline.o"
    subprocess.run([
        "cc", "-O2", "-march=core2", "-fPIC", "-ffreestanding", "-fno-stack-protector",
        "-mno-red-zone", "-ffunction-sections", "-fdata-sections",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-fvisibility=hidden",
        "-I" + str(core), "-c", str(baseline / "strings.c"), "-o", str(baseline_obj),
    ], check=True)
    subprocess.run(["objcopy", "--prefix-symbols=baseline_", str(baseline_obj)], check=True)
    library = directory / "bench.so"
    subprocess.run(["cc", "-shared", "-nostdlib", "-Wl,--gc-sections,--no-undefined",
                    str(assembly), str(new_obj), str(baseline_obj), "-o", str(library)], check=True)
    return library, report


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--core", type=Path,
                        default=Path(__file__).resolve().parents[3] / "submodules/opemu-linux/core")
    parser.add_argument("--iterations", type=int, default=300000)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if min(args.iterations, args.samples) < 1:
        parser.error("iterations and samples must be positive")
    directory = Path(tempfile.mkdtemp(prefix="static-penryn-strings-bench."))
    library, helper_report = build(directory, args.baseline.resolve(), args.core.resolve())
    lib = ctypes.CDLL(str(library))
    # Equal and differing bytes, plus low/high range bounds; no zero byte.
    data = ctypes.create_string_buffer(b"abcdefghijklmnopabxcdefzhijklmnq", 32)
    report = {"artifacts": str(directory), "iterations": args.iterations,
              "samples": args.samples, "helpers": helper_report, "cases": {}}
    for case, _, _ in CASES:
        funcs = {kind: getattr(lib, kind + "_" + case) for kind in ("baseline", "specialized")}
        for func in funcs.values():
            func.argtypes = [ctypes.c_uint64, ctypes.c_void_p]
            func.restype = None
            func(10000, data)
        timings = {kind: [] for kind in funcs}
        for sample in range(args.samples):
            # Alternate ordering to reduce drift from load/frequency changes.
            order = list(funcs) if sample % 2 == 0 else list(reversed(funcs))
            for kind in order:
                start = time.perf_counter_ns()
                funcs[kind](args.iterations, data)
                timings[kind].append((time.perf_counter_ns() - start) / args.iterations)
        medians = {kind + "_ns": statistics.median(values) for kind, values in timings.items()}
        medians["speedup"] = medians["baseline_ns"] / medians["specialized_ns"]
        report["cases"][case] = {**medians, "samples_ns": timings}
        print(f"{case}: {medians['baseline_ns']:.2f} -> {medians['specialized_ns']:.2f} ns "
              f"({medians['speedup']:.2f}x)", flush=True)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Artifacts: {directory}")


if __name__ == "__main__":
    main()
