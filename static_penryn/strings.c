/* SPDX-License-Identifier: MIT */
/* Arithmetic is compiled from the separately maintained, hardware-tested
 * opemu core.  This brings no decoder, signal handler or run-time dependency
 * into the patched executable.  The generated translation unit instantiates
 * PENRYN_HELPER once per used control/length/output combination.  Flattening
 * makes these leaf functions and removes runtime control-byte dispatch.
 *
 * -mgeneral-regs-only confines compiler allocation to GPRs: only the core's
 * explicit SSE2 asm can touch XMM registers, and it uses xmm12..xmm15.  The
 * object audit in strings.py enforces the leaf/register/stack contract before
 * a smaller trampoline frame can be used.  --gc-sections discards the unused
 * generic core entry points and their unrelated arithmetic/data.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define memset __builtin_memset
#include "emu-core.c"

struct penryn_string_frame {
    uint8_t a[16], b[16], mask[16];
    uint32_t index, padding;
    uint64_t flags;
    int64_t la, lb;
};
_Static_assert(sizeof(struct penryn_string_frame) == 80, "trampoline frame ABI");
_Static_assert(offsetof(struct penryn_string_frame, flags) == 56, "flags ABI");
_Static_assert(offsetof(struct penryn_string_frame, la) == 64, "length ABI");

static inline int32_t penryn_length(int64_t length, int mode)
{
    /* REX.W uses signed 64-bit lengths; saturating before narrowing handles
     * INT64_MIN without overflowing abs().  The core saturates words to 8. */
    if (mode == 2) {
        if (length > 16) return 16;
        if (length < -16) return -16;
    }
    return (int32_t) length;
}

#define PENRYN_HELPER(name, control, mode, masked)                         \
    __attribute__((flatten, visibility("hidden")))                         \
    void name(struct penryn_string_frame *frame)                          \
    {                                                                    \
        pcmpstr_core(frame->a, frame->b, control, (mode) != 0,              \
                     penryn_length(frame->la, mode),                      \
                     penryn_length(frame->lb, mode),                      \
                     (masked) ? NULL : &frame->index,                     \
                     (masked) ? frame->mask : NULL, &frame->flags);        \
    }
