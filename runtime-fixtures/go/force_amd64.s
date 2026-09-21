#include "textflag.h"

TEXT ·forcedPopcnt(SB), NOSPLIT, $0-16
    MOVQ value+0(FP), AX
    POPCNTQ AX, AX
    MOVQ AX, ret+8(FP)
    RET
