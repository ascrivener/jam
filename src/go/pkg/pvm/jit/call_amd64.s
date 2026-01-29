// +build amd64

#include "textflag.h"

// func callJITCode(entryPoint uintptr, statePtr unsafe.Pointer) (exitReason uint64, nextPC uint64)
// Uses stack-based calling convention (go:noescape forces this)
TEXT ·callJITCode(SB), NOSPLIT, $0-32
    // Load arguments from stack (stack-based ABI)
    MOVQ entryPoint+0(FP), R11   // R11 = entryPoint
    MOVQ statePtr+8(FP), DI      // DI = statePtr (System V first arg)
    
    // Call the JIT code
    CALL R11
    
    // JIT returns:
    //   AX = exitReason
    //   DX = nextPC
    MOVQ AX, ret+16(FP)
    MOVQ DX, ret1+24(FP)
    RET
