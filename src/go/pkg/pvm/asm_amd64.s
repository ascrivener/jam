//go:build amd64

#include "textflag.h"

// func callCompiledCode(codePtr uintptr, ctx unsafe.Pointer) uint64
// Calls compiled JIT code at codePtr with ctx in RDI (System V AMD64 ABI)
TEXT ·callCompiledCode(SB), NOSPLIT, $0-24
    MOVQ codePtr+0(FP), AX    // Load code pointer into AX
    MOVQ ctx+8(FP), DI        // Load context pointer into DI (first arg in System V ABI)
    CALL AX                    // Call the compiled code
    MOVQ AX, ret+16(FP)       // Store return value
    RET
