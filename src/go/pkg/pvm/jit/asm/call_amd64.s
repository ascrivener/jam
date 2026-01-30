//go:build amd64

#include "textflag.h"

// func CallJITCode(entryPoint uintptr, statePtr uintptr) (exitReason uint64, nextPC uint64)
// This is a pure Go assembly trampoline that calls JIT code directly,
// avoiding cgo overhead entirely.
//
// Go calling convention (register ABI):
//   - entryPoint in AX
//   - statePtr in BX
//   - Returns: exitReason in AX, nextPC in BX
//
// JIT calling convention (System V AMD64 ABI):
//   - statePtr in RDI
//   - Returns: exitReason in RAX, nextPC in RDX
TEXT ·CallJITCode(SB), NOSPLIT, $0-32
	// Load arguments
	MOVQ	entryPoint+0(FP), R12	// entry point (callee-saved)
	MOVQ	statePtr+8(FP), DI	// state -> RDI (first arg for JIT)

	// Save callee-saved registers that JIT might clobber
	PUSHQ	BP
	PUSHQ	BX
	PUSHQ	R13
	PUSHQ	R14
	PUSHQ	R15

	// Call JIT code
	CALL	R12

	// Restore callee-saved registers
	POPQ	R15
	POPQ	R14
	POPQ	R13
	POPQ	BX
	POPQ	BP

	// Return values: RAX = exit reason, RDX = next PC
	MOVQ	AX, exitReason+16(FP)
	MOVQ	DX, nextPC+24(FP)
	RET
