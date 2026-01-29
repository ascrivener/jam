package jit

import "unsafe"

// callJITCode calls JIT-compiled code with System V AMD64 ABI
// entryPoint: address of compiled code
// statePtr: pointer to State struct (passed in RDI)
// Returns: exitReason (RAX), nextPC (RDX)
//
//go:noescape
func callJITCode(entryPoint uintptr, statePtr unsafe.Pointer) (exitReason uint64, nextPC uint64)
