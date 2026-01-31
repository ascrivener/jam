//go:build linux && amd64

// Package asm provides pure Go assembly routines for JIT execution.
// This is a separate package to avoid mixing cgo and Go assembly.
package asm

// CallJITCode calls JIT-compiled code directly without cgo overhead.
// entryPoint: address of compiled code
// statePtr: pointer to State struct (passed in RDI per System V ABI)
// Returns: exitReason (RAX), nextPC (RDX)
func CallJITCode(entryPoint uintptr, statePtr uintptr) (exitReason uint64, nextPC uint64)
