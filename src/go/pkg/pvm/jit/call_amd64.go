//go:build linux && amd64

package jit

/*
#include "signal_handler.h"
*/
import "C"
import (
	"jam/pkg/pvm/jit/asm"
	"unsafe"
)

func init() {
	// Install JIT signal handler (one-time global setup)
	if C.jit_install_handler() < 0 {
		panic("failed to initialize JIT signal handler")
	}
}

// SetCodeRegion tells the signal handler the bounds of JIT code
func SetCodeRegion(start, end uintptr) {
	C.jit_set_region(C.uintptr_t(start), C.uintptr_t(end))
}

// SetRecoveryAddr sets the address to jump to on fault
func SetRecoveryAddr(addr uintptr) {
	C.jit_set_recovery(C.uintptr_t(addr))
}

// CheckAndClearFault checks if a fault occurred and clears the flag
func CheckAndClearFault() bool {
	return C.jit_clear_fault() != 0
}

// ErrSignalHandlerFailed is returned when signal handler installation fails
var ErrSignalHandlerFailed = &signalError{"failed to install signal handler"}

type signalError struct {
	msg string
}

func (e *signalError) Error() string {
	return e.msg
}

// callJITCode calls JIT-compiled code with System V AMD64 ABI
// entryPoint: address of compiled code
// statePtr: pointer to State struct (passed in RDI)
// Returns: exitReason (RAX), nextPC (RDX)
func callJITCode(entryPoint uintptr, statePtr unsafe.Pointer) (exitReason uint64, nextPC uint64) {
	// Use pure Go assembly trampoline from asm package to avoid cgo overhead
	return asm.CallJITCode(entryPoint, uintptr(statePtr))
}
