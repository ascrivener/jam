//go:build !linux || !amd64

package pvm

import "jam/pkg/pvm/jit"

// ExecutionMode determines how the PVM executes code
type ExecutionMode int

const (
	ModeInterpreter ExecutionMode = iota // Safe, debuggable
	ModeJIT                              // Fast, production (not available on this platform)
)

// GetExecutionMode always returns interpreter mode on non-Linux platforms
// JIT is only available on linux/amd64
func GetExecutionMode() ExecutionMode {
	// Ignore PVM_MODE environment variable - JIT is not available on this platform
	return ModeInterpreter
}

// CompileForJIT is a no-op on non-Linux platforms
func (pvm *PVM) CompileForJIT() (*jit.ProgramContext, error) {
	return nil, nil
}

// RunJIT is unreachable on non-Linux platforms since GetExecutionMode() always returns ModeInterpreter
// This stub exists only to satisfy the compiler
func RunJIT[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	panic("RunJIT should never be called on non-Linux platforms")
}
