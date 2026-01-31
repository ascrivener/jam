//go:build !linux || !amd64

package pvm

import "jam/pkg/pvm/jit"

// ExecutionMode determines how the PVM executes code
type ExecutionMode int

const (
	ModeInterpreter ExecutionMode = iota // Safe, debuggable
	ModeJIT                              // Fast, production (not available on this platform)
)

// GetExecutionMode returns the current execution mode based on environment
// On non-Linux platforms, always returns interpreter mode
func GetExecutionMode() ExecutionMode {
	return ModeInterpreter
}

// CompileForJIT is a no-op on non-Linux platforms
func (pvm *PVM) CompileForJIT() (*jit.ProgramContext, error) {
	return nil, nil
}

// RunJIT falls back to interpreter on non-Linux platforms
func RunJIT[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	return runInterpreter(pvm, hostFunc, hostArg)
}
