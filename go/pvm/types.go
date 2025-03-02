package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/ram"
)

type Register uint64

type SimpleExitReasonType int

const (
	ExitGo       SimpleExitReasonType = iota
	ExitHalt                          // ∎: regular halt
	ExitPanic                         // ☇: panic
	ExitOutOfGas                      // ∞: out-of-gas
)

type ComplexExitReasonType int

const (
	ExitHostCall  ComplexExitReasonType = iota // ̵h: host-call (with associated identifier)
	ExitPageFault                              // F: page-fault (with associated ram address)
)

type ComplexExitReason struct {
	Type      ComplexExitReasonType
	Parameter Register
}

type ExitReason struct {
	SimpleExitReason  *SimpleExitReasonType
	ComplexExitReason *ComplexExitReason
}

// NewSimpleExitReason creates an ExitReason representing a simple exit.
// It sets only the SimpleExitReason field.
func NewSimpleExitReason(reason SimpleExitReasonType) ExitReason {
	return ExitReason{
		SimpleExitReason:  &reason,
		ComplexExitReason: nil,
	}
}

// NewComplexExitReason creates an ExitReason representing a complex exit.
// It sets only the ComplexExitReason field.
func NewComplexExitReason(reasonType ComplexExitReasonType, parameter Register) ExitReason {
	return ExitReason{
		SimpleExitReason: nil,
		ComplexExitReason: &ComplexExitReason{
			Type:      reasonType,
			Parameter: parameter,
		},
	}
}

func (er ExitReason) IsSimple() bool {
	return er.SimpleExitReason != nil
}

func (er ExitReason) IsComplex() bool {
	return er.ComplexExitReason != nil
}

type ExecutionErrorType int

const (
	ExecutionErrorOutOfGas ExecutionErrorType = iota
	ExecutionErrorPanic
	ExecutionErrorInvalidNumExports
	ExecutionErrorBAD
	ExecutionErrorBIG
)

type ExecutionExitReason struct {
	ExecutionError *ExecutionErrorType
	Blob           *[]byte
}

func NewExecutionExitReasonError(reason ExecutionErrorType) ExecutionExitReason {
	return ExecutionExitReason{
		ExecutionError: &reason,
		Blob:           nil,
	}
}

func NewExecutionExitReasonBlob(blob []byte) ExecutionExitReason {
	return ExecutionExitReason{
		ExecutionError: nil,
		Blob:           &blob,
	}
}

func (er ExecutionExitReason) IsError() bool {
	return er.ExecutionError != nil
}

type Arguments []byte

func NewArguments(value []byte) (a Arguments, e error) {
	if len(value) >= ram.ArgumentsZoneSize {
		return a, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return Arguments(value), nil
}
