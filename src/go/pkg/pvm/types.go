package pvm

import "jam/pkg/types"

type SimpleExitReasonType int

const (
	ExitGo       SimpleExitReasonType = iota
	ExitHalt                          // regular halt
	ExitPanic                         // panic
	ExitOutOfGas                      // out-of-gas
)

type ComplexExitReasonType int

const (
	ExitHostCall  ComplexExitReasonType = iota // host-call (with associated identifier)
	ExitPageFault                              // page-fault (with associated ram address)
)

type ComplexExitReason struct {
	Type      ComplexExitReasonType
	Parameter types.Register
}

type ExitReason struct {
	SimpleExitReason  *SimpleExitReasonType
	ComplexExitReason *ComplexExitReason
}

// Pre-allocated ExitReason constants to avoid heap allocations
var (
	ExitReasonGo       = ExitReason{SimpleExitReason: &[]SimpleExitReasonType{ExitGo}[0]}
	ExitReasonPanic    = ExitReason{SimpleExitReason: &[]SimpleExitReasonType{ExitPanic}[0]}
	ExitReasonHalt     = ExitReason{SimpleExitReason: &[]SimpleExitReasonType{ExitHalt}[0]}
	ExitReasonOutOfGas = ExitReason{SimpleExitReason: &[]SimpleExitReasonType{ExitOutOfGas}[0]}
)

// NewSimpleExitReason creates an ExitReason representing a simple exit.
// It sets only the SimpleExitReason field.
func NewSimpleExitReason(reason SimpleExitReasonType) ExitReason {
	// Use pre-allocated constants for common cases
	switch reason {
	case ExitGo:
		return ExitReasonGo
	case ExitPanic:
		return ExitReasonPanic
	case ExitHalt:
		return ExitReasonHalt
	case ExitOutOfGas:
		return ExitReasonOutOfGas
	default:
		panic("NewSimpleExitReason: invalid reason")
	}
}

// NewComplexExitReason creates an ExitReason representing a complex exit.
// It sets only the ComplexExitReason field.
func NewComplexExitReason(reasonType ComplexExitReasonType, parameter types.Register) ExitReason {
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
