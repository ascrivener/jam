package pvm

import "jam/pkg/types"

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
	Parameter types.Register
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
