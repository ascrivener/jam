package pvm

type Register uint64

type RamAccess int

type RamIndex uint32

const (
	Immutable RamAccess = iota
	Mutable
	Inaccessible
)

type RAM struct {
	Value  [BytesInRam]byte
	Access [NumRamPages]RamAccess
}

func (r *RAM) accessForIndex(index RamIndex) RamAccess {
	return r.Access[RamIndex(index)/BytesInPage]
}

func (r *RAM) inspect(index Register, memoryAccessExceptionIndices []RamIndex) byte {
	ramIndex := RamIndex(index)
	if r.accessForIndex(ramIndex) == Inaccessible {
		memoryAccessExceptionIndices = append(memoryAccessExceptionIndices, ramIndex)
	}
	return r.Value[ramIndex]
}

func (r *RAM) inspectRange(start Register, count Register, memoryAccessExceptionIndices []RamIndex) []byte {
	result := make([]byte, count)
	for i := Register(0); i < count; i++ {
		ramIndex := RamIndex(start) + RamIndex(i)
		if r.accessForIndex(ramIndex) == Inaccessible {
			memoryAccessExceptionIndices = append(memoryAccessExceptionIndices, ramIndex)
		}
		result[i] = r.Value[ramIndex]
	}
	return result
}

func (r *RAM) mutate(index Register, newByte byte, memoryAccessExceptionIndices []RamIndex) {
	ramIndex := RamIndex(index)
	if r.accessForIndex(ramIndex) != Mutable {
		memoryAccessExceptionIndices = append(memoryAccessExceptionIndices, ramIndex)
	}
	r.Value[ramIndex] = newByte
}

func (r *RAM) mutateRange(start Register, newBytes []byte, memoryAccessExceptionIndices []RamIndex) {
	for i, newByte := range newBytes {
		ramIndex := RamIndex(start) + RamIndex(i)
		if r.accessForIndex(ramIndex) != Mutable {
			memoryAccessExceptionIndices = append(memoryAccessExceptionIndices, ramIndex)
		}
		r.Value[ramIndex] = newByte
	}
}

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
