package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
)

type Register uint64

type RamAccess int

type RamIndex uint32

const (
	Inaccessible RamAccess = iota
	Immutable
	Mutable
)

type RAM struct {
	Value           [RamSize]byte
	Access          [NumRamPages]RamAccess
	BeginningOfHeap *RamIndex // nil if no heap
}

func NewRAM(readData, writeData []byte, arguments Arguments, z, stackSize int) *RAM {
	heapStart := RamIndex(2*MajorZoneSize + TotalSizeNeededMajorZones(len(readData)))
	var beginningOfHeap *RamIndex
	if len(writeData)+int(z) > 0 { // then we actually have a heap
		beginningOfHeap = new(RamIndex)
		*beginningOfHeap = heapStart
	}
	ram := &RAM{
		Value:           [RamSize]byte{},
		Access:          [NumRamPages]RamAccess{},
		BeginningOfHeap: beginningOfHeap,
	}
	// read-only section
	ram.setSectionValue(readData, MajorZoneSize)
	ram.setSectionAccess(MajorZoneSize, RamIndex(TotalSizeNeededPages(len(readData))), Immutable)
	// heap
	ram.setSectionValue(writeData, heapStart)
	ram.setSectionAccess(heapStart, RamIndex(TotalSizeNeededPages(len(writeData))+z*PageSize), Mutable)
	// stack
	ram.setSectionAccess(RamIndex((1<<32)-2*MajorZoneSize-ArgumentsZoneSize-TotalSizeNeededPages(stackSize)), RamIndex(TotalSizeNeededPages(stackSize)), Mutable)
	// arguments
	ram.setSectionValue(arguments, RamIndex((1<<32)-MajorZoneSize-ArgumentsZoneSize))
	ram.setSectionAccess(RamIndex((1<<32)-MajorZoneSize-ArgumentsZoneSize), RamIndex(TotalSizeNeededPages(len(arguments))), Immutable)
	return ram
}

func (r *RAM) setSectionAccess(start, len RamIndex, access RamAccess) {
	firstPage := start / PageSize
	lastPage := (start + len - 1) / PageSize
	for i := firstPage; i <= lastPage; i++ {
		r.setAccessForIndex(i, access)
	}
}

func (r *RAM) setSectionValue(srcValues []byte, start RamIndex) {
	end := start + RamIndex(len(srcValues))
	copy(r.Value[start:end], srcValues[:end-start])
}

func (r *RAM) accessForIndex(index RamIndex) RamAccess {
	return r.Access[index/PageSize]
}

func (r *RAM) setAccessForIndex(index RamIndex, access RamAccess) {
	r.Access[index/PageSize] = access
}

func (r *RAM) inspect(index Register, memoryAccessExceptionIndices *[]RamIndex) byte {
	ramIndex := RamIndex(index)
	if r.accessForIndex(ramIndex) == Inaccessible {
		*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
	}
	return r.Value[ramIndex]
}

func (r *RAM) inspectRange(start Register, count Register, memoryAccessExceptionIndices *[]RamIndex) []byte {
	result := make([]byte, count)
	for i := Register(0); i < count; i++ {
		ramIndex := RamIndex(start) + RamIndex(i)
		if r.accessForIndex(ramIndex) == Inaccessible {
			*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
		}
		result[i] = r.Value[ramIndex]
	}
	return result
}

func (r *RAM) mutate(index Register, newByte byte, memoryAccessExceptionIndices *[]RamIndex) {
	ramIndex := RamIndex(index)
	if r.accessForIndex(ramIndex) != Mutable {
		*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
	}
	r.Value[ramIndex] = newByte
}

func (r *RAM) mutateRange(start Register, newBytes []byte, memoryAccessExceptionIndices *[]RamIndex) {
	for i, newByte := range newBytes {
		ramIndex := RamIndex(start) + RamIndex(i)
		if r.accessForIndex(ramIndex) != Mutable {
			*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
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

func (er ExitReason) IsSimple() bool {
	return er.SimpleExitReason != nil
}

func (er ExitReason) IsComplex() bool {
	return er.ComplexExitReason != nil
}

type Arguments []byte

func NewArguments(value []byte) (a Arguments, e error) {
	if len(value) >= ArgumentsZoneSize {
		return a, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return Arguments(value), nil
}
