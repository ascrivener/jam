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
	RollbackLog     map[RamIndex]byte
}

func NewEmptyRAM() *RAM {
	return &RAM{
		RollbackLog: make(map[RamIndex]byte),
	}
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
		RollbackLog:     make(map[RamIndex]byte),
	}
	// read-only section
	ram.setSectionValue(readData, MajorZoneSize)
	ram.setSectionAccess(MajorZoneSize, RamIndex(TotalSizeNeededPages(len(readData))), Immutable)
	// heap
	ram.setSectionValue(writeData, heapStart)
	ram.setSectionAccess(heapStart, RamIndex(TotalSizeNeededPages(len(writeData))+z*PageSize), Mutable)
	// stack
	stackStart := RamIndex(RamSize - 2*MajorZoneSize - ArgumentsZoneSize - TotalSizeNeededPages(stackSize))
	ram.setSectionAccess(stackStart, RamIndex(TotalSizeNeededPages(stackSize)), Mutable)
	// arguments
	argumentsStart := RamIndex(RamSize - MajorZoneSize - ArgumentsZoneSize)
	ram.setSectionValue(arguments, argumentsStart)
	ram.setSectionAccess(argumentsStart, RamIndex(TotalSizeNeededPages(len(arguments))), Immutable)
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
	copy(r.Value[start:end], srcValues)
}

func (r *RAM) accessForIndex(index RamIndex) RamAccess {
	return r.Access[index/PageSize]
}

func (r *RAM) rangeHas(access RamAccess, start, end RamIndex) bool {
	startPage := int(start / PageSize)
	endPage := int(end / PageSize)

	for i := startPage; i < endPage; i++ {
		if r.Access[i] == access {
			return true
		}
	}
	return false
}

func (r *RAM) rangeUniform(access RamAccess, start, end RamIndex) bool {
	startPage := int(start / PageSize)
	endPage := int(end / PageSize)

	for i := startPage; i < endPage; i++ {
		if r.Access[i] != access {
			return false
		}
	}
	return true
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
	// Initialize the changes map if needed.
	if r.RollbackLog == nil {
		r.RollbackLog = make(map[RamIndex]byte)
	}
	// Store the original value only once (for rollback).
	if _, exists := r.RollbackLog[ramIndex]; !exists {
		r.RollbackLog[ramIndex] = r.Value[ramIndex]
	}
	// Write directly to the value array.
	r.Value[ramIndex] = newByte
}

func (r *RAM) mutateRange(start Register, newBytes []byte, memoryAccessExceptionIndices *[]RamIndex) {
	if r.RollbackLog == nil {
		r.RollbackLog = make(map[RamIndex]byte)
	}
	for i, newByte := range newBytes {
		ramIndex := RamIndex(start) + RamIndex(i)
		if r.accessForIndex(ramIndex) != Mutable {
			*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
		}
		// Track the original value only once.
		if _, exists := r.RollbackLog[ramIndex]; !exists {
			r.RollbackLog[ramIndex] = r.Value[ramIndex]
		}
		// Write directly.
		r.Value[ramIndex] = newByte
	}
}

func (r *RAM) rollback() {
	if r.RollbackLog == nil {
		return
	}
	for addr, originalValue := range r.RollbackLog {
		r.Value[addr] = originalValue
	}
	r.RollbackLog = nil
}

func (r *RAM) clearRollbackLog() {
	r.RollbackLog = nil
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
	if len(value) >= ArgumentsZoneSize {
		return a, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return Arguments(value), nil
}
