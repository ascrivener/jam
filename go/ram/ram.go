package ram

// Constants for RAM memory layout and access control
const (
	PageSize          = (1 << 12)
	RamSize           = (1 << 32)
	MajorZoneSize     = (1 << 16)
	ArgumentsZoneSize = (1 << 24)
	NumRamPages       = RamSize / PageSize
)

var MinValidRamIndex RamIndex = MajorZoneSize

// Access permission types for RAM pages
type RamAccess int

const (
	Inaccessible RamAccess = iota
	Immutable
	Mutable
)

// RamIndex represents a 32-bit address into RAM
type RamIndex uint32

// Utility functions for RAM sizing calculations
func TotalSizeNeededMajorZones(size int) int {
	return MajorZoneSize * ((MajorZoneSize + size - 1) / MajorZoneSize)
}

func TotalSizeNeededPages(size int) int {
	return PageSize * ((PageSize + size - 1) / PageSize)
}

// RAM represents the memory of a PVM
type RAM struct {
	value           [RamSize]byte
	access          [NumRamPages]RamAccess
	BeginningOfHeap *RamIndex // nil if no heap
	rollbackLog     map[RamIndex]byte
}

//
// RAM Creation & Initialization
//

// NewEmptyRAM creates an empty RAM with rollback log initialized
func NewEmptyRAM() *RAM {
	return &RAM{
		rollbackLog: make(map[RamIndex]byte),
	}
}

// NewRAM creates a new RAM with the given data segments and access controls
func NewRAM(readData, writeData []byte, arguments []byte, z, stackSize int) *RAM {
	heapStart := RamIndex(2*MajorZoneSize + TotalSizeNeededMajorZones(len(readData)))
	var beginningOfHeap *RamIndex
	if len(writeData)+int(z) > 0 { // then we actually have a heap
		beginningOfHeap = new(RamIndex)
		*beginningOfHeap = heapStart
	}
	ram := &RAM{
		value:           [RamSize]byte{},
		access:          [NumRamPages]RamAccess{},
		BeginningOfHeap: beginningOfHeap,
		rollbackLog:     make(map[RamIndex]byte),
	}
	// read-only section
	ram.SetValueSlice(readData, MajorZoneSize)
	ram.SetSectionAccess(MajorZoneSize, uint64(MajorZoneSize+TotalSizeNeededPages(len(readData))), Immutable)
	// heap
	ram.SetValueSlice(writeData, uint64(heapStart))
	ram.SetSectionAccess(uint64(heapStart), uint64(heapStart)+uint64(TotalSizeNeededPages(len(writeData))+z*PageSize), Mutable)
	// stack
	stackStart := RamIndex(RamSize - 2*MajorZoneSize - ArgumentsZoneSize - TotalSizeNeededPages(stackSize))
	ram.SetSectionAccess(uint64(stackStart), uint64(stackStart)+uint64(TotalSizeNeededPages(stackSize)), Mutable)
	// arguments
	argumentsStart := RamIndex(RamSize - MajorZoneSize - ArgumentsZoneSize)
	ram.SetValueSlice(arguments, uint64(argumentsStart))
	ram.SetSectionAccess(uint64(argumentsStart), uint64(argumentsStart)+uint64(TotalSizeNeededPages(len(arguments))), Immutable)
	return ram
}

//
// Low-level RAM access methods
//

// GetValue returns the byte at the given index without checking access permissions
func (r *RAM) GetValue(index uint64) byte {
	ramIndex := RamIndex(index)
	return r.value[ramIndex]
}

// GetValueSlice returns count bytes starting from the given index without checking access permissions
func (r *RAM) GetValueSlice(start uint64, end uint64) []byte {
	var count uint64

	// Handle wrap-around case
	if end < start {
		// Calculate actual byte count needed (crossing 4GB boundary)
		count = min((RamSize-start)+end, RamSize)
	} else {
		count = end - start
	}

	return r.readBytes(start, count)
}

// readBytes is a helper that reads count bytes starting at start
func (r *RAM) readBytes(start uint64, count uint64) []byte {
	result := make([]byte, count)
	for i := uint64(0); i < count; i++ {
		ramIndex := RamIndex(start + i)
		result[i] = r.value[ramIndex]
	}
	return result
}

// SetValue sets the byte at the given index without checking access permissions
func (r *RAM) SetValue(index uint64, value byte) {
	ramIndex := RamIndex(index)
	r.value[ramIndex] = value
}

// SetValueSlice sets bytes starting from the given index without checking access permissions
func (r *RAM) SetValueSlice(values []byte, start uint64) {
	for i, v := range values {
		ramIdx := RamIndex(start + uint64(i))
		r.value[ramIdx] = v
	}
}

// pageRangeIterator applies the given function to each page in a range
// If earlyReturn is true, iteration stops when fn returns true
// Returns true if fn ever returned true, false otherwise
func (r *RAM) pageRangeIterator(start, end uint64, fn func(int) bool, earlyReturn bool) bool {
	// Convert to RamIndex to ensure proper 32-bit wrapping
	startIdx := RamIndex(start)
	endIdx := RamIndex(end)

	// If empty range after wrapping, return default
	if startIdx == endIdx {
		return false
	}

	// Calculate page boundaries
	startPage := int(startIdx / PageSize)
	endPage := int((endIdx-1)/PageSize) + 1

	// Handle wrap-around case
	if endIdx < startIdx {
		// Check from start to end of memory
		for i := startPage; i < int(RamSize/PageSize); i++ {
			if fn(i) && earlyReturn {
				return true
			}
		}
		// Check from beginning of memory to end
		for i := range endPage {
			if fn(i) && earlyReturn {
				return true
			}
		}
		return false
	}

	// Normal case (no wrap)
	for i := startPage; i < endPage; i++ {
		if fn(i) && earlyReturn {
			return true
		}
	}
	return false
}

//
// Memory access control methods
//

// AccessForIndex returns the access type for the given memory index
func (r *RAM) AccessForIndex(index uint64) RamAccess {
	return r.access[RamIndex(index)/PageSize]
}

// SetIndexAccess sets the access type for a page containing the given index
func (r *RAM) SetIndexAccess(index uint64, access RamAccess) {
	r.access[RamIndex(index)/PageSize] = access
}

// RangeHas checks if any page in the range has the specified access type
func (r *RAM) RangeHas(access RamAccess, start, end uint64) bool {
	return r.pageRangeIterator(start, end, func(i int) bool {
		return r.access[i] == access
	}, true) // Early return when condition is met
}

// RangeUniform checks if all pages in the range have the specified access type
func (r *RAM) RangeUniform(access RamAccess, start, end uint64) bool {
	return !r.pageRangeIterator(start, end, func(i int) bool {
		return r.access[i] != access
	}, true) // Early return when condition is met
}

// SetSectionAccess sets the access type for all pages in the range
func (r *RAM) SetSectionAccess(start, end uint64, access RamAccess) {
	r.pageRangeIterator(start, end, func(i int) bool {
		r.access[i] = access
		return false // Never triggers early return
	}, false) // Don't do early return
}

//
// Memory inspection and mutation with access control
//

// Inspect returns the byte at the given index, tracking access violations
func (r *RAM) Inspect(index uint64, memoryAccessExceptionIndices *[]RamIndex) byte {
	ramIndex := RamIndex(index)
	if r.AccessForIndex(index) == Inaccessible {
		*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
	}
	return r.value[ramIndex]
}

// InspectRange returns bytes from start to end, tracking access violations
func (r *RAM) InspectRange(start uint64, end uint64, memoryAccessExceptionIndices *[]RamIndex) []byte {
	var count uint64

	// Handle wrap-around case
	if end < start {
		// Calculate actual byte count needed (crossing 4GB boundary)
		count = min((RamSize-start)+end, RamSize)
	} else {
		count = end - start
	}

	// First check access for all indices
	for i := uint64(0); i < count; i++ {
		currentIndex := start + i
		ramIndex := RamIndex(currentIndex)
		if r.AccessForIndex(currentIndex) == Inaccessible {
			*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
		}
	}

	// Use readBytes to get the actual values
	return r.readBytes(start, count)
}

// Mutate changes a byte at the given index, tracking access violations and rollback state
func (r *RAM) Mutate(index uint64, newByte byte, memoryAccessExceptionIndices *[]RamIndex) {
	// Convert to RamIndex for array access
	ramIndex := RamIndex(index)

	if r.AccessForIndex(index) != Mutable {
		*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
	}

	// Initialize the changes map if needed.
	if r.rollbackLog == nil {
		r.rollbackLog = make(map[RamIndex]byte)
	}

	// Store the original value only once (for rollback).
	if _, exists := r.rollbackLog[ramIndex]; !exists {
		r.rollbackLog[ramIndex] = r.value[ramIndex]
	}

	// Write directly to the value array.
	r.value[ramIndex] = newByte
}

// MutateRange changes multiple bytes, tracking access violations and rollback state
func (r *RAM) MutateRange(start uint64, newBytes []byte, memoryAccessExceptionIndices *[]RamIndex) {
	if r.rollbackLog == nil {
		r.rollbackLog = make(map[RamIndex]byte)
	}

	for i, newByte := range newBytes {
		// Calculate the index with proper wrapping
		currentIndex := start + uint64(i)
		ramIndex := RamIndex(currentIndex)

		if r.AccessForIndex(currentIndex) != Mutable {
			*memoryAccessExceptionIndices = append(*memoryAccessExceptionIndices, ramIndex)
		}

		// Track the original value only once.
		if _, exists := r.rollbackLog[ramIndex]; !exists {
			r.rollbackLog[ramIndex] = r.value[ramIndex]
		}

		// Write directly.
		r.value[ramIndex] = newByte
	}
}

//
// Rollback functionality
//

// Rollback restores original values from the rollback log
func (r *RAM) Rollback() {
	if r.rollbackLog == nil {
		return
	}
	for addr, originalValue := range r.rollbackLog {
		r.value[addr] = originalValue
	}
	r.rollbackLog = nil
}

// ClearRollbackLog discards the rollback information
func (r *RAM) ClearRollbackLog() {
	r.rollbackLog = nil
}
