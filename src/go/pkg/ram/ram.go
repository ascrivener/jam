package ram

import (
	"fmt"

	"jam/pkg/constants"
)

// Constants for RAM memory layout and access control
const (
	PageSize          = (1 << 12)
	RamSize           = (1 << 32)
	MajorZoneSize     = (1 << 16)
	ArgumentsZoneSize = (1 << 24)
	NumRamPages       = RamSize / PageSize
)

var MinValidRamIndex RamIndex = MajorZoneSize

type Arguments []byte

func NewArguments(value []byte) (a Arguments, e error) {
	if len(value) >= ArgumentsZoneSize {
		return a, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return Arguments(value), nil
}

// MemoryAccessMode defines how memory accesses beyond RamSize should be handled
type MemoryAccessMode int

const (
	// NoWrap causes operations to fail when accessing memory beyond RamSize
	NoWrap MemoryAccessMode = iota
	// Wrap causes operations to wrap around when accessing memory beyond RamSize
	Wrap
)

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
	pages                        map[uint32][]byte    // Page number -> page content
	access                       map[uint32]RamAccess // Page number -> access rights
	BeginningOfHeap              *RamIndex            // nil if no heap
	rollbackLog                  map[RamIndex]byte
	memoryAccessExceptionIndices []RamIndex // Track memory access exceptions internally
}

//
// RAM Creation & Initialization
//

// NewEmptyRAM creates an empty RAM with rollback log initialized
func NewEmptyRAM() *RAM {
	return &RAM{
		pages:                        make(map[uint32][]byte),
		access:                       make(map[uint32]RamAccess),
		rollbackLog:                  make(map[RamIndex]byte),
		memoryAccessExceptionIndices: make([]RamIndex, 0),
	}
}

// NewRAM creates a new RAM with the given data segments and access controls
func NewRAM(readData, writeData, arguments []byte, z, stackSize int) *RAM {
	ram := NewEmptyRAM()
	heapStart := RamIndex(2*MajorZoneSize + TotalSizeNeededMajorZones(len(readData)))
	// read-only section
	ram.MutateRange(MajorZoneSize, readData, NoWrap, false)
	ram.MutateAccessRange(MajorZoneSize, uint64(TotalSizeNeededPages(len(readData))), Immutable, NoWrap)
	// heap
	ram.MutateRange(uint64(heapStart), writeData, NoWrap, false)
	// Calculate total heap size including both data and extra space
	heapLength := uint64(TotalSizeNeededPages(len(writeData)) + z*PageSize)
	ram.MutateAccessRange(uint64(heapStart), heapLength, Mutable, NoWrap)
	heapStart += RamIndex(heapLength)
	if heapLength > 0 { // then we actually have a heap
		ram.BeginningOfHeap = &heapStart
	}
	// stack
	stackStart := RamIndex(RamSize - 2*MajorZoneSize - ArgumentsZoneSize - TotalSizeNeededPages(stackSize))
	ram.MutateAccessRange(uint64(stackStart), uint64(TotalSizeNeededPages(stackSize)), Mutable, NoWrap)
	// arguments
	argumentsStart := RamIndex(RamSize - MajorZoneSize - ArgumentsZoneSize)
	ram.MutateRange(uint64(argumentsStart), arguments, NoWrap, false)
	ram.MutateAccessRange(uint64(argumentsStart), uint64(TotalSizeNeededPages(len(arguments))), Immutable, NoWrap)
	return ram
}

//
// Memory access and mutation methods
//

// getOrCreatePage returns the page at the given page number, creating it if it doesn't exist
func (r *RAM) getOrCreatePage(pageNum uint32) []byte {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to create page at invalid index %d (max is %d)", pageNum, NumRamPages-1))
	}

	page, exists := r.pages[pageNum]
	if !exists {
		page = make([]byte, PageSize)
		r.pages[pageNum] = page
	}
	return page
}

// Inspect returns the byte at the given index, optionally tracking access violations
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode, trackAccessExceptions bool) byte {
	result := r.InspectRange(index, 1, mode, trackAccessExceptions)
	return result[0]
}

// pageIterator handles the common logic of iterating through pages and checking access
func (r *RAM) pageIterator(start, length uint64, mode MemoryAccessMode, trackAccessExceptions bool,
	accessCheck func(RamAccess) bool, pageOperation func([]byte, uint64, uint64, uint64)) {

	// Handle zero-length ranges
	if length == 0 {
		return
	}

	// For small ranges, avoid map allocation
	var pageAccess map[uint32]RamAccess
	if length > PageSize*2 { // Only cache for multi-page operations
		startPage := uint32(start / PageSize)
		endPage := uint32((start + length - 1) / PageSize)
		pageAccess = make(map[uint32]RamAccess, endPage-startPage+1)
		for pageNum := startPage; pageNum <= endPage; pageNum++ {
			pageAccess[pageNum] = r.getPageAccess(pageNum)
		}
	}

	// Process data page by page
	for i := uint64(0); i < length; {
		index := start + i
		if mode == Wrap {
			index = index % RamSize
		}

		pageNum := uint32(index / PageSize)
		pageOffset := index % PageSize

		// Check access - use cached or direct lookup
		var access RamAccess
		if pageAccess != nil {
			access = pageAccess[pageNum]
		} else {
			access = r.getPageAccess(pageNum)
		}

		if accessCheck(access) && trackAccessExceptions {
			r.memoryAccessExceptionIndices = append(r.memoryAccessExceptionIndices, RamIndex(index))
		}

		// Get the page and perform the operation
		page := r.getOrCreatePage(pageNum)
		bytesToCopy := min(PageSize-pageOffset, length-i)
		pageOperation(page, pageOffset, bytesToCopy, i)

		i += bytesToCopy
	}
}

// InspectRange returns bytes from start to end, optionally tracking access violations
func (r *RAM) InspectRange(start, length uint64, mode MemoryAccessMode, trackAccessExceptions bool) []byte {
	if length == 0 {
		return make([]byte, 0)
	}

	result := make([]byte, length)
	resultOffset := uint64(0)

	r.pageIterator(start, length, mode, trackAccessExceptions,
		func(access RamAccess) bool { return access == Inaccessible },
		func(page []byte, pageOffset, bytesToCopy, i uint64) {
			copy(result[resultOffset:resultOffset+bytesToCopy], page[pageOffset:pageOffset+bytesToCopy])
			resultOffset += bytesToCopy
		})

	return result
}

// Mutate changes a byte at the given index, optionally tracking access violations and updating rollback state
func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	r.MutateRange(index, []byte{newByte}, mode, trackAccessExceptions)
}

// MutateRange changes multiple bytes, optionally tracking access violations and updating rollback state
func (r *RAM) MutateRange(start uint64, newBytes []byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	length := uint64(len(newBytes))
	sourceOffset := uint64(0)

	r.pageIterator(start, length, mode, trackAccessExceptions,
		func(access RamAccess) bool { return access != Mutable },
		func(page []byte, pageOffset, bytesToCopy, i uint64) {
			copy(page[pageOffset:pageOffset+bytesToCopy], newBytes[sourceOffset:sourceOffset+bytesToCopy])
			sourceOffset += bytesToCopy
		})
}

//
// Memory access control methods
//

// getPageAccess returns the access type for a given page number
// Pages not explicitly set default to Inaccessible
func (r *RAM) getPageAccess(pageNum uint32) RamAccess {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to access permissions for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}

	access, exists := r.access[pageNum]
	if !exists {
		return Inaccessible // Default access is Inaccessible
	}
	return access
}

// pageRangeCheck performs a check on all pages in a range with early termination
func (r *RAM) pageRangeCheck(start, length uint64, mode MemoryAccessMode, checkFunc func(RamAccess) bool) bool {
	// Handle zero-length ranges
	if length == 0 {
		return false // Default for empty ranges
	}

	// Check for potential overflow or out of bounds in NoWrap mode
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return false
	}

	// Calculate page range for access checking
	actualStart := start
	if mode == Wrap {
		actualStart = start % RamSize
	}

	startPage := uint32(actualStart / PageSize)
	endPage := uint32((actualStart + length - 1) / PageSize)

	// Check each page in the range
	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		if checkFunc(r.getPageAccess(pageNum)) {
			return true
		}
	}

	return false
}

// RangeHas checks if any page in the range has the specified access type
func (r *RAM) RangeHas(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	return r.pageRangeCheck(start, length, mode, func(pageAccess RamAccess) bool {
		return pageAccess == access
	})
}

// RangeUniform checks if all pages in the range have the specified access type
func (r *RAM) RangeUniform(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	// Handle zero-length ranges - vacuously true
	if length == 0 {
		return true
	}

	// Use pageRangeCheck to find any page that doesn't match
	return !r.pageRangeCheck(start, length, mode, func(pageAccess RamAccess) bool {
		return pageAccess != access
	})
}

// setPageAccess sets the access type for a specific page number
// with bounds checking
func (r *RAM) setPageAccess(pageNum uint32, access RamAccess) {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to set permissions for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	r.access[pageNum] = access
}

// ZeroPage removes a page from the pages map, effectively zeroing it out
// This is more memory efficient than storing a page full of zeros
func (r *RAM) ZeroPage(pageNum uint32) {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to zero invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}

	// Delete the page from the pages map if it exists
	// Since non-existent pages default to zeros, this effectively zeroes the page
	delete(r.pages, pageNum)
}

// ClearPageAccess removes a page from the access map
// This resets the page's access permissions to the default (typically Inaccessible)
func (r *RAM) ClearPageAccess(pageNum uint32) {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to clear access for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}

	// Delete the page from the access map if it exists
	delete(r.access, pageNum)
}

// MutateAccess sets the access type for a page containing the given index
func (r *RAM) MutateAccess(index uint64, access RamAccess, mode MemoryAccessMode) {
	if mode == Wrap {
		index = index % RamSize
	}

	pageNum := uint32(index / PageSize)
	r.setPageAccess(pageNum, access)
}

// MutateAccessRange sets the access type for all pages in the range
// Takes start index and length of range to modify
func (r *RAM) MutateAccessRange(start, length uint64, access RamAccess, mode MemoryAccessMode) {
	// Handle zero-length ranges
	if length == 0 {
		return
	}

	// Check for potential overflow or out of bounds in NoWrap mode
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return
	}

	// Calculate page range
	actualStart := start
	if mode == Wrap {
		actualStart = start % RamSize
	}

	startPage := uint32(actualStart / PageSize)
	endPage := uint32((actualStart + length - 1) / PageSize)

	// Set access for each page in the range
	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		r.setPageAccess(pageNum, access)
	}
}

//
// Rollback functionality
//

// ClearMemoryAccessExceptions clears the memory access exceptions
func (r *RAM) ClearMemoryAccessExceptions() {
	r.memoryAccessExceptionIndices = r.memoryAccessExceptionIndices[:0]
}

// GetMemoryAccessExceptions returns the memory access exceptions
func (r *RAM) GetMemoryAccessExceptions() []RamIndex {
	return r.memoryAccessExceptionIndices
}
