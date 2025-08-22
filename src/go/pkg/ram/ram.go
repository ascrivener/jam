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

// Helper methods for page-based memory management

// getPageAndOffset converts an absolute memory index to page number and offset
func (r *RAM) getPageAndOffset(index RamIndex) (pageNum uint32, offset uint32) {
	pageNum = uint32(index / PageSize)
	offset = uint32(index % PageSize)
	return
}

// getPage returns the page at the given page number, or nil if it doesn't exist
func (r *RAM) getPage(pageNum uint32) []byte {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to access invalid page number %d (max is %d)", pageNum, NumRamPages-1))
	}

	page, exists := r.pages[pageNum]
	if !exists {
		return nil
	}
	return page
}

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

// getByte returns a byte from a given absolute memory index
func (r *RAM) getByte(index RamIndex) byte {
	pageNum, offset := r.getPageAndOffset(index)
	page := r.getPage(pageNum)
	if page == nil {
		return 0 // Unallocated memory reads as zero
	}
	return page[offset]
}

// setByte sets a byte at a given absolute memory index
func (r *RAM) setByte(index RamIndex, value byte) {
	pageNum, offset := r.getPageAndOffset(index)
	page := r.getOrCreatePage(pageNum)
	page[offset] = value
}

// Inspect returns the byte at the given index, optionally tracking access violations
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode, trackAccessExceptions bool) byte {
	// Handle wrapping for Wrap mode
	if mode == Wrap {
		index = index % RamSize
	}

	ramIndex := RamIndex(index)
	if r.InspectAccess(index, mode) == Inaccessible {
		if trackAccessExceptions {
			r.memoryAccessExceptionIndices = append(r.memoryAccessExceptionIndices, ramIndex)
		}
	}

	return r.getByte(ramIndex)
}

// InspectRange returns bytes from start to end, optionally tracking access violations
func (r *RAM) InspectRange(start, length uint64, mode MemoryAccessMode, trackAccessExceptions bool) []byte {
	end := start + length
	// Pre-allocate the result slice
	result := make([]byte, 0, length)

	// Use indexRangeIterator to iterate through each index in the range
	r.indexRangeIterator(start, end, func(index uint64) {
		result = append(result, r.Inspect(index, mode, trackAccessExceptions))
	}, mode)

	return result
}

// Mutate changes a byte at the given index, optionally tracking access violations and updating rollback state
func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	// Handle wrapping for Wrap mode
	if mode == Wrap {
		index = index % RamSize
	}

	// Convert to RamIndex for access control
	ramIndex := RamIndex(index)

	if r.InspectAccess(index, mode) != Mutable {
		if trackAccessExceptions {
			r.memoryAccessExceptionIndices = append(r.memoryAccessExceptionIndices, ramIndex)
		}
	}

	// Store the original value only once (for rollback)
	// if _, exists := r.rollbackLog[ramIndex]; !exists {
	// 	r.rollbackLog[ramIndex] = r.getByte(ramIndex)
	// }

	// Set the new value
	r.setByte(ramIndex, newByte)

	// beginning := 207080
	// end := beginning + 1

	// // Debug output: show RAM values at [beginning...end] only if mutation is in that range
	// if index >= uint64(beginning) && index < uint64(end) {
	// 	fmt.Printf("Mutate at %d: RAM[%d:%d] = ", index, beginning, end)
	// 	for i := uint64(beginning); i < uint64(end); i++ {
	// 		fmt.Printf("%02x", r.getByte(RamIndex(i)))
	// 	}
	// 	fmt.Println()
	// }
}

// MutateRange changes multiple bytes, optionally tracking access violations and updating rollback state
func (r *RAM) MutateRange(start uint64, newBytes []byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	var offset uint64 = 0
	r.indexRangeIterator(start, start+uint64(len(newBytes)), func(index uint64) {
		r.Mutate(index, newBytes[offset], mode, trackAccessExceptions)
		offset++
	}, mode)
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

// InspectAccess returns the access type for the given memory index
func (r *RAM) InspectAccess(index uint64, mode MemoryAccessMode) RamAccess {
	if mode == Wrap {
		index = index % RamSize
	}
	pageNum := uint32(index / PageSize)
	return r.getPageAccess(pageNum)
}

// RangeHas checks if any page in the range has the specified access type
// Takes start index and length of range to inspect
func (r *RAM) RangeHas(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	// Check for potential overflow or out of bounds in NoWrap mode
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return false
	}

	// Calculate end safely, with wrapping handled by pageRangeIterator
	end := start + length

	result := false
	r.pageRangeIterator(start, end, func(page uint32) {
		pageAccess := r.getPageAccess(page)
		if pageAccess == access {
			result = true
		}
	}, mode)
	return result
}

// RangeUniform checks if all pages in the range have the specified access type
// Takes start index and length of range to inspect
func (r *RAM) RangeUniform(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	// Check for potential overflow or out of bounds in NoWrap mode
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return false
	}

	// Calculate end safely, with wrapping handled by pageRangeIterator
	end := start + length

	uniform := true
	r.pageRangeIterator(start, end, func(page uint32) {
		pageAccess := r.getPageAccess(uint32(page))
		if pageAccess != access {
			uniform = false
		}
	}, mode)
	return uniform
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
	end := start + length

	r.pageRangeIterator(start, end, func(page uint32) {
		r.setPageAccess(page, access)
	}, mode)
}

//
// Rollback functionality
//

// Rollback restores original values from the rollback log
func (r *RAM) Rollback() {
	for idx, val := range r.rollbackLog {
		r.setByte(idx, val)
	}
}

// ClearRollbackLog discards the rollback information
func (r *RAM) ClearRollbackLog() {
	for k := range r.rollbackLog {
		delete(r.rollbackLog, k)
	}
}

// ClearMemoryAccessExceptions clears the memory access exceptions
func (r *RAM) ClearMemoryAccessExceptions() {
	r.memoryAccessExceptionIndices = r.memoryAccessExceptionIndices[:0]
}

// GetMemoryAccessExceptions returns the memory access exceptions
func (r *RAM) GetMemoryAccessExceptions() []RamIndex {
	return r.memoryAccessExceptionIndices
}

// allocatePages ensures that pages from startPage to startPage+count exist
func (r *RAM) allocatePages(startPage uint32, count uint32) {
	endPage := startPage + count
	for pageNum := startPage; pageNum < endPage; pageNum++ {
		r.getOrCreatePage(pageNum)
	}
}

// rangeIterator is the core implementation for iterating over both indices and pages
// It provides a unified mechanism for handling wrapping and range validity
func (r *RAM) rangeIterator(start, end uint64, step uint64, fn func(uint64), mode MemoryAccessMode) {
	// Normal case with wrapping handled by modulo if needed
	for i := start; i < end; i += step {
		index := i
		if mode == Wrap {
			index = i % RamSize // Apply wrapping with modulo
		}

		fn(index)
	}
}

// indexRangeIterator applies the given function to each index in a range
func (r *RAM) indexRangeIterator(start, end uint64, fn func(uint64), mode MemoryAccessMode) {
	// Use rangeIterator with step size of 1 for byte-by-byte iteration
	r.rangeIterator(start, end, 1, fn, mode)
}

// pageRangeIterator applies the given function to each page in a range
func (r *RAM) pageRangeIterator(start, end uint64, fn func(uint32), mode MemoryAccessMode) {
	// Special case for zero-length ranges
	if start == end {
		return // No pages to process
	}
	// Calculate page boundaries
	startPage := uint64(RamIndex(start) / PageSize)
	endPage := uint64((RamIndex(end)-1)/PageSize) + 1

	// Use rangeIterator with step size of PageSize to iterate pages
	r.rangeIterator(
		startPage*PageSize,
		endPage*PageSize,
		PageSize,
		func(index uint64) {
			fn(uint32(index / PageSize))
		},
		mode,
	)
}
