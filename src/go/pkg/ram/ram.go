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
	pages                    [NumRamPages]*[]byte   // Page number -> page content (nil = unallocated)
	access                   [NumRamPages]RamAccess // Page number -> access rights
	BeginningOfHeap          *RamIndex              // nil if no heap
	minMemoryAccessException *RamIndex              // Track the minimum index that caused an access exception
	usedPages                map[uint32]struct{}    // Track which pages were allocated/modified (for fast reset)
}

// Custom RAM pool with fixed capacity that GC cannot clear
type FixedRAMPool struct {
	pool chan *RAM
	size int
}

func NewFixedRAMPool(size int) *FixedRAMPool {
	p := &FixedRAMPool{
		pool: make(chan *RAM, size),
		size: size,
	}

	// Pre-fill the pool with RAM objects
	for i := 0; i < size; i++ {
		ram := &RAM{
			pages:                    [NumRamPages]*[]byte{},
			access:                   [NumRamPages]RamAccess{},
			minMemoryAccessException: nil,
			usedPages:                make(map[uint32]struct{}),
		}
		p.pool <- ram
	}

	return p
}

func (p *FixedRAMPool) Get() *RAM {
	select {
	case ram := <-p.pool:
		return ram
	default:
		// Pool exhausted - create new one (this should be rare)
		fmt.Printf("POOL EXHAUSTED - creating new RAM (pool size: %d)\n", p.size)
		return &RAM{
			pages:                    [NumRamPages]*[]byte{},
			access:                   [NumRamPages]RamAccess{},
			minMemoryAccessException: nil,
			usedPages:                make(map[uint32]struct{}),
		}
	}
}

func (p *FixedRAMPool) Put(ram *RAM) {
	select {
	case p.pool <- ram:
		// Successfully returned to pool
	default:
		// Pool full - this means we have more objects than pool size
		// Just let this one be GC'd (should be rare)
	}
}

// Replace sync.Pool with fixed pool
var fixedRAMPool = NewFixedRAMPool(4)

func NewEmptyRAM() *RAM {
	ram := fixedRAMPool.Get()
	ram.resetToEmpty()
	return ram
}

func (r *RAM) resetToEmpty() {
	for pageNum := range r.usedPages {
		r.pages[pageNum] = nil
		r.access[pageNum] = Inaccessible
	}

	r.usedPages = make(map[uint32]struct{})

	r.BeginningOfHeap = nil
	r.minMemoryAccessException = nil
}

// trackUsedPage adds a page to the used pages map
func (r *RAM) trackUsedPage(pageNum uint32) {
	r.usedPages[pageNum] = struct{}{}
}

// NewRAM creates a new RAM with the given data segments and access controls
func NewRAM(readData, writeData, arguments []byte, z, stackSize int) *RAM {
	ram := NewEmptyRAM()
	heapStart := RamIndex(2*MajorZoneSize + TotalSizeNeededMajorZones(len(readData)))
	// read-only section
	ram.MutateRange(MajorZoneSize, len(readData), NoWrap, false, func(dest []byte) {
		copy(dest, readData)
	})
	ram.MutateAccessRange(MajorZoneSize, uint64(TotalSizeNeededPages(len(readData))), Immutable, NoWrap)
	// heap
	ram.MutateRange(uint64(heapStart), len(writeData), NoWrap, false, func(dest []byte) {
		copy(dest, writeData)
	})
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
	ram.MutateRange(uint64(argumentsStart), len(arguments), NoWrap, false, func(dest []byte) {
		copy(dest, arguments)
	})
	ram.MutateAccessRange(uint64(argumentsStart), uint64(TotalSizeNeededPages(len(arguments))), Immutable, NoWrap)
	return ram
}

//
// Memory access and mutation methods
//

// getOrCreatePage returns the page at the given page number for write operations
// Creates the page if it doesn't exist since we need to mutate it
func (r *RAM) getOrCreatePage(pageNum uint32) []byte {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to create page at invalid index %d (max is %d)", pageNum, NumRamPages-1))
	}

	if r.pages[pageNum] == nil {
		page := make([]byte, PageSize)
		r.pages[pageNum] = &page
		r.trackUsedPage(pageNum)
	}
	return *r.pages[pageNum]
}

// Inspect returns the byte at the given index, optionally tracking access violations
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode, trackAccessExceptions bool) byte {
	return r.InspectRange(index, 1, mode, trackAccessExceptions)[0]
}

// checkAccessViolations pre-checks access violations and sets exceptions early
func (r *RAM) checkAccessViolations(start, length uint64, mode MemoryAccessMode, trackAccessExceptions bool,
	accessCheck func(RamAccess) bool) {

	if !trackAccessExceptions {
		return
	}

	startPage := uint32(start / PageSize)
	endPage := uint32((start + length - 1) / PageSize)

	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		access := r.getPageAccess(pageNum)
		if accessCheck(access) {
			// Found violation - calculate the actual violating index within our range
			pageStart := uint64(pageNum) * PageSize

			// Find the intersection of [start, start+length-1] and [pageStart, pageEnd]
			violationIndex := max(start, pageStart)

			if mode == Wrap {
				violationIndex = violationIndex % RamSize
			}

			if r.minMemoryAccessException == nil || violationIndex < uint64(*r.minMemoryAccessException) {
				r.minMemoryAccessException = new(RamIndex)
				*r.minMemoryAccessException = RamIndex(violationIndex)
			}
			break // Found first violation, no need to check further
		}
	}
}

// isSinglePageAccess checks if the given range fits within a single page
func (r *RAM) isSinglePageAccess(index uint64, length uint64, mode MemoryAccessMode) (bool, uint32, uint64) {
	actualStart := index
	if mode == Wrap {
		actualStart = index % RamSize
	}
	startPageNum := uint32(actualStart / PageSize)
	startPageOffset := actualStart % PageSize
	isSinglePage := startPageOffset+length <= PageSize

	return isSinglePage, startPageNum, startPageOffset
}

// InspectRange returns a contiguous buffer for the range, either direct page memory or combined slices
func (r *RAM) InspectRange(index, length uint64, mode MemoryAccessMode, trackAccessExceptions bool) []byte {
	if length == 0 {
		return nil
	}

	r.checkAccessViolations(index, length, mode, trackAccessExceptions,
		func(access RamAccess) bool { return access == Inaccessible })

	// Check if this is a single page operation
	isSinglePage, pageNum, pageOffset := r.isSinglePageAccess(index, length, mode)

	if isSinglePage {
		// Fast path: single page access - return direct slice
		page := r.getOrCreatePage(pageNum)
		return page[pageOffset : pageOffset+length]
	} else {
		// Slow path: multi-page access
		slices := r.pageIterator(index, length, mode)

		// Combine into contiguous buffer
		combined := make([]byte, length)
		offset := 0
		for _, slice := range slices {
			copy(combined[offset:offset+len(slice)], slice)
			offset += len(slice)
		}
		return combined
	}
}

// Mutate changes a byte at the given index, optionally tracking access violations and updating rollback state
func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	r.MutateRange(index, 1, mode, trackAccessExceptions, func(dest []byte) {
		dest[0] = newByte
	})
}

// MutateRange provides direct access to writable memory via a callback function
func (r *RAM) MutateRange(index uint64, length int, mode MemoryAccessMode, trackAccessExceptions bool, fn func([]byte)) {
	if length == 0 {
		return
	}

	r.checkAccessViolations(index, uint64(length), mode, trackAccessExceptions,
		func(access RamAccess) bool { return access == Inaccessible || access == Immutable })

	// Check if this is a single page operation
	isSinglePage, pageNum, pageOffset := r.isSinglePageAccess(index, uint64(length), mode)

	if isSinglePage {
		page := r.getOrCreatePage(pageNum)
		fn(page[pageOffset : pageOffset+uint64(length)])
	} else {
		slices := r.pageIterator(index, uint64(length), mode)

		temp := make([]byte, length)
		fn(temp)

		offset := 0
		for _, slice := range slices {
			copy(slice, temp[offset:offset+len(slice)])
			offset += len(slice)
		}
	}
}

// pageIterator yields slices of memory for the given range, allowing callers to process each slice
// Note: This is only called for multi-page operations now
func (r *RAM) pageIterator(start, length uint64, mode MemoryAccessMode) [][]byte {

	if length == 0 {
		return nil
	}

	// Multi-page access - pre-allocate slice capacity
	expectedPages := (length + PageSize - 1) / PageSize
	slices := make([][]byte, 0, expectedPages)

	// Process data page by page
	for i := uint64(0); i < length; {
		index := start + i
		if mode == Wrap {
			index = index % RamSize
		}

		pageNum := uint32(index / PageSize)
		pageOffset := index % PageSize

		// Get the page for operations
		page := r.getOrCreatePage(pageNum)
		bytesToCopy := min(PageSize-pageOffset, length-i)

		// Add slice to results
		slices = append(slices, page[pageOffset:pageOffset+bytesToCopy])

		i += bytesToCopy
	}

	return slices
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

	// Direct slice access is faster than map lookup
	return r.access[pageNum]
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
	r.trackUsedPage(pageNum)
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
	r.pages[pageNum] = nil
}

// ClearPageAccess removes a page from the access map
// This resets the page's access permissions to the default (typically Inaccessible)
func (r *RAM) ClearPageAccess(pageNum uint32) {
	// Bounds check
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to clear access for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}

	// Delete the page from the access map if it exists
	// Since non-existent pages default to Inaccessible, this effectively clears the page's access
	r.access[pageNum] = Inaccessible
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
	r.minMemoryAccessException = nil
}

// GetMinMemoryAccessException returns the minimum memory access exception
func (r *RAM) GetMinMemoryAccessException() *RamIndex {
	return r.minMemoryAccessException
}

func (r *RAM) ReturnToPool() {
	fixedRAMPool.Put(r)
}
