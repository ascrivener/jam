package ram

import (
	"fmt"

	"jam/pkg/constants"

	"golang.org/x/sys/unix"
)

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

type MemoryAccessMode int

const (
	// NoWrap causes operations to fail when accessing memory beyond RamSize
	NoWrap MemoryAccessMode = iota
	// Wrap causes operations to wrap around when accessing memory beyond RamSize
	Wrap
)

type RamAccess uint8

const (
	Inaccessible RamAccess = iota
	Immutable
	Mutable
)

type AccessCheckType int

const (
	// CheckRead checks for inaccessible pages (read operations)
	CheckRead AccessCheckType = iota
	// CheckWrite checks for inaccessible or immutable pages (write operations)
	CheckWrite
)

type RamIndex uint32

func TotalSizeNeededMajorZones(size int) int {
	return MajorZoneSize * ((MajorZoneSize + size - 1) / MajorZoneSize)
}

func TotalSizeNeededPages(size int) int {
	return PageSize * ((PageSize + size - 1) / PageSize)
}

type RAM struct {
	buffer                   []byte      // mmap'd 4GB virtual address space
	access                   []RamAccess // Page number -> access rights (defaults to Inaccessible=0)
	BeginningOfHeap          *RamIndex   // nil if no heap
	minMemoryAccessException *RamIndex   // Track the minimum index that caused an access exception
}

func NewEmptyRAM() *RAM {
	// 4GB virtual address space via mmap (physical pages allocated on first access)
	buffer, err := unix.Mmap(
		-1, 0,
		RamSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to mmap RAM: %v", err))
	}

	return &RAM{
		buffer:                   buffer,
		access:                   make([]RamAccess, NumRamPages),
		minMemoryAccessException: nil,
	}
}

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
	heapLength := uint64(TotalSizeNeededPages(len(writeData)) + z*PageSize)
	ram.MutateAccessRange(uint64(heapStart), heapLength, Mutable, NoWrap)
	heapStart += RamIndex(heapLength)
	if heapLength > 0 {
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

// Inspect returns the byte at the given index, optionally tracking access violations
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode, trackAccessExceptions bool) byte {
	return r.InspectRange(index, 1, mode, trackAccessExceptions)[0]
}

func (r *RAM) checkAccessViolations(start, length uint64, mode MemoryAccessMode, trackAccessExceptions bool,
	checkType AccessCheckType) {

	if !trackAccessExceptions {
		return
	}

	startPage := uint32(start / PageSize)
	endPage := uint32((start + length - 1) / PageSize)

	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		access := r.getPageAccess(pageNum)
		var isViolation bool
		if checkType == CheckRead {
			isViolation = access == Inaccessible
		} else { // CheckWrite
			isViolation = access == Inaccessible || access == Immutable
		}
		if isViolation {
			pageStart := uint64(pageNum) * PageSize
			violationIndex := max(start, pageStart)

			if mode == Wrap {
				violationIndex = violationIndex % RamSize
			}

			if r.minMemoryAccessException == nil || violationIndex < uint64(*r.minMemoryAccessException) {
				r.minMemoryAccessException = new(RamIndex)
				*r.minMemoryAccessException = RamIndex(violationIndex)
			}
			break
		}
	}
}

func (r *RAM) InspectRange(index, length uint64, mode MemoryAccessMode, trackAccessExceptions bool) []byte {
	if length == 0 {
		return nil
	}

	r.checkAccessViolations(index, length, mode, trackAccessExceptions, CheckRead)

	return r.buffer[index : index+length]
}

func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode, trackAccessExceptions bool) {
	r.MutateRange(index, 1, mode, trackAccessExceptions, func(dest []byte) {
		dest[0] = newByte
	})
}

func (r *RAM) MutateRange(index uint64, length int, mode MemoryAccessMode, trackAccessExceptions bool, fn func([]byte)) {
	if length == 0 {
		return
	}

	r.checkAccessViolations(index, uint64(length), mode, trackAccessExceptions, CheckWrite)

	fn(r.buffer[index : index+uint64(length)])
}

func (r *RAM) getPageAccess(pageNum uint32) RamAccess {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to access permissions for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	return r.access[pageNum]
}

func (r *RAM) pageRangeCheck(start, length uint64, mode MemoryAccessMode, access RamAccess, checkFunc func(RamAccess) bool) bool {
	if length == 0 {
		return false
	}

	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		if access == Inaccessible {
			return true
		}
		return false
	}

	actualStart := start
	if mode == Wrap {
		actualStart = start % RamSize
	}

	startPage := uint32(actualStart / PageSize)
	endPage := uint32((actualStart + length - 1) / PageSize)

	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		if checkFunc(r.getPageAccess(pageNum)) {
			return true
		}
	}

	return false
}

func (r *RAM) RangeHas(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	return r.pageRangeCheck(start, length, mode, access, func(pageAccess RamAccess) bool {
		return pageAccess == access
	})
}

func (r *RAM) RangeUniform(access RamAccess, start, length uint64, mode MemoryAccessMode) bool {
	if length == 0 {
		return true
	}
	return !r.pageRangeCheck(start, length, mode, access, func(pageAccess RamAccess) bool {
		return pageAccess != access
	})
}

func (r *RAM) setPageAccess(pageNum uint32, access RamAccess) {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to set permissions for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	r.access[pageNum] = access
}

func (r *RAM) ZeroPage(pageNum uint32) {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to zero invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	pageStart := uint64(pageNum) * PageSize
	pageEnd := pageStart + PageSize
	clear(r.buffer[pageStart:pageEnd])
}

func (r *RAM) ClearPageAccess(pageNum uint32) {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to clear access for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	r.access[pageNum] = Inaccessible
}

func (r *RAM) MutateAccess(index uint64, access RamAccess, mode MemoryAccessMode) {
	if mode == Wrap {
		index = index % RamSize
	}

	pageNum := uint32(index / PageSize)
	r.setPageAccess(pageNum, access)
}

func (r *RAM) MutateAccessRange(start, length uint64, access RamAccess, mode MemoryAccessMode) {
	if length == 0 {
		return
	}
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return
	}
	actualStart := start
	if mode == Wrap {
		actualStart = start % RamSize
	}
	startPage := uint32(actualStart / PageSize)
	endPage := uint32((actualStart + length - 1) / PageSize)
	for pageNum := startPage; pageNum <= endPage; pageNum++ {
		r.setPageAccess(pageNum, access)
	}
}

func (r *RAM) ClearMemoryAccessExceptions() {
	r.minMemoryAccessException = nil
}

func (r *RAM) GetMinMemoryAccessException() *RamIndex {
	return r.minMemoryAccessException
}
