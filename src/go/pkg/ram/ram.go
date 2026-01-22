package ram

import (
	"fmt"
	"jam/pkg/constants"
	"unsafe"

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

// probeSink prevents the compiler from optimizing away memory probes
var probeSink byte

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

type RamIndex uint32

func TotalSizeNeededMajorZones(size int) int {
	return MajorZoneSize * ((MajorZoneSize + size - 1) / MajorZoneSize)
}

func TotalSizeNeededPages(size int) int {
	return PageSize * ((PageSize + size - 1) / PageSize)
}

type RAM struct {
	buffer          []byte    // mmap'd 4GB virtual address space (mprotect enforces permissions)
	BeginningOfHeap *RamIndex // nil if no heap
}

// BufferBase returns the base address of the RAM buffer for computing fault offsets
func (r *RAM) BufferBase() uintptr {
	return uintptr(unsafe.Pointer(&r.buffer[0]))
}

// AddressToIndex converts a faulting address to a RAM index, returns nil if outside buffer
func (r *RAM) AddressToIndex(addr uintptr) *RamIndex {
	base := r.BufferBase()
	if addr < base {
		return nil
	}
	offset := addr - base
	if offset >= uintptr(RamSize) {
		return nil
	}
	idx := RamIndex(offset)
	return &idx
}

func NewEmptyRAM() *RAM {
	// 4GB virtual address space via mmap, starts as PROT_NONE (inaccessible)
	buffer, err := unix.Mmap(
		-1, 0,
		RamSize,
		unix.PROT_NONE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to mmap RAM: %v", err))
	}

	return &RAM{
		buffer: buffer,
	}
}

func NewRAM(readData, writeData, arguments []byte, z, stackSize int) *RAM {
	ram := NewEmptyRAM()
	heapStart := RamIndex(2*MajorZoneSize + TotalSizeNeededMajorZones(len(readData)))

	// read-only section: set writable first, write data, then make immutable
	ram.MutateAccessRange(MajorZoneSize, uint64(TotalSizeNeededPages(len(readData))), Mutable, NoWrap)
	copy(ram.buffer[MajorZoneSize:], readData)
	ram.MutateAccessRange(MajorZoneSize, uint64(TotalSizeNeededPages(len(readData))), Immutable, NoWrap)

	// heap: set writable, write initial data
	heapLength := uint64(TotalSizeNeededPages(len(writeData)) + z*PageSize)
	ram.MutateAccessRange(uint64(heapStart), heapLength, Mutable, NoWrap)
	copy(ram.buffer[heapStart:], writeData)
	heapStart += RamIndex(heapLength)
	if heapLength > 0 {
		ram.BeginningOfHeap = &heapStart
	}

	// stack: just set writable
	stackStart := RamIndex(RamSize - 2*MajorZoneSize - ArgumentsZoneSize - TotalSizeNeededPages(stackSize))
	ram.MutateAccessRange(uint64(stackStart), uint64(TotalSizeNeededPages(stackSize)), Mutable, NoWrap)

	// arguments: set writable, write data, then make immutable
	argumentsStart := RamIndex(RamSize - MajorZoneSize - ArgumentsZoneSize)
	ram.MutateAccessRange(uint64(argumentsStart), uint64(TotalSizeNeededPages(len(arguments))), Mutable, NoWrap)
	copy(ram.buffer[argumentsStart:], arguments)
	ram.MutateAccessRange(uint64(argumentsStart), uint64(TotalSizeNeededPages(len(arguments))), Immutable, NoWrap)

	return ram
}

// Inspect returns a byte at the given index (hardware protection enforced)
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode) byte {
	if mode == Wrap {
		index = index % RamSize
	}
	return r.buffer[index]
}

// InspectRange returns a slice of bytes (hardware protection enforced)
func (r *RAM) InspectRange(index, length uint64, mode MemoryAccessMode) []byte {
	if length == 0 {
		return []byte{}
	}
	if mode == Wrap {
		index = index % RamSize
		// Handle wrap-around: if access crosses RamSize boundary, split it
		if index+length > RamSize {
			result := make([]byte, length)
			firstPart := RamSize - index
			copy(result[:firstPart], r.buffer[index:RamSize])
			copy(result[firstPart:], r.buffer[0:length-firstPart]) // will fault on low memory
			return result
		}
	}
	return r.buffer[index : index+length]
}

// InspectRangeSafe returns a slice of bytes with panic recovery (hardware protection enforced)
// Returns nil if a segmentation fault occurs (accessing protected memory)
func (r *RAM) InspectRangeSafe(index, length uint64, mode MemoryAccessMode) (result []byte) {
	defer func() {
		if recover() != nil {
			result = nil
		}
	}()

	data := r.InspectRange(index, length, mode)

	// Probe through the slice at page boundaries to trigger any segfaults
	// Use probeSink to prevent compiler from optimizing away the reads
	for i := uint64(0); i < length; i += PageSize {
		probeSink = data[i]
	}
	// Also probe the last byte if not already covered
	if length > 0 {
		probeSink = data[length-1]
	}

	return data
}

// Mutate writes a single byte (hardware protection enforced)
func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode) {
	if mode == Wrap {
		index = index % RamSize
	}
	r.buffer[index] = newByte
}

// MutateRange writes bytes via callback (hardware protection enforced)
func (r *RAM) MutateRange(index uint64, length int, mode MemoryAccessMode, fn func([]byte)) {
	if length == 0 {
		return
	}
	if mode == Wrap {
		index = index % RamSize
		// Handle wrap-around: if access crosses RamSize boundary, split it
		if index+uint64(length) > RamSize {
			tmp := make([]byte, length)
			firstPart := RamSize - index
			copy(tmp[:firstPart], r.buffer[index:RamSize])
			copy(tmp[firstPart:], r.buffer[0:uint64(length)-firstPart]) // will fault on low memory
			fn(tmp)
			// Write back
			copy(r.buffer[index:RamSize], tmp[:firstPart])
			copy(r.buffer[0:uint64(length)-firstPart], tmp[firstPart:]) // will fault on low memory
			return
		}
	}
	fn(r.buffer[index : index+uint64(length)])
}

// MutateRangeSafe writes bytes via callback with panic recovery (hardware protection enforced)
// Returns false if a segmentation fault occurs (accessing protected memory)
func (r *RAM) MutateRangeSafe(index uint64, length int, mode MemoryAccessMode, fn func([]byte)) (ok bool) {
	defer func() {
		if rec := recover(); rec != nil {
			// Segfault occurred - return false to indicate inaccessible memory
			ok = false
		}
	}()
	r.MutateRange(index, length, mode, fn)
	return true
}

// ZeroPage clears a page (must be writable)
func (r *RAM) ZeroPage(pageNum uint32) {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to zero invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	pageStart := uint64(pageNum) * PageSize
	pageEnd := pageStart + PageSize
	clear(r.buffer[pageStart:pageEnd])
}

// ClearPageAccess sets a page to inaccessible
func (r *RAM) ClearPageAccess(pageNum uint32) {
	if pageNum >= NumRamPages {
		panic(fmt.Sprintf("Attempted to clear access for invalid page %d (max is %d)", pageNum, NumRamPages-1))
	}
	r.mprotectRange(uint64(pageNum)*PageSize, PageSize, Inaccessible)
}

// MutateAccessRange changes protection for a range using mprotect
func (r *RAM) MutateAccessRange(start, length uint64, access RamAccess, mode MemoryAccessMode) {
	if length == 0 {
		return
	}
	if mode == NoWrap && (start >= RamSize || RamSize-start < length) {
		return
	}
	if mode == Wrap {
		start = start % RamSize
	}
	r.mprotectRange(start, length, access)
}

// mprotectRange sets OS-level page protection for a memory range
func (r *RAM) mprotectRange(start, length uint64, access RamAccess) {
	if length == 0 {
		return
	}

	// Align start down to page boundary and adjust length
	alignedStart := (start / PageSize) * PageSize
	alignedEnd := ((start + length + PageSize - 1) / PageSize) * PageSize
	alignedLength := alignedEnd - alignedStart

	var prot int
	switch access {
	case Inaccessible:
		prot = unix.PROT_NONE
	case Immutable:
		prot = unix.PROT_READ
	case Mutable:
		prot = unix.PROT_READ | unix.PROT_WRITE
	}

	err := unix.Mprotect(unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(&r.buffer[0]), alignedStart)), alignedLength), prot)
	if err != nil {
		panic(fmt.Sprintf("mprotect failed: start=0x%x length=0x%x access=%d err=%v", alignedStart, alignedLength, access, err))
	}

}

// GetBuffer returns the underlying buffer for direct JIT access
func (r *RAM) GetBuffer() []byte {
	return r.buffer
}

// Legacy compatibility stubs (no longer needed with hardware protection)
func (r *RAM) ClearMemoryAccessExceptions()           {}
func (r *RAM) GetMinMemoryAccessException() *RamIndex { return nil }
