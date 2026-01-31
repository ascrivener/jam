package pvm

import (
	"fmt"
	"jam/pkg/constants"
	"jam/pkg/types"
	"runtime/debug"
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

// probeXOR is always 0, but the compiler can't prove it at compile time
// This forces the XOR operation to actually execute
var probeXOR byte = 0

// probeWrite forces a single-byte write that cannot be optimized away
// XORs with probeXOR (always 0) - compiler can't prove it's a no-op since
// probeXOR could theoretically be modified at runtime
//
//go:noinline
func probeWrite(p *byte) {
	*p ^= probeXOR
}

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
	buffer             []byte      // mmap'd 4GB virtual address space
	permissions        []RamAccess // software permission tracking (1 byte per page)
	hardwareProtection bool        // if true, use mprotect (for JIT); if false, software-only (for interpreter)
	BeginningOfHeap    *RamIndex   // nil if no heap
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

// checkReadPermission returns the first faulting address, or 0 if all bytes are readable
// Only used in interpreter mode (hardwareProtection=false)
func (r *RAM) checkReadPermission(start, length uint64) uint64 {
	if length == 0 {
		return 0
	}
	startPage := start / PageSize
	endPage := (start + length - 1) / PageSize
	for page := startPage; page <= endPage; page++ {
		if r.permissions[page] == Inaccessible {
			// Return max(page start, request start) as the faulting address
			pageStart := page * PageSize
			if pageStart > start {
				return pageStart
			}
			return start
		}
	}
	return 0
}

// checkWritePermission returns the first faulting address, or 0 if all bytes are writable
// Only used in interpreter mode (hardwareProtection=false)
func (r *RAM) checkWritePermission(start, length uint64) uint64 {
	if length == 0 {
		return 0
	}
	startPage := start / PageSize
	endPage := (start + length - 1) / PageSize
	for page := startPage; page <= endPage; page++ {
		if r.permissions[page] != Mutable {
			// Return max(page start, request start) as the faulting address
			pageStart := page * PageSize
			if pageStart > start {
				return pageStart
			}
			return start
		}
	}
	return 0
}

// NewEmptyRAM creates a new RAM instance
// If hardwareProtection is true (JIT mode), uses mprotect for hardware enforcement
// If hardwareProtection is false (interpreter mode), uses software-only permission checks
func NewEmptyRAM(hardwareProtection bool) *RAM {
	var prot int
	if hardwareProtection {
		// JIT mode: start as PROT_NONE, mprotect will set permissions as needed
		prot = unix.PROT_NONE
	} else {
		// Interpreter mode: allocate as fully accessible, software checks enforce permissions
		prot = unix.PROT_READ | unix.PROT_WRITE
	}

	buffer, err := unix.Mmap(
		-1, 0,
		RamSize,
		prot,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to mmap RAM: %v", err))
	}

	// Software permission tracking - all pages start as Inaccessible
	permissions := make([]RamAccess, NumRamPages)
	// Default value is 0 which is Inaccessible, so no initialization loop needed

	return &RAM{
		buffer:             buffer,
		permissions:        permissions,
		hardwareProtection: hardwareProtection,
	}
}

func NewRAM(readData, writeData, arguments []byte, z, stackSize int, hardwareProtection bool) *RAM {
	ram := NewEmptyRAM(hardwareProtection)
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

// Inspect returns a byte at the given index (software permission check + hardware protection)
func (r *RAM) Inspect(index uint64, mode MemoryAccessMode) (byte, ExitReason) {
	if mode == Wrap {
		index = index % RamSize
	}
	if faultAddr := r.checkReadPermission(index, 1); faultAddr != 0 {
		if faultAddr < uint64(MinValidRamIndex) {
			return 0, ExitReasonPanic
		}
		return 0, NewComplexExitReason(ExitPageFault, types.Register(faultAddr))
	}
	return r.buffer[index], ExitReasonGo
}

// InspectRange returns a copy of bytes from the buffer (software permission check)
// Returns a NEW slice (not a view into the buffer) to avoid mprotect issues
func (r *RAM) InspectRange(index, length uint64, mode MemoryAccessMode) []byte {
	if length == 0 {
		return []byte{}
	}
	if mode == Wrap {
		index = index % RamSize
	}
	return r.buffer[index : index+length]
}

func (r *RAM) InspectRangeInterpreter(index, length uint64) ([]byte, ExitReason) {
	if faultAddr := r.checkReadPermission(index, length); faultAddr != 0 {
		if faultAddr < uint64(MinValidRamIndex) {
			return nil, ExitReasonPanic
		}
		return nil, NewComplexExitReason(ExitPageFault, types.Register(faultAddr))
	}
	return r.InspectRange(index, length, Wrap), ExitReasonGo
}

// InspectRangeSafe returns a slice of bytes with panic recovery (hardware protection enforced)
// Returns nil if a segmentation fault occurs (accessing protected memory)
func (r *RAM) InspectRangeSafe(index, length uint64) (result []byte) {
	if !r.CanRead(index, length) {
		return nil
	}
	return r.InspectRange(index, length, NoWrap)
}

// CanRead checks if a memory range is readable
// JIT mode: uses probe-based check (actual memory access with recover)
// Interpreter mode: uses software permission array
func (r *RAM) CanRead(index, length uint64) (ok bool) {
	if r.hardwareProtection {
		// JIT mode: probe memory via actual reads
		// SetPanicOnFault makes SIGSEGV recoverable via panic/recover
		prev := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(prev)
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		endIndex := index + length
		for i := index; i < endIndex; i = (i/PageSize + 1) * PageSize {
			probeSink = r.buffer[i]
		}
		return true
	}
	// Interpreter mode: use software permission array
	return r.checkReadPermission(index, length) == 0
}

// CanWrite checks if a memory range is writable
// JIT mode: uses probe-based check (actual memory access with recover)
// Interpreter mode: uses software permission array
func (r *RAM) CanWrite(index, length uint64) (ok bool) {
	if r.hardwareProtection {
		// JIT mode: probe memory via actual writes
		// SetPanicOnFault makes SIGSEGV recoverable via panic/recover
		prev := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(prev)
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		endIndex := index + length
		for i := index; i < endIndex; i = (i/PageSize + 1) * PageSize {
			probeWrite(&r.buffer[i])
		}
		return true
	}
	// Interpreter mode: use software permission array
	return r.checkWritePermission(index, length) == 0
}

// Mutate writes a single byte (software permission check + hardware protection)
func (r *RAM) Mutate(index uint64, newByte byte, mode MemoryAccessMode) ExitReason {
	if mode == Wrap {
		index = index % RamSize
	}
	if faultAddr := r.checkWritePermission(index, 1); faultAddr != 0 {
		if faultAddr < uint64(MinValidRamIndex) {
			return ExitReasonPanic
		}
		return NewComplexExitReason(ExitPageFault, types.Register(faultAddr))
	}
	r.buffer[index] = newByte
	return ExitReasonGo
}

// MutateRange writes bytes via callback (software permission check + hardware protection)
func (r *RAM) MutateRange(index, length uint64, mode MemoryAccessMode, fn func([]byte)) {
	if length == 0 {
		return
	}
	if mode == Wrap {
		index = index % RamSize
	}
	fn(r.buffer[index : index+length])
}

// MutateRangeSafe writes bytes via callback with panic recovery (hardware protection enforced)
// Returns false if a segmentation fault occurs (accessing protected memory)
func (r *RAM) MutateRangeInterpreter(index, length uint64, fn func([]byte)) ExitReason {
	if faultAddr := r.checkWritePermission(index, length); faultAddr != 0 {
		if faultAddr < uint64(MinValidRamIndex) {
			return ExitReasonPanic
		}
		return NewComplexExitReason(ExitPageFault, types.Register(faultAddr))
	}
	r.MutateRange(index, length, Wrap, fn)
	return ExitReasonGo
}

// MutateRangeSafe writes bytes via callback with panic recovery (hardware protection enforced)
// Returns false if a segmentation fault occurs (accessing protected memory)
func (r *RAM) MutateRangeSafe(index, length uint64, fn func([]byte)) (ok bool) {
	if !r.CanWrite(index, length) {
		return false
	}
	r.MutateRange(index, length, NoWrap, fn)
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

// mprotectRange sets software permissions and optionally hardware protection for a memory range
func (r *RAM) mprotectRange(start, length uint64, access RamAccess) {
	if length == 0 {
		return
	}

	// Align start down to page boundary and adjust length
	alignedStart := (start / PageSize) * PageSize
	alignedEnd := ((start + length + PageSize - 1) / PageSize) * PageSize
	alignedLength := alignedEnd - alignedStart

	// Update hardware protection only if enabled (JIT mode)
	if r.hardwareProtection {
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
	} else {
		// Update software permission array
		startPage := alignedStart / PageSize
		endPage := alignedEnd / PageSize
		for page := startPage; page < endPage; page++ {
			r.permissions[page] = access
		}
	}
}

// GetBuffer returns the underlying buffer for direct JIT access
func (r *RAM) GetBuffer() []byte {
	return r.buffer
}

// Legacy compatibility stubs (no longer needed with hardware protection)
func (r *RAM) ClearMemoryAccessExceptions()           {}
func (r *RAM) GetMinMemoryAccessException() *RamIndex { return nil }
