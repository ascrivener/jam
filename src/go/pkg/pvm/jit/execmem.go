//go:build linux && amd64

package jit

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	DefaultCodeSize = 16 * 1024 * 1024 // 16MB default (used for initial runtime setup)
)

// ExecutableMemory manages mmap'd memory with execute permissions for JIT code
type ExecutableMemory struct {
	buffer []byte
	used   int
	mu     sync.Mutex
}

// NewExecutableMemory allocates executable memory via mmap
func NewExecutableMemory(size int) (*ExecutableMemory, error) {
	if size <= 0 {
		size = DefaultCodeSize
	}

	// Allocate memory with RWX permissions
	// Note: On some systems you may need to mprotect separately
	buffer, err := unix.Mmap(
		-1, 0,
		size,
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap executable memory: %w", err)
	}

	return &ExecutableMemory{
		buffer: buffer,
		used:   0,
	}, nil
}

// Allocate reserves a chunk of executable memory and returns the pointer
func (em *ExecutableMemory) Allocate(size int) (uintptr, []byte, error) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.used+size > len(em.buffer) {
		return 0, nil, fmt.Errorf("out of executable memory: need %d, have %d", size, len(em.buffer)-em.used)
	}

	slice := em.buffer[em.used : em.used+size]
	addr := uintptr(em.used) + em.BaseAddress()
	em.used += size

	return addr, slice, nil
}

// BaseAddress returns the base address of the executable memory region
func (em *ExecutableMemory) BaseAddress() uintptr {
	if len(em.buffer) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&em.buffer[0]))
}

// Free releases the executable memory
func (em *ExecutableMemory) Free() error {
	em.mu.Lock()
	defer em.mu.Unlock()

	if em.buffer == nil {
		return nil
	}

	err := unix.Munmap(em.buffer)
	em.buffer = nil
	em.used = 0
	return err
}

// Reset clears the used counter, allowing memory to be reused
func (em *ExecutableMemory) Reset() {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.used = 0
}

// Used returns the amount of memory currently in use
func (em *ExecutableMemory) Used() int {
	em.mu.Lock()
	defer em.mu.Unlock()
	return em.used
}

// Capacity returns the total capacity
func (em *ExecutableMemory) Capacity() int {
	return len(em.buffer)
}

// GetBounds returns the start and end addresses of the executable memory region
func (em *ExecutableMemory) GetBounds() (start, end uintptr) {
	if len(em.buffer) == 0 {
		return 0, 0
	}
	start = em.BaseAddress()
	end = start + uintptr(len(em.buffer))
	return
}

// GetBytes returns a copy of the bytes at the given address
func (em *ExecutableMemory) GetBytes(addr uintptr, size int) []byte {
	offset := int(addr - em.BaseAddress())
	if offset < 0 || offset+size > len(em.buffer) {
		return nil
	}
	result := make([]byte, size)
	copy(result, em.buffer[offset:offset+size])
	return result
}
