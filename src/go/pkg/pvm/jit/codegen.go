//go:build linux && amd64

package jit

import "jam/pkg/types"

// Code generation methods for each PVM instruction

// emitLoadImm64: ra = vx (64-bit immediate)
func (c *Compiler) emitLoadImm64(ra int, vx types.Register) {
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)
}

// emitLoadImm: ra = vx (sign-extended immediate)
func (c *Compiler) emitLoadImm(ra int, vx types.Register) {
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)
}

// emitMoveReg: rd = ra
func (c *Compiler) emitMoveReg(rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	c.storePvmReg(rd, src)
}

// emitHostCall: ecalli vx
func (c *Compiler) emitHostCall(vx types.Register, nextPC types.Register) {
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			c.asm.MovMemReg64(StateReg, offset, pvmRegToX86[pvmReg])
		}
	}
	c.asm.MovRegImm64(RAX, 0x8000000000000000|uint64(vx))
	c.asm.MovRegImm64(RDX, uint64(nextPC))
	c.asm.Pop(RBP)
	c.asm.Pop(R15)
	c.asm.Pop(R14)
	c.asm.Pop(R13)
	c.asm.Pop(R12)
	c.asm.Pop(RBX)
	c.asm.Ret()
}

// emitJump: unconditional jump to vx
func (c *Compiler) emitJump(target types.Register) {
	c.emitExitGo(target)
}

// emitJumpInd: jump to (ra + vx) using dynamic jump table
// Returns DynamicJump exit (exitType=1) with computed 'a' value for Go to process via djump()
func (c *Compiler) emitJumpInd(ra int, vx types.Register) {
	// Compute a = (ra + vx) & 0xFFFFFFFF into ScratchReg2 (RCX)
	src := c.getPvmReg(ra, ScratchReg2)
	if src != ScratchReg2 {
		c.asm.MovRegReg(ScratchReg2, src)
	}
	c.asm.AddRegImm32(ScratchReg2, int32(vx))
	// Mask to 32 bits
	c.asm.MovRegImm64(ScratchReg1, 0xFFFFFFFF)
	c.asm.AndRegReg(ScratchReg2, ScratchReg1)

	// Save registers and return with DynamicJump exit
	// exitEncoded = 0x8100000000000000 | a (exitType=1 for DynamicJump)
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			c.asm.MovMemReg64(StateReg, offset, pvmRegToX86[pvmReg])
		}
	}
	// Now safe to use RAX - ScratchReg2 (RCX) holds the 'a' value
	c.asm.MovRegImm64(RAX, 0x8100000000000000)
	c.asm.OrRegReg(RAX, ScratchReg2) // RAX = 0x8100000000000000 | a
	c.asm.MovRegImm64(RDX, 0)        // nextPC unused for DynamicJump
	c.asm.Pop(RBP)
	c.asm.Pop(R15)
	c.asm.Pop(R14)
	c.asm.Pop(R13)
	c.asm.Pop(R12)
	c.asm.Pop(RBX)
	c.asm.Ret()
}

// emitEpilogueWithReg saves state and returns with nextPC in a register
func (c *Compiler) emitEpilogueWithReg(exitReason uint64, nextPCReg Reg) {
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			c.asm.MovMemReg64(StateReg, offset, pvmRegToX86[pvmReg])
		}
	}
	c.asm.MovRegImm64(RAX, exitReason)
	c.asm.MovRegReg(RDX, nextPCReg)
	c.asm.Pop(RBP)
	c.asm.Pop(R15)
	c.asm.Pop(R14)
	c.asm.Pop(R13)
	c.asm.Pop(R12)
	c.asm.Pop(RBX)
	c.asm.Ret()
}

// emitSbrk: heap allocation via inline mprotect syscall
// φ'_D = min(x ∈ N_R) where x ≥ h and pages [x, x+φ_A) become accessible
// Ra contains the number of pages to allocate
// Rd receives the old heap end (or MaxUint64 on failure)
//
// RAM struct layout:
//
//	offset 0:  buffer.data (ptr, 8 bytes)
//	offset 8:  buffer.len (int, 8 bytes)
//	offset 16: buffer.cap (int, 8 bytes)
//	offset 24: BeginningOfHeap (*RamIndex, 8 bytes) - pointer to uint32
//
// mprotect syscall (Linux x86_64):
//
//	RAX = 10 (SYS_mprotect)
//	RDI = addr (page-aligned)
//	RSI = len
//	RDX = prot (PROT_READ|PROT_WRITE = 3)
//	Returns 0 on success, -errno on failure
//
// Register usage during syscall:
//   - syscall clobbers: RAX (return), RCX, R11
//   - We preserve: R8 (RAM ptr), R9 (heap ptr ptr), R10 (old heap value)
//   - We save/restore: byte length (on stack)
func (c *Compiler) emitSbrk(rd, ra int) {
	const (
		RAMBeginningOfHeapOffset = 56 // Updated: buffer(24) + permissions(24) + hardwareProtection(8)
		SysMprotect              = 10
		ProtReadWrite            = 3 // PROT_READ | PROT_WRITE
	)

	// Load RAM pointer from State
	// ScratchReg4 (R8) = State->RAM
	c.asm.MovRegMem64(ScratchReg4, StateReg, StateRAMOffset)

	// Load BeginningOfHeap pointer
	// ScratchReg5 (R9) = RAM->BeginningOfHeap (this is a *RamIndex, i.e., pointer to uint32)
	c.asm.MovRegMem64(ScratchReg5, ScratchReg4, RAMBeginningOfHeapOffset)

	// Check if BeginningOfHeap is nil (no heap initialized)
	// If nil, return 0 (matching interpreter behavior)
	c.asm.TestRegReg(ScratchReg5, ScratchReg5)
	nilJumpOffset := c.asm.Offset()
	c.asm.JeNear(0) // Jump to nil-heap path if nil - will patch

	// Load current heap end (h) - it's a uint32 at *BeginningOfHeap
	// ScratchReg6 (R10) = *BeginningOfHeap (zero-extended from 32-bit)
	// This is the value we'll return, so we preserve it
	c.asm.MovRegMem32(ScratchReg6, ScratchReg5, 0)

	// Get size (bytes) to allocate from Ra into ScratchReg2 (RCX)
	// (Don't use R11 since syscall clobbers it)
	src := c.getPvmReg(ra, ScratchReg2)
	if src != ScratchReg2 {
		c.asm.MovRegReg(ScratchReg2, src)
	}

	// Check if size == 0 (nothing to allocate, just return current heap)
	c.asm.TestRegReg(ScratchReg2, ScratchReg2)
	zeroJumpOffset := c.asm.Offset()
	c.asm.JeNear(0) // Jump to success (no-op) if zero size - will patch

	// Save values to stack before syscall:
	// - RDI (StateReg) - syscall uses RDI for first arg, we need State pointer after
	// - original size (for heap update after syscall - interpreter adds raw size)
	// - old heap value (for return)
	c.asm.Push(StateReg)    // save State pointer
	c.asm.Push(ScratchReg2) // original size (bytes) - for heap update
	c.asm.Push(ScratchReg6) // old heap value (for return)

	// Compute address = RAM.buffer.data + heap_end
	// RDI = buffer.data + h (for syscall)
	c.asm.MovRegMem64(RDI, ScratchReg4, 0) // RDI = RAM->buffer.data
	c.asm.AddRegReg(RDI, ScratchReg6)      // RDI = buffer.data + h

	// Page-align for mprotect (matching interpreter's mprotectRange):
	// alignedStart = (h / 4096) * 4096 = h & ~0xFFF
	// alignedEnd = ((h + size + 4095) / 4096) * 4096
	// alignedLength = alignedEnd - alignedStart
	// But since buffer.data is page-aligned and we're adding h to it,
	// we need to align the final address, not just h.

	// Save unaligned address in ScratchReg3
	c.asm.MovRegReg(ScratchReg3, RDI)
	// Align address down: RDI = RDI & ~0xFFF (-4096 sign-extends to 0xFFFFFFFFFFFFF000)
	c.asm.AndRegImm32(RDI, -4096)

	// Compute aligned length: (unaligned_addr + size) rounded up - aligned_addr
	// ScratchReg1 = unaligned_addr + size
	c.asm.MovRegReg(ScratchReg1, ScratchReg3)
	c.asm.AddRegReg(ScratchReg1, ScratchReg2)
	// Round up to page: ScratchReg1 = (ScratchReg1 + 4095) & ~0xFFF
	c.asm.AddRegImm32(ScratchReg1, 4095)
	c.asm.AndRegImm32(ScratchReg1, -4096)
	// RSI = aligned_end - aligned_start
	c.asm.MovRegReg(RSI, ScratchReg1)
	c.asm.SubRegReg(RSI, RDI)

	// Set up mprotect syscall
	// RDI = aligned address (already set)
	// RSI = aligned length (already set)
	// RDX = PROT_READ | PROT_WRITE
	c.asm.MovRegImm64(RDX, ProtReadWrite)
	// RAX = SYS_mprotect
	c.asm.MovRegImm64(RAX, SysMprotect)

	// Issue syscall
	c.asm.Syscall()

	// Restore values from stack
	c.asm.Pop(ScratchReg6) // old heap value
	c.asm.Pop(ScratchReg2) // original size (bytes)
	c.asm.Pop(StateReg)    // restore State pointer (RDI)

	// Check result (RAX = 0 on success, negative on failure)
	c.asm.TestRegReg(RAX, RAX)
	syscallFailOffset := c.asm.Offset()
	c.asm.JsNear(0) // Jump to failure if negative (sign bit set) - will patch

	// Success: update BeginningOfHeap
	// Compute new_heap = old_heap + size (matching interpreter behavior)
	c.asm.MovRegReg(ScratchReg1, ScratchReg6) // ScratchReg1 = old heap
	c.asm.AddRegReg(ScratchReg1, ScratchReg2) // ScratchReg1 = old + size = new heap

	// Store new heap end back to *BeginningOfHeap (as 32-bit)
	// R9 still has the pointer to BeginningOfHeap
	c.asm.MovMem32Reg(ScratchReg5, 0, ScratchReg1)

	// Patch zero-pages jump to here (success path)
	// R10 still has old heap value for both paths
	c.patchJumpNear(zeroJumpOffset)

	// Store old heap end in Rd (R10 has the original value)
	c.storePvmReg(rd, ScratchReg6)

	// Jump to continue
	continueJumpOffset := c.asm.Offset()
	c.asm.JmpRel32(0) // Will patch

	// Nil heap path: return 0 (interpreter returns 0 when BeginningOfHeap is nil)
	c.patchJumpNear(nilJumpOffset)
	c.asm.XorRegReg(ScratchReg1, ScratchReg1) // ScratchReg1 = 0
	c.storePvmReg(rd, ScratchReg1)
	c.asm.JmpRel32(0) // Jump to continue - will patch
	nilContinueOffset := c.asm.Offset() - 5

	// Syscall failure path: return MaxUint64
	c.patchJumpNear(syscallFailOffset)
	c.asm.MovRegImm64(ScratchReg1, 0xFFFFFFFFFFFFFFFF)
	c.storePvmReg(rd, ScratchReg1)

	// Patch continue jumps
	c.patchJump32(continueJumpOffset)
	c.patchJump32(nilContinueOffset)
}

// Helper to patch near jumps
func (c *Compiler) patchJumpNear(jumpOffset int) {
	target := c.asm.Offset()
	rel := int32(target - jumpOffset - 6)
	buf := c.asm.Bytes()
	buf[jumpOffset+2] = byte(rel)
	buf[jumpOffset+3] = byte(rel >> 8)
	buf[jumpOffset+4] = byte(rel >> 16)
	buf[jumpOffset+5] = byte(rel >> 24)
}

func (c *Compiler) patchJump32(jumpOffset int) {
	target := c.asm.Offset()
	rel := int32(target - jumpOffset - 5)
	buf := c.asm.Bytes()
	buf[jumpOffset+1] = byte(rel)
	buf[jumpOffset+2] = byte(rel >> 8)
	buf[jumpOffset+3] = byte(rel >> 16)
	buf[jumpOffset+4] = byte(rel >> 24)
}
