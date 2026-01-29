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

// emitSbrk: heap allocation (calls into Go runtime)
func (c *Compiler) emitSbrk(rd, ra int, nextPC types.Register) {
	// For now, emit code that exits and lets interpreter handle it
	// This is complex because it needs to call Go functions
	c.emitExitGo(nextPC) // Will be handled by interpreter fallback
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
