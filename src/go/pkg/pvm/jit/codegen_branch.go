package jit

import "jam/pkg/types"

// Branch and jump code generation

// emitLoadImmJump: ra = vx, then jump to vy
func (c *Compiler) emitLoadImmJump(ra int, vx, target types.Register) {
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)
	c.emitExitGo(target)
}

// emitBranchImm: conditional branch based on comparing ra with immediate
func (c *Compiler) emitBranchImm(opcode byte, ra int, vx, target, nextPC types.Register) {
	src := c.getPvmReg(ra, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.CmpRegReg(src, ScratchReg2)

	switch opcode {
	case 80: // load_imm_jump (unconditional after load)
		c.emitLoadImmJump(ra, vx, target)
		return
	case 81: // branch_eq_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JneNear(0) })
	case 82: // branch_ne_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JeNear(0) })
	case 83: // branch_lt_u_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JaeNear(0) })
	case 84: // branch_le_u_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JaNear(0) })
	case 85: // branch_ge_u_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JbNear(0) })
	case 86: // branch_gt_u_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JbeNear(0) })
	case 87: // branch_lt_s_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JgeNear(0) })
	case 88: // branch_le_s_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JgNear(0) })
	case 89: // branch_ge_s_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JlNear(0) })
	case 90: // branch_gt_s_imm
		c.emitConditionalExit(target, nextPC, func() { c.asm.JleNear(0) })
	}
}

// emitConditionalExit: emit code that exits to target if condition is true, else to nextPC
func (c *Compiler) emitConditionalExit(target, nextPC types.Register, emitJumpIfFalse func()) {
	jumpOffset := c.asm.Offset()
	emitJumpIfFalse()
	c.emitExitGo(target)
	notTakenOffset := c.asm.Offset()
	rel := int32(notTakenOffset - jumpOffset - 6)
	buf := c.asm.Bytes()
	buf[jumpOffset+2] = byte(rel)
	buf[jumpOffset+3] = byte(rel >> 8)
	buf[jumpOffset+4] = byte(rel >> 16)
	buf[jumpOffset+5] = byte(rel >> 24)
	c.emitExitGo(nextPC)
}

// emitBranchReg: conditional branch comparing two registers
func (c *Compiler) emitBranchReg(opcode byte, ra, rb int, target, nextPC types.Register) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.CmpRegReg(srcA, srcB)

	switch opcode {
	case 170: // branch_eq
		c.emitConditionalExit(target, nextPC, func() { c.asm.JneNear(0) })
	case 171: // branch_ne
		c.emitConditionalExit(target, nextPC, func() { c.asm.JeNear(0) })
	case 172: // branch_lt_u
		c.emitConditionalExit(target, nextPC, func() { c.asm.JaeNear(0) })
	case 173: // branch_lt_s
		c.emitConditionalExit(target, nextPC, func() { c.asm.JgeNear(0) })
	case 174: // branch_ge_u
		c.emitConditionalExit(target, nextPC, func() { c.asm.JbNear(0) })
	case 175: // branch_ge_s
		c.emitConditionalExit(target, nextPC, func() { c.asm.JlNear(0) })
	}
}

// emitLoadImmJumpInd: ra = vx, then jump to (rb + vy) via dynamic jump table
// Returns DynamicJump exit (exitType=1) with computed 'a' value for Go to process via djump()
func (c *Compiler) emitLoadImmJumpInd(ra, rb int, vx, vy types.Register) {
	// First: ra = vx
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)

	// Compute a = (rb + vy) & 0xFFFFFFFF
	base := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, base)
	c.asm.AddRegImm32(ScratchReg2, int32(vy))
	c.asm.MovRegImm64(ScratchReg1, 0xFFFFFFFF)
	c.asm.AndRegReg(ScratchReg2, ScratchReg1)

	// Save registers and return with DynamicJump exit
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			c.asm.MovMemReg64(StateReg, offset, pvmRegToX86[pvmReg])
		}
	}
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
