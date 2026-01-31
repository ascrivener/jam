//go:build linux && amd64

package jit

import "jam/pkg/types"

// emitArith32: 32-bit arithmetic (add, sub, mul)
func (c *Compiler) emitArith32(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	switch opcode {
	case 190: // add_32
		c.asm.AddRegReg32(ScratchReg3, srcB)
	case 191: // sub_32
		c.asm.SubRegReg32(ScratchReg3, srcB)
	case 192: // mul_32
		c.asm.IMulRegReg32(ScratchReg3, srcB)
	}
	c.asm.MovsxdRegReg(ScratchReg3, ScratchReg3)
	c.storePvmReg(rd, ScratchReg3)
}

// emitArith64: 64-bit arithmetic (add, sub, mul)
func (c *Compiler) emitArith64(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	switch opcode {
	case 200: // add_64
		c.asm.AddRegReg(ScratchReg3, srcB)
	case 201: // sub_64
		c.asm.SubRegReg(ScratchReg3, srcB)
	case 202: // mul_64
		c.asm.IMulRegReg(ScratchReg3, srcB)
	}
	c.storePvmReg(rd, ScratchReg3)
}

// emitDiv32: 32-bit division
func (c *Compiler) emitDiv32(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.MovRegImm64(ScratchReg3, 0xFFFFFFFFFFFFFFFF)
	divByZeroJump := c.asm.Offset()
	c.asm.JeNear(0)
	c.asm.MovRegReg(RAX, srcA)
	if opcode == 193 { // div_u_32
		c.asm.XorRegReg(RDX, RDX)
		c.asm.AndRegImm32(RAX, -1)
		c.asm.MovRegReg(ScratchReg4, srcB)
		c.asm.AndRegImm32(ScratchReg4, -1)
		c.asm.Div(ScratchReg4)
	} else { // div_s_32 (194)
		c.asm.CmpRegImm32(srcA, -0x80000000)
		oc1 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.CmpRegImm32(srcB, -1)
		oc2 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.MovRegImm64(ScratchReg3, 0xFFFFFFFF80000000)
		oj := c.asm.Offset()
		c.asm.JmpRel32(0)
		c.patchJumpNear(oc1)
		c.patchJumpNear(oc2)
		c.asm.Cdqe()
		c.asm.Cqo()
		c.asm.MovsxdRegReg(ScratchReg4, srcB)
		c.asm.IDiv(ScratchReg4)
		c.patchJump32(oj)
	}
	c.asm.MovsxdRegReg(ScratchReg3, RAX)
	c.patchJumpNear(divByZeroJump)
	c.storePvmReg(rd, ScratchReg3)
}

// emitDiv64: 64-bit division
func (c *Compiler) emitDiv64(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.MovRegImm64(ScratchReg3, 0xFFFFFFFFFFFFFFFF)
	divByZeroJump := c.asm.Offset()
	c.asm.JeNear(0)
	c.asm.MovRegReg(RAX, srcA)
	if opcode == 203 { // div_u_64
		c.asm.XorRegReg(RDX, RDX)
		c.asm.Div(srcB)
	} else { // div_s_64 (204)
		c.asm.MovRegImm64(ScratchReg4, 0x8000000000000000)
		c.asm.CmpRegReg(srcA, ScratchReg4)
		oc1 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.CmpRegImm32(srcB, -1)
		oc2 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.MovRegReg(ScratchReg3, srcA)
		oj := c.asm.Offset()
		c.asm.JmpRel32(0)
		c.patchJumpNear(oc1)
		c.patchJumpNear(oc2)
		c.asm.Cqo()
		c.asm.IDiv(srcB)
		c.patchJump32(oj)
	}
	c.asm.MovRegReg(ScratchReg3, RAX)
	c.patchJumpNear(divByZeroJump)
	c.storePvmReg(rd, ScratchReg3)
}

// emitRem32: 32-bit remainder
func (c *Compiler) emitRem32(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.MovsxdRegReg(ScratchReg3, srcA)
	divByZeroJump := c.asm.Offset()
	c.asm.JeNear(0)
	c.asm.MovRegReg(RAX, srcA)
	if opcode == 195 { // rem_u_32
		c.asm.XorRegReg(RDX, RDX)
		c.asm.AndRegImm32(RAX, -1)
		c.asm.MovRegReg(ScratchReg4, srcB)
		c.asm.AndRegImm32(ScratchReg4, -1)
		c.asm.Div(ScratchReg4)
		c.asm.MovsxdRegReg(ScratchReg3, RDX)
	} else { // rem_s_32 (196)
		c.asm.CmpRegImm32(srcA, -0x80000000)
		oc1 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.CmpRegImm32(srcB, -1)
		oc2 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.XorRegReg(ScratchReg3, ScratchReg3)
		oj := c.asm.Offset()
		c.asm.JmpRel32(0)
		c.patchJumpNear(oc1)
		c.patchJumpNear(oc2)
		c.asm.Cdqe()
		c.asm.Cqo()
		c.asm.MovsxdRegReg(ScratchReg4, srcB)
		c.asm.IDiv(ScratchReg4)
		c.asm.MovsxdRegReg(ScratchReg3, RDX)
		c.patchJump32(oj)
	}
	c.patchJumpNear(divByZeroJump)
	c.storePvmReg(rd, ScratchReg3)
}

// emitRem64: 64-bit remainder
func (c *Compiler) emitRem64(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.MovRegReg(ScratchReg3, srcA)
	divByZeroJump := c.asm.Offset()
	c.asm.JeNear(0)
	c.asm.MovRegReg(RAX, srcA)
	if opcode == 205 { // rem_u_64
		c.asm.XorRegReg(RDX, RDX)
		c.asm.Div(srcB)
		c.asm.MovRegReg(ScratchReg3, RDX)
	} else { // rem_s_64 (206)
		c.asm.MovRegImm64(ScratchReg4, 0x8000000000000000)
		c.asm.CmpRegReg(srcA, ScratchReg4)
		oc1 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.CmpRegImm32(srcB, -1)
		oc2 := c.asm.Offset()
		c.asm.JneNear(0)
		c.asm.XorRegReg(ScratchReg3, ScratchReg3)
		oj := c.asm.Offset()
		c.asm.JmpRel32(0)
		c.patchJumpNear(oc1)
		c.patchJumpNear(oc2)
		c.asm.Cqo()
		c.asm.IDiv(srcB)
		c.asm.MovRegReg(ScratchReg3, RDX)
		c.patchJump32(oj)
	}
	c.patchJumpNear(divByZeroJump)
	c.storePvmReg(rd, ScratchReg3)
}

// emitAddImm32: ra = rb + vx (32-bit)
func (c *Compiler) emitAddImm32(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.AddRegImm32(ScratchReg2, int32(vx))
	c.asm.MovsxdRegReg(ScratchReg2, ScratchReg2)
	c.storePvmReg(ra, ScratchReg2)
}

// emitAddImm64: ra = rb + vx (64-bit)
func (c *Compiler) emitAddImm64(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.AddRegReg(ScratchReg2, ScratchReg3)
	c.storePvmReg(ra, ScratchReg2)
}

// emitMulImm32: ra = rb * vx (32-bit)
func (c *Compiler) emitMulImm32(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.IMulRegRegImm32(ScratchReg2, src, int32(vx))
	c.asm.MovsxdRegReg(ScratchReg2, ScratchReg2)
	c.storePvmReg(ra, ScratchReg2)
}

// emitMulImm64: ra = rb * vx (64-bit)
func (c *Compiler) emitMulImm64(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.IMulRegReg(ScratchReg2, src)
	c.storePvmReg(ra, ScratchReg2)
}

// emitNegAddImm32: ra = vx - rb (32-bit)
func (c *Compiler) emitNegAddImm32(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.SubRegReg(ScratchReg2, src)
	c.asm.MovsxdRegReg(ScratchReg2, ScratchReg2)
	c.storePvmReg(ra, ScratchReg2)
}

// emitNegAddImm64: ra = vx - rb (64-bit)
func (c *Compiler) emitNegAddImm64(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.SubRegReg(ScratchReg2, src)
	c.storePvmReg(ra, ScratchReg2)
}

// emitMulUpper: high bits of multiplication
func (c *Compiler) emitMulUpper(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(RAX, srcA)
	switch opcode {
	case 213: // mul_upper_s_s
		c.asm.IMulRegReg(RAX, srcB) // This won't work - need special handling
		// For signed*signed upper, we need imul r64, which puts result in rdx:rax
		// Actually we need: imul rdx:rax, src
		c.asm.MovRegReg(RAX, srcA)
		c.asm.emit(rexW(0, srcB), 0xF7, modRM(0xC0, 5, srcB)) // imul srcB
		c.asm.MovRegReg(ScratchReg3, RDX)
	case 214: // mul_upper_u_u
		c.asm.emit(rexW(0, srcB), 0xF7, modRM(0xC0, 4, srcB)) // mul srcB
		c.asm.MovRegReg(ScratchReg3, RDX)
	case 215: // mul_upper_s_u
		// Signed * unsigned upper: upper(a*b) - b if a < 0
		// First do unsigned multiply
		c.asm.emit(rexW(0, srcB), 0xF7, modRM(0xC0, 4, srcB)) // mul srcB (unsigned)
		c.asm.MovRegReg(ScratchReg3, RDX)                     // Save upper result
		// If srcA was negative, subtract srcB from upper result
		c.asm.TestRegReg(srcA, srcA)
		skipAdjust := c.asm.Offset()
		c.asm.JnsNear(0) // Jump if not sign (srcA >= 0)
		c.asm.SubRegReg(ScratchReg3, srcB)
		c.patchJumpNear(skipAdjust)
	}
	c.storePvmReg(rd, ScratchReg3)
}
