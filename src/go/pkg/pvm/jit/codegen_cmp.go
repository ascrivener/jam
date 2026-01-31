//go:build linux && amd64

package jit

import "jam/pkg/types"

// Comparison and conditional move code generation

func (c *Compiler) emitSetLtImm(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.XorRegReg(ScratchReg3, ScratchReg3) // Zero before compare (XOR clobbers flags)
	c.asm.CmpRegReg(src, ScratchReg2)
	if opcode == 136 { // set_lt_u_imm
		c.asm.Setb(ScratchReg3)
	} else { // set_lt_s_imm (137)
		c.asm.Setl(ScratchReg3)
	}
	c.asm.MovzxRegReg8(ScratchReg3, ScratchReg3)
	c.storePvmReg(ra, ScratchReg3)
}

func (c *Compiler) emitSetGtImm(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(vx))
	c.asm.XorRegReg(ScratchReg3, ScratchReg3) // Zero before compare (XOR clobbers flags)
	c.asm.CmpRegReg(src, ScratchReg2)
	if opcode == 142 { // set_gt_u_imm
		c.asm.Seta(ScratchReg3)
	} else { // set_gt_s_imm (143)
		c.asm.Setg(ScratchReg3)
	}
	c.asm.MovzxRegReg8(ScratchReg3, ScratchReg3)
	c.storePvmReg(ra, ScratchReg3)
}

func (c *Compiler) emitSetLt(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.XorRegReg(ScratchReg3, ScratchReg3) // Zero before compare (XOR clobbers flags)
	c.asm.CmpRegReg(srcA, srcB)
	if opcode == 216 { // set_lt_u
		c.asm.Setb(ScratchReg3)
	} else { // set_lt_s (217)
		c.asm.Setl(ScratchReg3)
	}
	c.asm.MovzxRegReg8(ScratchReg3, ScratchReg3)
	c.storePvmReg(rd, ScratchReg3)
}

// Conditional moves

func (c *Compiler) emitCmovIz(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	dst := c.getPvmReg(rd, ScratchReg3)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.Cmove(dst, srcA)
	c.storePvmReg(rd, dst)
}

func (c *Compiler) emitCmovNz(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	dst := c.getPvmReg(rd, ScratchReg3)
	c.asm.TestRegReg(srcB, srcB)
	c.asm.Cmovne(dst, srcA)
	c.storePvmReg(rd, dst)
}

func (c *Compiler) emitCmovIzImm(ra, rb int, vx types.Register) {
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	notZeroJump := c.asm.Offset()
	c.asm.JneNear(0)
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)
	c.patchJumpNear(notZeroJump)
}

func (c *Compiler) emitCmovNzImm(ra, rb int, vx types.Register) {
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.TestRegReg(srcB, srcB)
	zeroJump := c.asm.Offset()
	c.asm.JeNear(0)
	c.asm.MovRegImm64(ScratchReg1, uint64(vx))
	c.storePvmReg(ra, ScratchReg1)
	c.patchJumpNear(zeroJump)
}

// Min/Max operations

func (c *Compiler) emitMax(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.CmpRegReg(srcA, srcB)
	if opcode == 227 { // max (signed)
		c.asm.Cmovl(ScratchReg3, srcB)
	} else { // max_u (228, unsigned)
		c.asm.Cmovb(ScratchReg3, srcB)
	}
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitMin(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.CmpRegReg(srcA, srcB)
	if opcode == 229 { // min (signed)
		c.asm.Cmovg(ScratchReg3, srcB)
	} else { // min_u (230, unsigned)
		c.asm.Cmova(ScratchReg3, srcB)
	}
	c.storePvmReg(rd, ScratchReg3)
}
