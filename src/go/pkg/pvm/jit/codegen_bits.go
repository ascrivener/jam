//go:build linux && amd64

package jit

import "jam/pkg/types"

// Bit manipulation code generation

func (c *Compiler) emitPopcnt(opcode byte, rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	if opcode == 102 { // popcnt64
		c.asm.Popcnt(ScratchReg2, src)
	} else { // popcnt32 (103)
		c.asm.Popcnt32(ScratchReg2, src)
	}
	c.storePvmReg(rd, ScratchReg2)
}

func (c *Compiler) emitLzcnt(opcode byte, rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	if opcode == 104 { // lzcnt64
		c.asm.Lzcnt(ScratchReg2, src)
	} else { // lzcnt32 (105)
		c.asm.Lzcnt32(ScratchReg2, src)
	}
	c.storePvmReg(rd, ScratchReg2)
}

func (c *Compiler) emitTzcnt(opcode byte, rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	if opcode == 106 { // tzcnt64
		c.asm.Tzcnt(ScratchReg2, src)
	} else { // tzcnt32 (107)
		c.asm.Tzcnt32(ScratchReg2, src)
	}
	c.storePvmReg(rd, ScratchReg2)
}

func (c *Compiler) emitSignExtend8(rd, ra int) {
	src := c.getPvmReg(ra, RAX)
	if src != RAX {
		c.asm.MovRegReg(RAX, src)
	}
	c.asm.emit(0x48, 0x0F, 0xBE, 0xC0) // movsx rax, al
	c.storePvmReg(rd, RAX)
}

func (c *Compiler) emitSignExtend16(rd, ra int) {
	src := c.getPvmReg(ra, RAX)
	if src != RAX {
		c.asm.MovRegReg(RAX, src)
	}
	c.asm.emit(0x48, 0x0F, 0xBF, 0xC0) // movsx rax, ax
	c.storePvmReg(rd, RAX)
}

func (c *Compiler) emitZeroExtend16(rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.AndRegImm32(ScratchReg2, 0xFFFF)
	c.storePvmReg(rd, ScratchReg2)
}

func (c *Compiler) emitBswap(rd, ra int) {
	src := c.getPvmReg(ra, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.Bswap(ScratchReg2)
	c.storePvmReg(rd, ScratchReg2)
}

// Logical operations

func (c *Compiler) emitAnd(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.AndRegReg(ScratchReg3, srcB)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitOr(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.OrRegReg(ScratchReg3, srcB)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitXor(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.XorRegReg(ScratchReg3, srcB)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitAndInv(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcB)
	c.asm.NotReg(ScratchReg3)
	c.asm.AndRegReg(ScratchReg3, srcA)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitOrInv(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcB)
	c.asm.NotReg(ScratchReg3)
	c.asm.OrRegReg(ScratchReg3, srcA)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitXnor(rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, srcA)
	c.asm.XorRegReg(ScratchReg3, srcB)
	c.asm.NotReg(ScratchReg3)
	c.storePvmReg(rd, ScratchReg3)
}

// Immediate logical operations

func (c *Compiler) emitAndImm(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.AndRegReg(ScratchReg2, ScratchReg3)
	c.storePvmReg(ra, ScratchReg2)
}

func (c *Compiler) emitOrImm(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.OrRegReg(ScratchReg2, ScratchReg3)
	c.storePvmReg(ra, ScratchReg2)
}

func (c *Compiler) emitXorImm(ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.XorRegReg(ScratchReg2, ScratchReg3)
	c.storePvmReg(ra, ScratchReg2)
}
