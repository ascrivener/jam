package jit

import "jam/pkg/types"

// Memory operation code generation

// emitLoad: load from memory at address vx
func (c *Compiler) emitLoad(opcode byte, ra int, addr types.Register) {
	c.asm.MovRegImm64(ScratchReg1, uint64(addr))
	c.asm.AndRegImm32(ScratchReg1, -1)
	c.asm.AddRegReg(ScratchReg1, RAMReg)

	switch opcode {
	case 52: // load_u8
		c.asm.MovRegMem8(ScratchReg1, ScratchReg1, 0)
	case 53: // load_i8
		c.asm.MovRegMem8Signed(ScratchReg1, ScratchReg1, 0)
	case 54: // load_u16
		c.asm.MovRegMem16(ScratchReg1, ScratchReg1, 0)
	case 55: // load_i16
		c.asm.MovRegMem16Signed(ScratchReg1, ScratchReg1, 0)
	case 56: // load_u32
		c.asm.MovRegMem32(ScratchReg1, ScratchReg1, 0)
	case 57: // load_i32
		c.asm.MovRegMem32Signed(ScratchReg1, ScratchReg1, 0)
	case 58: // load_u64
		c.asm.MovRegMem64(ScratchReg1, ScratchReg1, 0)
	}
	c.storePvmReg(ra, ScratchReg1)
}

// emitStore: store register to memory at address vx
func (c *Compiler) emitStore(opcode byte, ra int, addr types.Register) {
	src := c.getPvmReg(ra, ScratchReg1)
	c.asm.MovRegImm64(ScratchReg2, uint64(addr))
	c.asm.AndRegImm32(ScratchReg2, -1)
	c.asm.AddRegReg(ScratchReg2, RAMReg)

	switch opcode {
	case 59: // store_u8
		c.asm.MovMem8Reg(ScratchReg2, 0, src)
	case 60: // store_u16
		c.asm.MovMem16Reg(ScratchReg2, 0, src)
	case 61: // store_u32
		c.asm.MovMem32Reg(ScratchReg2, 0, src)
	case 62: // store_u64
		c.asm.MovMemReg64(ScratchReg2, 0, src)
	}
}

// emitStoreImm: store immediate to memory
func (c *Compiler) emitStoreImm(opcode byte, addr, value types.Register) {
	c.asm.MovRegImm64(ScratchReg1, uint64(value))
	c.asm.MovRegImm64(ScratchReg2, uint64(addr))
	c.asm.AndRegImm32(ScratchReg2, -1)
	c.asm.AddRegReg(ScratchReg2, RAMReg)

	switch opcode {
	case 30: // store_imm_u8
		c.asm.MovMem8Reg(ScratchReg2, 0, ScratchReg1)
	case 31: // store_imm_u16
		c.asm.MovMem16Reg(ScratchReg2, 0, ScratchReg1)
	case 32: // store_imm_u32
		c.asm.MovMem32Reg(ScratchReg2, 0, ScratchReg1)
	case 33: // store_imm_u64
		c.asm.MovMemReg64(ScratchReg2, 0, ScratchReg1)
	}
}

// emitStoreImmInd: store immediate to memory at (ra + vx)
func (c *Compiler) emitStoreImmInd(opcode byte, ra int, offset, value types.Register) {
	base := c.getPvmReg(ra, ScratchReg3)
	c.asm.MovRegImm64(ScratchReg1, uint64(value))
	c.asm.MovRegReg(ScratchReg2, base)
	c.asm.AddRegImm32(ScratchReg2, int32(offset))
	c.asm.AndRegImm32(ScratchReg2, -1)
	c.asm.AddRegReg(ScratchReg2, RAMReg)

	switch opcode {
	case 70: // store_imm_ind_u8
		c.asm.MovMem8Reg(ScratchReg2, 0, ScratchReg1)
	case 71: // store_imm_ind_u16
		c.asm.MovMem16Reg(ScratchReg2, 0, ScratchReg1)
	case 72: // store_imm_ind_u32
		c.asm.MovMem32Reg(ScratchReg2, 0, ScratchReg1)
	case 73: // store_imm_ind_u64
		c.asm.MovMemReg64(ScratchReg2, 0, ScratchReg1)
	}
}

// emitLoadInd: load from (rb + vx) to ra
func (c *Compiler) emitLoadInd(opcode byte, ra, rb int, offset types.Register) {
	base := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg1, base)
	c.asm.AddRegImm32(ScratchReg1, int32(offset))
	c.asm.AndRegImm32(ScratchReg1, -1)
	c.asm.AddRegReg(ScratchReg1, RAMReg)

	switch opcode {
	case 124: // load_ind_u8
		c.asm.MovRegMem8(ScratchReg1, ScratchReg1, 0)
	case 125: // load_ind_i8
		c.asm.MovRegMem8Signed(ScratchReg1, ScratchReg1, 0)
	case 126: // load_ind_u16
		c.asm.MovRegMem16(ScratchReg1, ScratchReg1, 0)
	case 127: // load_ind_i16
		c.asm.MovRegMem16Signed(ScratchReg1, ScratchReg1, 0)
	case 128: // load_ind_u32
		c.asm.MovRegMem32(ScratchReg1, ScratchReg1, 0)
	case 129: // load_ind_i32
		c.asm.MovRegMem32Signed(ScratchReg1, ScratchReg1, 0)
	case 130: // load_ind_u64
		c.asm.MovRegMem64(ScratchReg1, ScratchReg1, 0)
	}
	c.storePvmReg(ra, ScratchReg1)
}

// emitStoreInd: store ra to (rb + vx)
func (c *Compiler) emitStoreInd(opcode byte, ra, rb int, offset types.Register) {
	src := c.getPvmReg(ra, ScratchReg1)
	base := c.getPvmReg(rb, ScratchReg2)
	c.asm.MovRegReg(ScratchReg3, base)
	c.asm.AddRegImm32(ScratchReg3, int32(offset))
	c.asm.AndRegImm32(ScratchReg3, -1)
	c.asm.AddRegReg(ScratchReg3, RAMReg)

	switch opcode {
	case 120: // store_ind_u8
		c.asm.MovMem8Reg(ScratchReg3, 0, src)
	case 121: // store_ind_u16
		c.asm.MovMem16Reg(ScratchReg3, 0, src)
	case 122: // store_ind_u32
		c.asm.MovMem32Reg(ScratchReg3, 0, src)
	case 123: // store_ind_u64
		c.asm.MovMemReg64(ScratchReg3, 0, src)
	}
}
