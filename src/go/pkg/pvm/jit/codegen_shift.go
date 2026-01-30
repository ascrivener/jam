package jit

import "jam/pkg/types"

// Shift and rotate code generation

func (c *Compiler) emitShift32(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, RCX)
	if srcB != RCX {
		c.asm.MovRegReg(RCX, srcB)
	}
	c.asm.AndRegImm32(RCX, 31)
	c.asm.MovRegReg(ScratchReg3, srcA)
	switch opcode {
	case 197: // shlo_l_32
		c.asm.Shl32RegCL(ScratchReg3)
	case 198: // shlo_r_32
		c.asm.Shr32RegCL(ScratchReg3)
	case 199: // shar_r_32
		c.asm.Sar32RegCL(ScratchReg3)
	}
	c.asm.MovsxdRegReg(ScratchReg3, ScratchReg3)
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitShift64(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, RCX)
	if srcB != RCX {
		c.asm.MovRegReg(RCX, srcB)
	}
	c.asm.AndRegImm32(RCX, 63)
	c.asm.MovRegReg(ScratchReg3, srcA)
	switch opcode {
	case 207: // shlo_l_64
		c.asm.ShlRegCL(ScratchReg3)
	case 208: // shlo_r_64
		c.asm.ShrRegCL(ScratchReg3)
	case 209: // shar_r_64
		c.asm.SarRegCL(ScratchReg3)
	}
	c.storePvmReg(rd, ScratchReg3)
}

func (c *Compiler) emitShiftImm32(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	shift := byte(vx % 32)
	switch opcode {
	case 138: // shlo_l_imm_32
		c.asm.Shl32RegImm8(ScratchReg2, shift)
	case 139: // shlo_r_imm_32
		c.asm.Shr32RegImm8(ScratchReg2, shift)
	case 140: // shar_r_imm_32
		c.asm.Sar32RegImm8(ScratchReg2, shift)
	}
	c.asm.MovsxdRegReg(ScratchReg2, ScratchReg2)
	c.storePvmReg(ra, ScratchReg2)
}

func (c *Compiler) emitShiftImm64(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg1)
	c.asm.MovRegReg(ScratchReg2, src)
	shift := byte(vx % 64)
	switch opcode {
	case 151: // shlo_l_imm_64
		c.asm.ShlRegImm8(ScratchReg2, shift)
	case 152: // shlo_r_imm_64
		c.asm.ShrRegImm8(ScratchReg2, shift)
	case 153: // shar_r_imm_64
		c.asm.SarRegImm8(ScratchReg2, shift)
	}
	c.storePvmReg(ra, ScratchReg2)
}

func (c *Compiler) emitShiftImmAlt32(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg4)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.MovRegReg(RCX, src)
	c.asm.AndRegImm32(RCX, 31)
	switch opcode {
	case 144: // shlo_l_imm_alt_32
		c.asm.Shl32RegCL(ScratchReg3)
	case 145: // shlo_r_imm_alt_32
		c.asm.Shr32RegCL(ScratchReg3)
	case 146: // shar_r_imm_alt_32
		c.asm.Sar32RegCL(ScratchReg3)
	}
	c.asm.MovsxdRegReg(ScratchReg3, ScratchReg3)
	c.storePvmReg(ra, ScratchReg3)
}

func (c *Compiler) emitShiftImmAlt64(opcode byte, ra, rb int, vx types.Register) {
	src := c.getPvmReg(rb, ScratchReg4)
	c.asm.MovRegImm64(ScratchReg3, uint64(vx))
	c.asm.MovRegReg(RCX, src)
	c.asm.AndRegImm32(RCX, 63)
	switch opcode {
	case 155: // shlo_l_imm_alt_64
		c.asm.ShlRegCL(ScratchReg3)
	case 156: // shlo_r_imm_alt_64
		c.asm.ShrRegCL(ScratchReg3)
	case 157: // shar_r_imm_alt_64
		c.asm.SarRegCL(ScratchReg3)
	}
	c.storePvmReg(ra, ScratchReg3)
}

// Rotation operations

func (c *Compiler) emitRotL(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg3) // Use ScratchReg3 to avoid clobbering
	c.asm.MovRegReg(ScratchReg4, srcA)   // Use ScratchReg4 for value (not RCX!)
	c.asm.MovRegReg(RCX, srcB)           // Move count to RCX last
	if opcode == 220 {                   // rot_l_64
		c.asm.AndRegImm32(RCX, 63)
		c.asm.RolRegCL(ScratchReg4)
	} else { // rot_l_32 (221)
		c.asm.AndRegImm32(RCX, 31)
		c.asm.Rol32RegCL(ScratchReg4)
		c.asm.MovsxdRegReg(ScratchReg4, ScratchReg4)
	}
	c.storePvmReg(rd, ScratchReg4)
}

func (c *Compiler) emitRotR(opcode byte, rd, ra, rb int) {
	srcA := c.getPvmReg(ra, ScratchReg1)
	srcB := c.getPvmReg(rb, ScratchReg3) // Use ScratchReg3 to avoid clobbering
	c.asm.MovRegReg(ScratchReg4, srcA)   // Use ScratchReg4 for value (not RCX!)
	c.asm.MovRegReg(RCX, srcB)           // Move count to RCX last
	if opcode == 222 {                   // rot_r_64
		c.asm.AndRegImm32(RCX, 63)
		c.asm.RorRegCL(ScratchReg4)
	} else { // rot_r_32 (223)
		c.asm.AndRegImm32(RCX, 31)
		c.asm.Ror32RegCL(ScratchReg4)
		c.asm.MovsxdRegReg(ScratchReg4, ScratchReg4)
	}
	c.storePvmReg(rd, ScratchReg4)
}

func (c *Compiler) emitRotR64Imm(opcode byte, ra, rb int, vx types.Register) {
	if opcode == 158 { // rot_r_64_imm: rotate rb by immediate
		src := c.getPvmReg(rb, ScratchReg1)
		c.asm.MovRegReg(ScratchReg4, src)
		c.asm.RorRegImm8(ScratchReg4, byte(vx%64))
	} else { // rot_r_64_imm_alt (159): rotate immediate by rb
		src := c.getPvmReg(rb, RCX)
		if src != RCX {
			c.asm.MovRegReg(RCX, src)
		}
		c.asm.AndRegImm32(RCX, 63)
		c.asm.MovRegImm64(ScratchReg4, uint64(vx))
		c.asm.RorRegCL(ScratchReg4)
	}
	c.storePvmReg(ra, ScratchReg4)
}

func (c *Compiler) emitRotR32Imm(opcode byte, ra, rb int, vx types.Register) {
	if opcode == 160 { // rot_r_32_imm
		src := c.getPvmReg(rb, ScratchReg1)
		c.asm.MovRegReg(ScratchReg4, src)
		c.asm.Ror32RegImm8(ScratchReg4, byte(vx%32))
	} else { // rot_r_32_imm_alt (161)
		src := c.getPvmReg(rb, RCX)
		if src != RCX {
			c.asm.MovRegReg(RCX, src)
		}
		c.asm.AndRegImm32(RCX, 31)
		c.asm.MovRegImm64(ScratchReg4, uint64(vx))
		c.asm.Ror32RegCL(ScratchReg4)
	}
	c.asm.MovsxdRegReg(ScratchReg4, ScratchReg4)
	c.storePvmReg(ra, ScratchReg4)
}
