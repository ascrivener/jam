package pvm

// =============================================================================
// Additional x86-64 instruction emitters for the JIT recompiler
// =============================================================================

// emitNot: not reg (one's complement)
func (cb *CodeBuffer) emitNot(reg int) {
	cb.emit(rexByte(true, false, false, reg >= 8))
	cb.emit(0xF7)                   // NOT r/m64
	cb.emit(modRM(3, 2, byte(reg))) // /2 = NOT
}

// emitPopcnt: popcnt destReg, srcReg
func (cb *CodeBuffer) emitPopcnt(destReg, srcReg int, is32bit bool) {
	cb.emit(0xF3) // mandatory prefix
	cb.emit(rexByte(!is32bit, destReg >= 8, false, srcReg >= 8))
	cb.emit(0x0F)
	cb.emit(0xB8) // POPCNT
	cb.emit(modRM(3, byte(destReg), byte(srcReg)))
	if is32bit {
		cb.emitTruncate32(destReg)
	}
}

// emitLzcnt: lzcnt destReg, srcReg
func (cb *CodeBuffer) emitLzcnt(destReg, srcReg int, is32bit bool) {
	cb.emit(0xF3) // mandatory prefix
	cb.emit(rexByte(!is32bit, destReg >= 8, false, srcReg >= 8))
	cb.emit(0x0F)
	cb.emit(0xBD) // LZCNT
	cb.emit(modRM(3, byte(destReg), byte(srcReg)))
	if is32bit {
		cb.emitTruncate32(destReg)
	}
}

// emitTzcnt: tzcnt destReg, srcReg
func (cb *CodeBuffer) emitTzcnt(destReg, srcReg int, is32bit bool) {
	cb.emit(0xF3) // mandatory prefix
	cb.emit(rexByte(!is32bit, destReg >= 8, false, srcReg >= 8))
	cb.emit(0x0F)
	cb.emit(0xBC) // TZCNT
	cb.emit(modRM(3, byte(destReg), byte(srcReg)))
	if is32bit {
		cb.emitTruncate32(destReg)
	}
}

// emitSignExtend8: movsx rax, al (sign extend 8-bit to 64-bit)
func (cb *CodeBuffer) emitSignExtend8(reg int) {
	cb.emit(rexByte(true, reg >= 8, false, reg >= 8))
	cb.emit(0x0F)
	cb.emit(0xBE) // MOVSX r64, r/m8
	cb.emit(modRM(3, byte(reg), byte(reg)))
}

// emitSignExtend16: movsx rax, ax (sign extend 16-bit to 64-bit)
func (cb *CodeBuffer) emitSignExtend16(reg int) {
	cb.emit(rexByte(true, reg >= 8, false, reg >= 8))
	cb.emit(0x0F)
	cb.emit(0xBF) // MOVSX r64, r/m16
	cb.emit(modRM(3, byte(reg), byte(reg)))
}

// emitZeroExtend16: movzx rax, ax (zero extend 16-bit to 64-bit)
func (cb *CodeBuffer) emitZeroExtend16(reg int) {
	cb.emit(rexByte(true, reg >= 8, false, reg >= 8))
	cb.emit(0x0F)
	cb.emit(0xB7) // MOVZX r64, r/m16
	cb.emit(modRM(3, byte(reg), byte(reg)))
}

// emitBswap: bswap reg (byte swap)
func (cb *CodeBuffer) emitBswap(reg int) {
	cb.emit(rexByte(true, false, false, reg >= 8))
	cb.emit(0x0F)
	cb.emit(0xC8 + byte(reg&7)) // BSWAP
}

// emitAddImm: add reg, imm
func (cb *CodeBuffer) emitAddImm(reg int, imm int64) {
	if imm >= -128 && imm <= 127 {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x83) // ADD r/m64, imm8
		cb.emit(modRM(3, 0, byte(reg)))
		cb.emit(byte(imm))
	} else {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x81) // ADD r/m64, imm32
		cb.emit(modRM(3, 0, byte(reg)))
		cb.emitI32(int32(imm))
	}
}

// emitAndImm: and reg, imm
func (cb *CodeBuffer) emitAndImm(reg int, imm int64) {
	if imm >= -128 && imm <= 127 {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x83)
		cb.emit(modRM(3, 4, byte(reg))) // /4 = AND
		cb.emit(byte(imm))
	} else {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x81)
		cb.emit(modRM(3, 4, byte(reg)))
		cb.emitI32(int32(imm))
	}
}

// emitXorImm: xor reg, imm
func (cb *CodeBuffer) emitXorImm(reg int, imm int64) {
	if imm >= -128 && imm <= 127 {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x83)
		cb.emit(modRM(3, 6, byte(reg))) // /6 = XOR
		cb.emit(byte(imm))
	} else {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x81)
		cb.emit(modRM(3, 6, byte(reg)))
		cb.emitI32(int32(imm))
	}
}

// emitOrImm: or reg, imm
func (cb *CodeBuffer) emitOrImm(reg int, imm int64) {
	if imm >= -128 && imm <= 127 {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x83)
		cb.emit(modRM(3, 1, byte(reg))) // /1 = OR
		cb.emit(byte(imm))
	} else {
		cb.emit(rexByte(true, false, false, reg >= 8))
		cb.emit(0x81)
		cb.emit(modRM(3, 1, byte(reg)))
		cb.emitI32(int32(imm))
	}
}

// emitIMulImm: imul reg, reg, imm
func (cb *CodeBuffer) emitIMulImm(reg int, imm int64) {
	if imm >= -128 && imm <= 127 {
		cb.emit(rexByte(true, reg >= 8, false, reg >= 8))
		cb.emit(0x6B) // IMUL r64, r/m64, imm8
		cb.emit(modRM(3, byte(reg), byte(reg)))
		cb.emit(byte(imm))
	} else {
		cb.emit(rexByte(true, reg >= 8, false, reg >= 8))
		cb.emit(0x69) // IMUL r64, r/m64, imm32
		cb.emit(modRM(3, byte(reg), byte(reg)))
		cb.emitI32(int32(imm))
	}
}

// emitShiftImm: shift destReg by immediate amount
// opExt: 0xE0=SHL, 0xE8=SHR, 0xF8=SAR
func (cb *CodeBuffer) emitShiftImm(destReg, srcReg, amount int, opExt byte, truncate32 bool) {
	cb.emitMovReg(destReg, srcReg)
	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	if amount == 1 {
		cb.emit(0xD1) // shift by 1
	} else {
		cb.emit(0xC1) // shift by imm8
	}
	cb.emit(modRM(3, (opExt>>3)&7, byte(destReg)))
	if amount != 1 {
		cb.emit(byte(amount))
	}
	if truncate32 {
		cb.emitTruncate32(destReg)
	}
}

// emitShiftReg: shift destReg = srcReg << (shiftReg % mod)
func (cb *CodeBuffer) emitShiftReg(destReg, srcReg, shiftReg int, opExt byte, truncate32 bool, mod int) {
	// Save RCX if it's not the shift register and we're using it
	needSaveCX := shiftReg != REG_RCX && destReg != REG_RCX && srcReg != REG_RCX
	if needSaveCX {
		cb.emitPush(REG_RCX)
	}

	// Move shift amount to CL
	cb.emitMovReg(REG_RCX, shiftReg)
	// AND with mod-1 to get modulo
	cb.emitAndImm(REG_RCX, int64(mod-1))

	// Move source to dest
	cb.emitMovReg(destReg, srcReg)

	// Perform shift
	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	cb.emit(0xD3) // shift by CL
	cb.emit(modRM(3, (opExt>>3)&7, byte(destReg)))

	if truncate32 {
		cb.emitTruncate32(destReg)
	}

	if needSaveCX {
		cb.emitPop(REG_RCX)
	}
}

// emitShiftRegCL: shift destReg = imm << (shiftReg % mod)
func (cb *CodeBuffer) emitShiftRegCL(destReg int, imm uint64, shiftReg int, opExt byte, truncate32 bool, mod int) {
	// Load immediate into dest
	cb.emitMovImm64(destReg, imm)

	// Save RCX if needed
	needSaveCX := shiftReg != REG_RCX && destReg != REG_RCX
	if needSaveCX {
		cb.emitPush(REG_RCX)
	}

	// Move shift amount to CL
	cb.emitMovReg(REG_RCX, shiftReg)
	cb.emitAndImm(REG_RCX, int64(mod-1))

	// Perform shift
	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	cb.emit(0xD3)
	cb.emit(modRM(3, (opExt>>3)&7, byte(destReg)))

	if truncate32 {
		cb.emitTruncate32(destReg)
	}

	if needSaveCX {
		cb.emitPop(REG_RCX)
	}
}

// emitRotateImm: rotate destReg = srcReg rotated by amount
func (cb *CodeBuffer) emitRotateImm(destReg, srcReg, amount int, truncate32, isLeft bool) {
	cb.emitMovReg(destReg, srcReg)
	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	var opExt byte
	if isLeft {
		opExt = 0 // ROL
	} else {
		opExt = 1 // ROR
	}
	if amount == 1 {
		cb.emit(0xD1)
	} else {
		cb.emit(0xC1)
	}
	cb.emit(modRM(3, opExt, byte(destReg)))
	if amount != 1 {
		cb.emit(byte(amount))
	}
	if truncate32 {
		cb.emitTruncate32(destReg)
	}
}

// emitRotateReg: rotate destReg = srcReg rotated by shiftReg
func (cb *CodeBuffer) emitRotateReg(destReg, srcReg, shiftReg int, truncate32, isLeft bool) {
	needSaveCX := shiftReg != REG_RCX && destReg != REG_RCX && srcReg != REG_RCX
	if needSaveCX {
		cb.emitPush(REG_RCX)
	}

	cb.emitMovReg(REG_RCX, shiftReg)
	mod := 64
	if truncate32 {
		mod = 32
	}
	cb.emitAndImm(REG_RCX, int64(mod-1))
	cb.emitMovReg(destReg, srcReg)

	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	var opExt byte
	if isLeft {
		opExt = 0
	} else {
		opExt = 1
	}
	cb.emit(0xD3)
	cb.emit(modRM(3, opExt, byte(destReg)))

	if truncate32 {
		cb.emitTruncate32(destReg)
	}

	if needSaveCX {
		cb.emitPop(REG_RCX)
	}
}

// emitRotateRegCL: rotate destReg = imm rotated by shiftReg
func (cb *CodeBuffer) emitRotateRegCL(destReg int, imm uint64, shiftReg int, truncate32 bool, mod int) {
	cb.emitMovImm64(destReg, imm)

	needSaveCX := shiftReg != REG_RCX && destReg != REG_RCX
	if needSaveCX {
		cb.emitPush(REG_RCX)
	}

	cb.emitMovReg(REG_RCX, shiftReg)
	cb.emitAndImm(REG_RCX, int64(mod-1))

	if truncate32 {
		cb.emit(rexByte(false, false, false, destReg >= 8))
	} else {
		cb.emit(rexByte(true, false, false, destReg >= 8))
	}
	cb.emit(0xD3)
	cb.emit(modRM(3, 1, byte(destReg))) // ROR

	if truncate32 {
		cb.emitTruncate32(destReg)
	}

	if needSaveCX {
		cb.emitPop(REG_RCX)
	}
}

// emitSetCC: set destReg = (srcReg <cond> imm) ? 1 : 0
func (cb *CodeBuffer) emitSetCC(destReg, srcReg int, imm uint64, ccOpcode byte) {
	// Compare srcReg with immediate
	cb.emitMovImm64(REG_RAX, imm)
	cb.emitCmpReg(srcReg, REG_RAX)

	// SETcc to AL
	cb.emit(0x0F)
	cb.emit(0x90 | (ccOpcode & 0x0F)) // SETcc
	cb.emit(modRM(3, 0, REG_RAX))

	// Zero-extend AL to RAX
	cb.emit(0x48)
	cb.emit(0x0F)
	cb.emit(0xB6) // MOVZX
	cb.emit(modRM(3, REG_RAX, REG_RAX))

	cb.emitMovReg(destReg, REG_RAX)
}

// emitSetLt: set destReg = (regA < regB) ? 1 : 0
func (cb *CodeBuffer) emitSetLt(destReg, regA, regB int, signed bool) {
	cb.emitCmpReg(regA, regB)

	var ccOpcode byte
	if signed {
		ccOpcode = 0x7C // JL -> SETL
	} else {
		ccOpcode = 0x72 // JB -> SETB
	}

	cb.emit(0x0F)
	cb.emit(0x90 | (ccOpcode & 0x0F))
	cb.emit(modRM(3, 0, REG_RAX))

	cb.emit(0x48)
	cb.emit(0x0F)
	cb.emit(0xB6)
	cb.emit(modRM(3, REG_RAX, REG_RAX))

	cb.emitMovReg(destReg, REG_RAX)
}

// emitCmov: if condReg == 0 (or != 0), then destReg = srcReg
func (cb *CodeBuffer) emitCmov(destReg, srcReg, condReg int, ifZero bool) {
	// Test condReg
	cb.emit(rexByte(true, condReg >= 8, false, condReg >= 8))
	cb.emit(0x85) // TEST r/m64, r64
	cb.emit(modRM(3, byte(condReg), byte(condReg)))

	// CMOVcc destReg, srcReg
	cb.emit(rexByte(true, destReg >= 8, false, srcReg >= 8))
	cb.emit(0x0F)
	if ifZero {
		cb.emit(0x44) // CMOVE
	} else {
		cb.emit(0x45) // CMOVNE
	}
	cb.emit(modRM(3, byte(destReg), byte(srcReg)))
}

// emitCmovImm: if condReg == 0 (or != 0), then destReg = imm
func (cb *CodeBuffer) emitCmovImm(destReg, condReg int, imm uint64, ifZero bool) {
	// Load imm into RAX
	cb.emitMovImm64(REG_RAX, imm)

	// Test condReg
	cb.emit(rexByte(true, condReg >= 8, false, condReg >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(condReg), byte(condReg)))

	// CMOVcc destReg, RAX
	cb.emit(rexByte(true, destReg >= 8, false, false))
	cb.emit(0x0F)
	if ifZero {
		cb.emit(0x44)
	} else {
		cb.emit(0x45)
	}
	cb.emit(modRM(3, byte(destReg), REG_RAX))
}

// emitMaxMin: destReg = max/min(regA, regB)
func (cb *CodeBuffer) emitMaxMin(destReg, regA, regB int, signed, isMax bool) {
	cb.emitCmpReg(regA, regB)

	// Select condition
	var ccOpcode byte
	if isMax {
		if signed {
			ccOpcode = 0x4D // CMOVGE (take A if A >= B)
		} else {
			ccOpcode = 0x43 // CMOVAE
		}
	} else {
		if signed {
			ccOpcode = 0x4C // CMOVL (take A if A < B)
		} else {
			ccOpcode = 0x42 // CMOVB
		}
	}

	// Move regB to dest first
	cb.emitMovReg(destReg, regB)

	// CMOVcc destReg, regA (conditionally overwrite with regA)
	cb.emit(rexByte(true, destReg >= 8, false, regA >= 8))
	cb.emit(0x0F)
	cb.emit(ccOpcode)
	cb.emit(modRM(3, byte(destReg), byte(regA)))
}

// =============================================================================
// Division operations (with div-by-zero handling)
// =============================================================================

// emitDivU32: destReg = regA / regB (unsigned 32-bit)
func (cb *CodeBuffer) emitDivU32(destReg, regA, regB int) {
	// Check for div by zero
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0x85) // TEST r32, r32
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75) // JNE (skip div-by-zero handling)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	// Div by zero: result = 0xFFFFFFFF
	cb.emitMovImm64(destReg, 0xFFFFFFFF)
	cb.emit(0xEB) // JMP over normal path
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	// Normal path
	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	// Zero RDX, move dividend to EAX
	cb.emit(0x31) // XOR edx, edx
	cb.emit(modRM(3, REG_RDX, REG_RDX))
	cb.emitMovReg(REG_RAX, regA)
	cb.emitTruncate32(REG_RAX)

	// DIV r32
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 6, byte(regB))) // /6 = DIV

	cb.emitTruncate32(REG_RAX)
	cb.emitMovReg(destReg, REG_RAX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitDivS32: destReg = regA / regB (signed 32-bit)
func (cb *CodeBuffer) emitDivS32(destReg, regA, regB int) {
	// Check for div by zero
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	// Div by zero: result = -1
	cb.emitMovImm64(destReg, 0xFFFFFFFFFFFFFFFF)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	// Move dividend to EAX, sign-extend to EDX:EAX
	cb.emitMovReg(REG_RAX, regA)
	cb.emit(0x99) // CDQ (sign-extend EAX to EDX:EAX)

	// IDIV r32
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 7, byte(regB))) // /7 = IDIV

	cb.emitTruncate32(REG_RAX)
	cb.emitMovReg(destReg, REG_RAX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitRemU32: destReg = regA % regB (unsigned 32-bit)
func (cb *CodeBuffer) emitRemU32(destReg, regA, regB int) {
	// Check for div by zero
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	// Div by zero: result = regA
	cb.emitMovReg(destReg, regA)
	cb.emitTruncate32(destReg)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	cb.emit(0x31)
	cb.emit(modRM(3, REG_RDX, REG_RDX))
	cb.emitMovReg(REG_RAX, regA)
	cb.emitTruncate32(REG_RAX)

	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 6, byte(regB)))

	// Remainder is in EDX
	cb.emitTruncate32(REG_RDX)
	cb.emitMovReg(destReg, REG_RDX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitRemS32: destReg = regA % regB (signed 32-bit)
func (cb *CodeBuffer) emitRemS32(destReg, regA, regB int) {
	// Check for div by zero
	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	cb.emitMovReg(destReg, regA)
	cb.emitTruncate32(destReg)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	cb.emitMovReg(REG_RAX, regA)
	cb.emit(0x99) // CDQ

	cb.emit(rexByte(false, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 7, byte(regB)))

	cb.emitTruncate32(REG_RDX)
	cb.emitMovReg(destReg, REG_RDX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitDivU64: destReg = regA / regB (unsigned 64-bit)
func (cb *CodeBuffer) emitDivU64(destReg, regA, regB int) {
	cb.emit(rexByte(true, regB >= 8, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	cb.emitMovImm64(destReg, 0xFFFFFFFFFFFFFFFF)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	// XOR rdx, rdx
	cb.emit(0x48)
	cb.emit(0x31)
	cb.emit(modRM(3, REG_RDX, REG_RDX))

	cb.emitMovReg(REG_RAX, regA)

	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 6, byte(regB)))

	cb.emitMovReg(destReg, REG_RAX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitDivS64: destReg = regA / regB (signed 64-bit)
func (cb *CodeBuffer) emitDivS64(destReg, regA, regB int) {
	cb.emit(rexByte(true, regB >= 8, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	cb.emitMovImm64(destReg, 0xFFFFFFFFFFFFFFFF)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	cb.emitMovReg(REG_RAX, regA)
	cb.emit(0x48)
	cb.emit(0x99) // CQO (sign-extend RAX to RDX:RAX)

	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 7, byte(regB)))

	cb.emitMovReg(destReg, REG_RAX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitRemU64: destReg = regA % regB (unsigned 64-bit)
func (cb *CodeBuffer) emitRemU64(destReg, regA, regB int) {
	cb.emit(rexByte(true, regB >= 8, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	cb.emitMovReg(destReg, regA)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	cb.emit(0x48)
	cb.emit(0x31)
	cb.emit(modRM(3, REG_RDX, REG_RDX))

	cb.emitMovReg(REG_RAX, regA)

	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 6, byte(regB)))

	cb.emitMovReg(destReg, REG_RDX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// emitRemS64: destReg = regA % regB (signed 64-bit)
func (cb *CodeBuffer) emitRemS64(destReg, regA, regB int) {
	cb.emit(rexByte(true, regB >= 8, false, regB >= 8))
	cb.emit(0x85)
	cb.emit(modRM(3, byte(regB), byte(regB)))

	cb.emit(0x75)
	divByZeroPatch := cb.len()
	cb.emit(0x00)

	cb.emitMovReg(destReg, regA)
	cb.emit(0xEB)
	skipNormalPatch := cb.len()
	cb.emit(0x00)

	normalPos := cb.len()
	cb.patchByte(divByZeroPatch, byte(normalPos-divByZeroPatch-1))

	cb.emitMovReg(REG_RAX, regA)
	cb.emit(0x48)
	cb.emit(0x99)

	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 7, byte(regB)))

	cb.emitMovReg(destReg, REG_RDX)

	afterPos := cb.len()
	cb.patchByte(skipNormalPatch, byte(afterPos-skipNormalPatch-1))
}

// =============================================================================
// Multiplication upper bits
// =============================================================================

// emitMulUpperUU: destReg = (regA * regB) >> 64 (unsigned)
func (cb *CodeBuffer) emitMulUpperUU(destReg, regA, regB int) {
	cb.emitMovReg(REG_RAX, regA)
	// MUL r64 - result in RDX:RAX
	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 4, byte(regB))) // /4 = MUL
	cb.emitMovReg(destReg, REG_RDX)
}

// emitMulUpperSS: destReg = (regA * regB) >> 64 (signed)
func (cb *CodeBuffer) emitMulUpperSS(destReg, regA, regB int) {
	cb.emitMovReg(REG_RAX, regA)
	// IMUL r64 - result in RDX:RAX
	cb.emit(rexByte(true, false, false, regB >= 8))
	cb.emit(0xF7)
	cb.emit(modRM(3, 5, byte(regB))) // /5 = IMUL (one operand form)
	cb.emitMovReg(destReg, REG_RDX)
}

// emitMulUpperSU: destReg = (signed(regA) * unsigned(regB)) >> 64
// This is complex - we'll use a workaround
func (cb *CodeBuffer) emitMulUpperSU(destReg, regA, regB int) {
	// For now, fall back to unsigned multiply and adjust
	// This is an approximation - proper implementation needs more work
	cb.emitMulUpperUU(destReg, regA, regB)
	// TODO: Proper signed*unsigned implementation
}

// =============================================================================
// Indirect memory operations
// =============================================================================

// emitLoadInd: load from RAM[regBase + offset]
// Uses hardware memory protection (mprotect) - no software checks needed
func (cb *CodeBuffer) emitLoadInd(destReg, baseReg int, offset int64, size int, signExtend bool) {
	// Compute address: RAX = regBase + offset (wrapped to 32-bit)
	cb.emitMovReg(REG_RAX, baseReg)
	if offset != 0 {
		cb.emitAddImm(REG_RAX, offset)
	}
	// Truncate to 32-bit for address wrapping
	cb.emitTruncate32(REG_RAX)

	// Load RAM pointer
	cb.emitLoadFromContext(REG_R8, OffsetRAMPtr)

	// Load value directly - hardware protection will fault on invalid access
	switch size {
	case 1:
		if signExtend {
			cb.emit(rexByte(true, destReg >= 8, false, true))
			cb.emit(0x0F)
			cb.emit(0xBE) // MOVSX r64, r/m8
		} else {
			cb.emit(rexByte(true, destReg >= 8, false, true))
			cb.emit(0x0F)
			cb.emit(0xB6) // MOVZX r64, r/m8
		}
		cb.emit(modRM(0, byte(destReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 2:
		if signExtend {
			cb.emit(rexByte(true, destReg >= 8, false, true))
			cb.emit(0x0F)
			cb.emit(0xBF) // MOVSX r64, r/m16
		} else {
			cb.emit(rexByte(true, destReg >= 8, false, true))
			cb.emit(0x0F)
			cb.emit(0xB7) // MOVZX r64, r/m16
		}
		cb.emit(modRM(0, byte(destReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 4:
		if signExtend {
			cb.emit(rexByte(true, destReg >= 8, false, true))
			cb.emit(0x63) // MOVSXD r64, r/m32
		} else {
			cb.emit(rexByte(false, destReg >= 8, false, true))
			cb.emit(0x8B) // MOV r32, r/m32 (zero-extends)
		}
		cb.emit(modRM(0, byte(destReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 8:
		cb.emit(rexByte(true, destReg >= 8, false, true))
		cb.emit(0x8B) // MOV r64, r/m64
		cb.emit(modRM(0, byte(destReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	}
}

// emitStoreInd: store to RAM[regBase + offset]
// Uses hardware memory protection (mprotect) - no software checks needed
func (cb *CodeBuffer) emitStoreInd(srcReg, baseReg int, offset int64, size int) {
	// Compute address: RAX = baseReg + offset (wrapped to 32-bit)
	cb.emitMovReg(REG_RAX, baseReg)
	if offset != 0 {
		cb.emitAddImm(REG_RAX, offset)
	}
	cb.emitTruncate32(REG_RAX)

	// Load RAM pointer
	cb.emitLoadFromContext(REG_R8, OffsetRAMPtr)

	// Store value directly - hardware protection will fault on invalid access
	switch size {
	case 1:
		// MOV [r8 + rax], srcReg_low8
		if srcReg >= 8 {
			cb.emit(rexByte(false, srcReg >= 8, false, true))
		} else {
			cb.emit(0x41) // REX.B for r8
		}
		cb.emit(0x88) // MOV r/m8, r8
		cb.emit(modRM(0, byte(srcReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 2:
		cb.emit(0x66) // operand size prefix
		if srcReg >= 8 {
			cb.emit(rexByte(false, srcReg >= 8, false, true))
		} else {
			cb.emit(0x41)
		}
		cb.emit(0x89) // MOV r/m16, r16
		cb.emit(modRM(0, byte(srcReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 4:
		if srcReg >= 8 {
			cb.emit(rexByte(false, srcReg >= 8, false, true))
		} else {
			cb.emit(0x41)
		}
		cb.emit(0x89) // MOV r/m32, r32
		cb.emit(modRM(0, byte(srcReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	case 8:
		cb.emit(rexByte(true, srcReg >= 8, false, true))
		cb.emit(0x89) // MOV r/m64, r64
		cb.emit(modRM(0, byte(srcReg), 4))
		cb.emit(sib(0, REG_RAX, REG_R8&7))
	}
}
