package jit

import (
	"encoding/binary"
)

// x86-64 register encoding
type Reg byte

const (
	RAX Reg = 0
	RCX Reg = 1
	RDX Reg = 2
	RBX Reg = 3
	RSP Reg = 4
	RBP Reg = 5
	RSI Reg = 6
	RDI Reg = 7
	R8  Reg = 8
	R9  Reg = 9
	R10 Reg = 10
	R11 Reg = 11
	R12 Reg = 12
	R13 Reg = 13
	R14 Reg = 14
	R15 Reg = 15
)

// Assembler emits x86-64 machine code
type Assembler struct {
	buf    []byte
	offset int
}

// NewAssembler creates an assembler targeting the given buffer
func NewAssembler(buf []byte) *Assembler {
	return &Assembler{buf: buf, offset: 0}
}

// Offset returns current write position
func (a *Assembler) Offset() int {
	return a.offset
}

// Bytes returns the assembled code
func (a *Assembler) Bytes() []byte {
	return a.buf[:a.offset]
}

// emit appends bytes to the buffer
func (a *Assembler) emit(bytes ...byte) {
	copy(a.buf[a.offset:], bytes)
	a.offset += len(bytes)
}

// emitUint32 appends a little-endian uint32
func (a *Assembler) emitUint32(v uint32) {
	binary.LittleEndian.PutUint32(a.buf[a.offset:], v)
	a.offset += 4
}

// emitUint64 appends a little-endian uint64
func (a *Assembler) emitUint64(v uint64) {
	binary.LittleEndian.PutUint64(a.buf[a.offset:], v)
	a.offset += 8
}

// emitInt32 appends a little-endian int32
func (a *Assembler) emitInt32(v int32) {
	binary.LittleEndian.PutUint32(a.buf[a.offset:], uint32(v))
	a.offset += 4
}

// rex builds REX prefix: 0100WRXB
// W=1 for 64-bit operand size
// R=1 if reg field uses R8-R15
// X=1 if SIB index uses R8-R15
// B=1 if rm field uses R8-R15
func rex(w, r, x, b bool) byte {
	var prefix byte = 0x40
	if w {
		prefix |= 0x08
	}
	if r {
		prefix |= 0x04
	}
	if x {
		prefix |= 0x02
	}
	if b {
		prefix |= 0x01
	}
	return prefix
}

// rexW returns REX.W prefix for 64-bit operations
func rexW(reg, rm Reg) byte {
	return rex(true, reg >= 8, false, rm >= 8)
}

// rexWOptional returns REX prefix for 64-bit ops, only if needed
func rexWOptional(reg, rm Reg) byte {
	if reg >= 8 || rm >= 8 {
		return rex(true, reg >= 8, false, rm >= 8)
	}
	return rex(true, false, false, false)
}

// modRM builds ModR/M byte: [mod:2][reg:3][rm:3]
// mod should be pre-shifted: 0x00=no disp, 0x40=disp8, 0x80=disp32, 0xC0=register
func modRM(mod byte, reg, rm Reg) byte {
	return mod | ((byte(reg) & 7) << 3) | (byte(rm) & 7)
}

// MovRegReg: mov dst, src (64-bit)
func (a *Assembler) MovRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x89, modRM(0xC0, src, dst))
}

// MovRegImm64: mov reg, imm64
func (a *Assembler) MovRegImm64(reg Reg, imm uint64) {
	// REX.W + B8+rd + imm64
	a.emit(rex(true, false, false, reg >= 8), 0xB8|byte(reg&7))
	a.emitUint64(imm)
}

// MovRegImm32SignExt: mov reg, imm32 (sign-extended to 64-bit)
func (a *Assembler) MovRegImm32SignExt(reg Reg, imm int32) {
	// REX.W + C7 /0 + imm32
	a.emit(rex(true, false, false, reg >= 8), 0xC7, modRM(0xC0, 0, reg))
	a.emitInt32(imm)
}

// MovRegMem64: mov reg, [base + disp32] (64-bit load)
func (a *Assembler) MovRegMem64(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x8B)
	if base == RSP || base == R12 {
		// Need SIB byte for RSP/R12 base
		a.emit(modRM(0x80, reg, RSP), 0x24) // SIB: scale=0, index=RSP (none), base=RSP
	} else if base == RBP || base == R13 {
		a.emit(modRM(0x80, reg, base))
	} else if disp == 0 {
		a.emit(modRM(0x00, reg, base))
		return
	} else if disp >= -128 && disp <= 127 {
		a.emit(modRM(0x40, reg, base), byte(disp))
		return
	} else {
		a.emit(modRM(0x80, reg, base))
	}
	a.emitInt32(disp)
}

// MovMemReg64: mov [base + disp32], reg (64-bit store)
func (a *Assembler) MovMemReg64(base Reg, disp int32, reg Reg) {
	a.emit(rexW(reg, base), 0x89)
	if base == RSP || base == R12 {
		a.emit(modRM(0x80, reg, RSP), 0x24)
	} else if base == RBP || base == R13 {
		a.emit(modRM(0x80, reg, base))
	} else if disp == 0 {
		a.emit(modRM(0x00, reg, base))
		return
	} else if disp >= -128 && disp <= 127 {
		a.emit(modRM(0x40, reg, base), byte(disp))
		return
	} else {
		a.emit(modRM(0x80, reg, base))
	}
	a.emitInt32(disp)
}

// MovRegMemIdx64: mov reg, [base + index*8] (64-bit load with index)
func (a *Assembler) MovRegMemIdx64(reg, base, index Reg) {
	// REX.W + 8B /r with SIB
	prefix := rex(true, reg >= 8, index >= 8, base >= 8)
	a.emit(prefix, 0x8B, modRM(0x00, reg, RSP)) // mod=00, rm=100 indicates SIB
	// SIB: scale=3 (8), index, base
	sib := byte(0xC0) | ((byte(index) & 7) << 3) | (byte(base) & 7) // scale=3 for *8
	a.emit(sib)
}

// MovMemIdxReg64: mov [base + index*8], reg (64-bit store with index)
func (a *Assembler) MovMemIdxReg64(base, index, reg Reg) {
	prefix := rex(true, reg >= 8, index >= 8, base >= 8)
	a.emit(prefix, 0x89, modRM(0x00, reg, RSP))
	sib := byte(0xC0) | ((byte(index) & 7) << 3) | (byte(base) & 7)
	a.emit(sib)
}

// MovRegMem8: movzx reg, byte [base + disp32]
func (a *Assembler) MovRegMem8(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x0F, 0xB6)
	a.emitMemOperand(reg, base, disp)
}

// MovRegMem8Signed: movsx reg, byte [base + disp32]
func (a *Assembler) MovRegMem8Signed(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x0F, 0xBE)
	a.emitMemOperand(reg, base, disp)
}

// MovRegMem16: movzx reg, word [base + disp32]
func (a *Assembler) MovRegMem16(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x0F, 0xB7)
	a.emitMemOperand(reg, base, disp)
}

// MovRegMem16Signed: movsx reg, word [base + disp32]
func (a *Assembler) MovRegMem16Signed(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x0F, 0xBF)
	a.emitMemOperand(reg, base, disp)
}

// MovRegMem32: mov reg32, [base + disp32] (zero-extends to 64-bit)
func (a *Assembler) MovRegMem32(reg, base Reg, disp int32) {
	prefix := byte(0)
	if reg >= 8 || base >= 8 {
		prefix = rex(false, reg >= 8, false, base >= 8)
		a.emit(prefix)
	}
	a.emit(0x8B)
	a.emitMemOperand(reg, base, disp)
}

// MovRegMem32Signed: movsxd reg, dword [base + disp32]
func (a *Assembler) MovRegMem32Signed(reg, base Reg, disp int32) {
	a.emit(rexW(reg, base), 0x63)
	a.emitMemOperand(reg, base, disp)
}

// MovMem8Reg: mov byte [base + disp32], reg
func (a *Assembler) MovMem8Reg(base Reg, disp int32, reg Reg) {
	// Need REX for R8-R15 or to access SPL/BPL/SIL/DIL
	if reg >= 8 || base >= 8 || reg >= RSP {
		a.emit(rex(false, reg >= 8, false, base >= 8))
	}
	a.emit(0x88)
	a.emitMemOperand(reg, base, disp)
}

// MovMem16Reg: mov word [base + disp32], reg
func (a *Assembler) MovMem16Reg(base Reg, disp int32, reg Reg) {
	a.emit(0x66) // operand size prefix
	if reg >= 8 || base >= 8 {
		a.emit(rex(false, reg >= 8, false, base >= 8))
	}
	a.emit(0x89)
	a.emitMemOperand(reg, base, disp)
}

// MovMem32Reg: mov dword [base + disp32], reg
func (a *Assembler) MovMem32Reg(base Reg, disp int32, reg Reg) {
	if reg >= 8 || base >= 8 {
		a.emit(rex(false, reg >= 8, false, base >= 8))
	}
	a.emit(0x89)
	a.emitMemOperand(reg, base, disp)
}

// emitMemOperand emits ModR/M and displacement for memory operands
func (a *Assembler) emitMemOperand(reg, base Reg, disp int32) {
	if base == RSP || base == R12 {
		if disp == 0 {
			a.emit(modRM(0x00, reg, RSP), 0x24)
		} else if disp >= -128 && disp <= 127 {
			a.emit(modRM(0x40, reg, RSP), 0x24, byte(disp))
		} else {
			a.emit(modRM(0x80, reg, RSP), 0x24)
			a.emitInt32(disp)
		}
	} else if base == RBP || base == R13 {
		if disp >= -128 && disp <= 127 {
			a.emit(modRM(0x40, reg, base), byte(disp))
		} else {
			a.emit(modRM(0x80, reg, base))
			a.emitInt32(disp)
		}
	} else if disp == 0 {
		a.emit(modRM(0x00, reg, base))
	} else if disp >= -128 && disp <= 127 {
		a.emit(modRM(0x40, reg, base), byte(disp))
	} else {
		a.emit(modRM(0x80, reg, base))
		a.emitInt32(disp)
	}
}

// AddRegReg: add dst, src (64-bit)
func (a *Assembler) AddRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x01, modRM(0xC0, src, dst))
}

// AddRegImm32: add reg, imm32 (64-bit, sign-extended)
func (a *Assembler) AddRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 0, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 0, reg))
		a.emitInt32(imm)
	}
}

// SubRegReg: sub dst, src (64-bit)
func (a *Assembler) SubRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x29, modRM(0xC0, src, dst))
}

// SubRegImm32: sub reg, imm32 (64-bit, sign-extended)
func (a *Assembler) SubRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 5, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 5, reg))
		a.emitInt32(imm)
	}
}

// IMulRegReg: imul dst, src (64-bit signed multiply)
func (a *Assembler) IMulRegReg(dst, src Reg) {
	a.emit(rexW(dst, src), 0x0F, 0xAF, modRM(0xC0, dst, src))
}

// IMulRegImm32: imul dst, src, imm32
func (a *Assembler) IMulRegRegImm32(dst, src Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(dst, src), 0x6B, modRM(0xC0, dst, src), byte(imm))
	} else {
		a.emit(rexW(dst, src), 0x69, modRM(0xC0, dst, src))
		a.emitInt32(imm)
	}
}

// AndRegReg: and dst, src (64-bit)
func (a *Assembler) AndRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x21, modRM(0xC0, src, dst))
}

// AndRegImm32: and reg, imm32 (64-bit, sign-extended)
func (a *Assembler) AndRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 4, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 4, reg))
		a.emitInt32(imm)
	}
}

// OrRegReg: or dst, src (64-bit)
func (a *Assembler) OrRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x09, modRM(0xC0, src, dst))
}

// OrRegImm32: or reg, imm32 (64-bit, sign-extended)
func (a *Assembler) OrRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 1, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 1, reg))
		a.emitInt32(imm)
	}
}

// XorRegReg: xor dst, src (64-bit)
func (a *Assembler) XorRegReg(dst, src Reg) {
	a.emit(rexW(src, dst), 0x31, modRM(0xC0, src, dst))
}

// XorRegImm32: xor reg, imm32 (64-bit, sign-extended)
func (a *Assembler) XorRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 6, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 6, reg))
		a.emitInt32(imm)
	}
}

// NotReg: not reg (64-bit)
func (a *Assembler) NotReg(reg Reg) {
	a.emit(rexW(0, reg), 0xF7, modRM(0xC0, 2, reg))
}

// NegReg: neg reg (64-bit)
func (a *Assembler) NegReg(reg Reg) {
	a.emit(rexW(0, reg), 0xF7, modRM(0xC0, 3, reg))
}

// ShlRegCL: shl reg, cl (64-bit)
func (a *Assembler) ShlRegCL(reg Reg) {
	a.emit(rexW(0, reg), 0xD3, modRM(0xC0, 4, reg))
}

// ShlRegImm8: shl reg, imm8 (64-bit)
func (a *Assembler) ShlRegImm8(reg Reg, imm byte) {
	if imm == 1 {
		a.emit(rexW(0, reg), 0xD1, modRM(0xC0, 4, reg))
	} else {
		a.emit(rexW(0, reg), 0xC1, modRM(0xC0, 4, reg), imm)
	}
}

// ShrRegCL: shr reg, cl (64-bit logical)
func (a *Assembler) ShrRegCL(reg Reg) {
	a.emit(rexW(0, reg), 0xD3, modRM(0xC0, 5, reg))
}

// ShrRegImm8: shr reg, imm8 (64-bit logical)
func (a *Assembler) ShrRegImm8(reg Reg, imm byte) {
	if imm == 1 {
		a.emit(rexW(0, reg), 0xD1, modRM(0xC0, 5, reg))
	} else {
		a.emit(rexW(0, reg), 0xC1, modRM(0xC0, 5, reg), imm)
	}
}

// SarRegCL: sar reg, cl (64-bit arithmetic)
func (a *Assembler) SarRegCL(reg Reg) {
	a.emit(rexW(0, reg), 0xD3, modRM(0xC0, 7, reg))
}

// SarRegImm8: sar reg, imm8 (64-bit arithmetic)
func (a *Assembler) SarRegImm8(reg Reg, imm byte) {
	if imm == 1 {
		a.emit(rexW(0, reg), 0xD1, modRM(0xC0, 7, reg))
	} else {
		a.emit(rexW(0, reg), 0xC1, modRM(0xC0, 7, reg), imm)
	}
}

// RorRegCL: ror reg, cl (64-bit)
func (a *Assembler) RorRegCL(reg Reg) {
	a.emit(rexW(0, reg), 0xD3, modRM(0xC0, 1, reg))
}

// RorRegImm8: ror reg, imm8 (64-bit)
func (a *Assembler) RorRegImm8(reg Reg, imm byte) {
	if imm == 1 {
		a.emit(rexW(0, reg), 0xD1, modRM(0xC0, 1, reg))
	} else {
		a.emit(rexW(0, reg), 0xC1, modRM(0xC0, 1, reg), imm)
	}
}

// RolRegCL: rol reg, cl (64-bit)
func (a *Assembler) RolRegCL(reg Reg) {
	a.emit(rexW(0, reg), 0xD3, modRM(0xC0, 0, reg))
}

// RolRegImm8: rol reg, imm8 (64-bit)
func (a *Assembler) RolRegImm8(reg Reg, imm byte) {
	if imm == 1 {
		a.emit(rexW(0, reg), 0xD1, modRM(0xC0, 0, reg))
	} else {
		a.emit(rexW(0, reg), 0xC1, modRM(0xC0, 0, reg), imm)
	}
}

// CmpRegReg: cmp left, right (64-bit)
func (a *Assembler) CmpRegReg(left, right Reg) {
	a.emit(rexW(right, left), 0x39, modRM(0xC0, right, left))
}

// CmpRegImm32: cmp reg, imm32 (64-bit, sign-extended)
func (a *Assembler) CmpRegImm32(reg Reg, imm int32) {
	if imm >= -128 && imm <= 127 {
		a.emit(rexW(0, reg), 0x83, modRM(0xC0, 7, reg), byte(imm))
	} else {
		a.emit(rexW(0, reg), 0x81, modRM(0xC0, 7, reg))
		a.emitInt32(imm)
	}
}

// TestRegReg: test left, right (64-bit)
func (a *Assembler) TestRegReg(left, right Reg) {
	a.emit(rexW(right, left), 0x85, modRM(0xC0, right, left))
}

// Setcc instructions (set byte based on condition)
func (a *Assembler) Sete(reg Reg) { // set if equal (ZF=1)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x94, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setne(reg Reg) { // set if not equal (ZF=0)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x95, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setb(reg Reg) { // set if below (CF=1, unsigned)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x92, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setae(reg Reg) { // set if above or equal (CF=0, unsigned)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x93, modRM(0xC0, 0, reg))
}

func (a *Assembler) Seta(reg Reg) { // set if above (CF=0 and ZF=0, unsigned)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x97, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setbe(reg Reg) { // set if below or equal (CF=1 or ZF=1, unsigned)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x96, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setl(reg Reg) { // set if less (SF≠OF, signed)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x9C, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setge(reg Reg) { // set if greater or equal (SF=OF, signed)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x9D, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setg(reg Reg) { // set if greater (ZF=0 and SF=OF, signed)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x9F, modRM(0xC0, 0, reg))
}

func (a *Assembler) Setle(reg Reg) { // set if less or equal (ZF=1 or SF≠OF, signed)
	if reg >= 8 || reg >= RSP {
		a.emit(rex(false, false, false, reg >= 8))
	}
	a.emit(0x0F, 0x9E, modRM(0xC0, 0, reg))
}

// MovzxRegReg8: movzx dst, src8 (zero-extend byte to 64-bit)
func (a *Assembler) MovzxRegReg8(dst, src Reg) {
	a.emit(rexW(dst, src), 0x0F, 0xB6, modRM(0xC0, dst, src))
}

// Conditional jumps - short form (rel8)
func (a *Assembler) Je(rel8 int8) { // jump if equal
	a.emit(0x74, byte(rel8))
}

func (a *Assembler) Jne(rel8 int8) { // jump if not equal
	a.emit(0x75, byte(rel8))
}

func (a *Assembler) Jb(rel8 int8) { // jump if below (unsigned)
	a.emit(0x72, byte(rel8))
}

func (a *Assembler) Jae(rel8 int8) { // jump if above or equal (unsigned)
	a.emit(0x73, byte(rel8))
}

func (a *Assembler) Ja(rel8 int8) { // jump if above (unsigned)
	a.emit(0x77, byte(rel8))
}

func (a *Assembler) Jbe(rel8 int8) { // jump if below or equal (unsigned)
	a.emit(0x76, byte(rel8))
}

func (a *Assembler) Jl(rel8 int8) { // jump if less (signed)
	a.emit(0x7C, byte(rel8))
}

func (a *Assembler) Jge(rel8 int8) { // jump if greater or equal (signed)
	a.emit(0x7D, byte(rel8))
}

func (a *Assembler) Jg(rel8 int8) { // jump if greater (signed)
	a.emit(0x7F, byte(rel8))
}

func (a *Assembler) Jle(rel8 int8) { // jump if less or equal (signed)
	a.emit(0x7E, byte(rel8))
}

func (a *Assembler) Js(rel8 int8) { // jump if sign (negative)
	a.emit(0x78, byte(rel8))
}

// Conditional jumps - near form (rel32)
func (a *Assembler) JeNear(rel32 int32) {
	a.emit(0x0F, 0x84)
	a.emitInt32(rel32)
}

func (a *Assembler) JneNear(rel32 int32) {
	a.emit(0x0F, 0x85)
	a.emitInt32(rel32)
}

func (a *Assembler) JbNear(rel32 int32) {
	a.emit(0x0F, 0x82)
	a.emitInt32(rel32)
}

func (a *Assembler) JaeNear(rel32 int32) {
	a.emit(0x0F, 0x83)
	a.emitInt32(rel32)
}

func (a *Assembler) JaNear(rel32 int32) {
	a.emit(0x0F, 0x87)
	a.emitInt32(rel32)
}

func (a *Assembler) JbeNear(rel32 int32) {
	a.emit(0x0F, 0x86)
	a.emitInt32(rel32)
}

func (a *Assembler) JlNear(rel32 int32) {
	a.emit(0x0F, 0x8C)
	a.emitInt32(rel32)
}

func (a *Assembler) JgeNear(rel32 int32) {
	a.emit(0x0F, 0x8D)
	a.emitInt32(rel32)
}

func (a *Assembler) JgNear(rel32 int32) {
	a.emit(0x0F, 0x8F)
	a.emitInt32(rel32)
}

func (a *Assembler) JleNear(rel32 int32) {
	a.emit(0x0F, 0x8E)
	a.emitInt32(rel32)
}

func (a *Assembler) JsNear(rel32 int32) {
	a.emit(0x0F, 0x88)
	a.emitInt32(rel32)
}

func (a *Assembler) JnsNear(rel32 int32) {
	a.emit(0x0F, 0x89)
	a.emitInt32(rel32)
}

// JmpRel32: jmp rel32
func (a *Assembler) JmpRel32(rel32 int32) {
	a.emit(0xE9)
	a.emitInt32(rel32)
}

// JmpRel8: jmp rel8
func (a *Assembler) JmpRel8(rel8 int8) {
	a.emit(0xEB, byte(rel8))
}

// JmpReg: jmp reg
func (a *Assembler) JmpReg(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xFF, modRM(0xC0, 4, reg))
}

// CallReg: call reg
func (a *Assembler) CallReg(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xFF, modRM(0xC0, 2, reg))
}

// CallRel32: call rel32
func (a *Assembler) CallRel32(rel32 int32) {
	a.emit(0xE8)
	a.emitInt32(rel32)
}

// Ret: ret
func (a *Assembler) Ret() {
	a.emit(0xC3)
}

// Push: push reg
func (a *Assembler) Push(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0x50 | byte(reg&7))
}

// Pop: pop reg
func (a *Assembler) Pop(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0x58 | byte(reg&7))
}

// Nop: nop
func (a *Assembler) Nop() {
	a.emit(0x90)
}

// Int3: int3 (breakpoint)
func (a *Assembler) Int3() {
	a.emit(0xCC)
}

// Cdqe: cdqe (sign-extend EAX to RAX)
func (a *Assembler) Cdqe() {
	a.emit(0x48, 0x98)
}

// Cqo: cqo (sign-extend RAX to RDX:RAX)
func (a *Assembler) Cqo() {
	a.emit(0x48, 0x99)
}

// IDiv: idiv reg (signed divide RDX:RAX by reg)
func (a *Assembler) IDiv(reg Reg) {
	a.emit(rexW(0, reg), 0xF7, modRM(0xC0, 7, reg))
}

// Div: div reg (unsigned divide RDX:RAX by reg)
func (a *Assembler) Div(reg Reg) {
	a.emit(rexW(0, reg), 0xF7, modRM(0xC0, 6, reg))
}

// Popcnt: popcnt dst, src
func (a *Assembler) Popcnt(dst, src Reg) {
	a.emit(0xF3, rexW(dst, src), 0x0F, 0xB8, modRM(0xC0, dst, src))
}

// Lzcnt: lzcnt dst, src
func (a *Assembler) Lzcnt(dst, src Reg) {
	a.emit(0xF3, rexW(dst, src), 0x0F, 0xBD, modRM(0xC0, dst, src))
}

// Tzcnt: tzcnt dst, src
func (a *Assembler) Tzcnt(dst, src Reg) {
	a.emit(0xF3, rexW(dst, src), 0x0F, 0xBC, modRM(0xC0, dst, src))
}

// Bswap: bswap reg (byte swap)
func (a *Assembler) Bswap(reg Reg) {
	a.emit(rexW(0, reg), 0x0F, 0xC8|byte(reg&7))
}

// 32-bit variants for instructions that need them

// AddRegReg32: add dst32, src32
func (a *Assembler) AddRegReg32(dst, src Reg) {
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, src >= 8, false, dst >= 8))
	}
	a.emit(0x01, modRM(0xC0, src, dst))
}

// SubRegReg32: sub dst32, src32
func (a *Assembler) SubRegReg32(dst, src Reg) {
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, src >= 8, false, dst >= 8))
	}
	a.emit(0x29, modRM(0xC0, src, dst))
}

// IMulRegReg32: imul dst32, src32
func (a *Assembler) IMulRegReg32(dst, src Reg) {
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, dst >= 8, false, src >= 8))
	}
	a.emit(0x0F, 0xAF, modRM(0xC0, dst, src))
}

// MovsxdRegReg: movsxd dst64, src32 (sign-extend 32->64)
func (a *Assembler) MovsxdRegReg(dst, src Reg) {
	a.emit(rexW(dst, src), 0x63, modRM(0xC0, dst, src))
}

// Shl32RegCL: shl reg32, cl
func (a *Assembler) Shl32RegCL(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xD3, modRM(0xC0, 4, reg))
}

// Shl32RegImm8: shl reg32, imm8
func (a *Assembler) Shl32RegImm8(reg Reg, imm byte) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	if imm == 1 {
		a.emit(0xD1, modRM(0xC0, 4, reg))
	} else {
		a.emit(0xC1, modRM(0xC0, 4, reg), imm)
	}
}

// Shr32RegCL: shr reg32, cl
func (a *Assembler) Shr32RegCL(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xD3, modRM(0xC0, 5, reg))
}

// Shr32RegImm8: shr reg32, imm8
func (a *Assembler) Shr32RegImm8(reg Reg, imm byte) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	if imm == 1 {
		a.emit(0xD1, modRM(0xC0, 5, reg))
	} else {
		a.emit(0xC1, modRM(0xC0, 5, reg), imm)
	}
}

// Sar32RegCL: sar reg32, cl
func (a *Assembler) Sar32RegCL(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xD3, modRM(0xC0, 7, reg))
}

// Sar32RegImm8: sar reg32, imm8
func (a *Assembler) Sar32RegImm8(reg Reg, imm byte) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	if imm == 1 {
		a.emit(0xD1, modRM(0xC0, 7, reg))
	} else {
		a.emit(0xC1, modRM(0xC0, 7, reg), imm)
	}
}

// Ror32RegCL: ror reg32, cl
func (a *Assembler) Ror32RegCL(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xD3, modRM(0xC0, 1, reg))
}

// Ror32RegImm8: ror reg32, imm8
func (a *Assembler) Ror32RegImm8(reg Reg, imm byte) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	if imm == 1 {
		a.emit(0xD1, modRM(0xC0, 1, reg))
	} else {
		a.emit(0xC1, modRM(0xC0, 1, reg), imm)
	}
}

// Rol32RegCL: rol reg32, cl
func (a *Assembler) Rol32RegCL(reg Reg) {
	if reg >= 8 {
		a.emit(rex(false, false, false, true))
	}
	a.emit(0xD3, modRM(0xC0, 0, reg))
}

// Popcnt32: popcnt dst32, src32
func (a *Assembler) Popcnt32(dst, src Reg) {
	a.emit(0xF3)
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, dst >= 8, false, src >= 8))
	}
	a.emit(0x0F, 0xB8, modRM(0xC0, dst, src))
}

// Lzcnt32: lzcnt dst32, src32
func (a *Assembler) Lzcnt32(dst, src Reg) {
	a.emit(0xF3)
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, dst >= 8, false, src >= 8))
	}
	a.emit(0x0F, 0xBD, modRM(0xC0, dst, src))
}

// Tzcnt32: tzcnt dst32, src32
func (a *Assembler) Tzcnt32(dst, src Reg) {
	a.emit(0xF3)
	if dst >= 8 || src >= 8 {
		a.emit(rex(false, dst >= 8, false, src >= 8))
	}
	a.emit(0x0F, 0xBC, modRM(0xC0, dst, src))
}

// CMov conditional moves
func (a *Assembler) Cmove(dst, src Reg) { // cmove dst, src (move if equal)
	a.emit(rexW(dst, src), 0x0F, 0x44, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovne(dst, src Reg) { // cmovne dst, src (move if not equal)
	a.emit(rexW(dst, src), 0x0F, 0x45, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovb(dst, src Reg) { // cmovb dst, src (move if below, unsigned)
	a.emit(rexW(dst, src), 0x0F, 0x42, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovae(dst, src Reg) { // cmovae dst, src (move if above/equal, unsigned)
	a.emit(rexW(dst, src), 0x0F, 0x43, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmova(dst, src Reg) { // cmova dst, src (move if above, unsigned)
	a.emit(rexW(dst, src), 0x0F, 0x47, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovbe(dst, src Reg) { // cmovbe dst, src (move if below/equal, unsigned)
	a.emit(rexW(dst, src), 0x0F, 0x46, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovl(dst, src Reg) { // cmovl dst, src (move if less, signed)
	a.emit(rexW(dst, src), 0x0F, 0x4C, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovge(dst, src Reg) { // cmovge dst, src (move if greater/equal, signed)
	a.emit(rexW(dst, src), 0x0F, 0x4D, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovg(dst, src Reg) { // cmovg dst, src (move if greater, signed)
	a.emit(rexW(dst, src), 0x0F, 0x4F, modRM(0xC0, dst, src))
}

func (a *Assembler) Cmovle(dst, src Reg) { // cmovle dst, src (move if less/equal, signed)
	a.emit(rexW(dst, src), 0x0F, 0x4E, modRM(0xC0, dst, src))
}

// Mulx: mulx r1, r2, src (unsigned multiply RDX by src, store high in r1, low in r2)
// Requires BMI2
func (a *Assembler) MulHi(dst, src Reg) {
	// Alternative using regular mul: mul src puts high bits in RDX, low in RAX
	a.emit(rexW(0, src), 0xF7, modRM(0xC0, 4, src))
}

// Syscall: syscall instruction
func (a *Assembler) Syscall() {
	a.emit(0x0F, 0x05)
}
