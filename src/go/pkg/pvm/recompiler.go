package pvm

import (
	"jam/pkg/ram"
	"jam/pkg/types"
	"syscall"
	"unsafe"
)

// x86-64 register encoding
const (
	REG_RAX = 0
	REG_RCX = 1
	REG_RDX = 2
	REG_RBX = 3
	REG_RSP = 4
	REG_RBP = 5
	REG_RSI = 6
	REG_RDI = 7
	REG_R8  = 8
	REG_R9  = 9
	REG_R10 = 10
	REG_R11 = 11
	REG_R12 = 12
	REG_R13 = 13
	REG_R14 = 14
	REG_R15 = 15
)

// PVM register to x86-64 register mapping
// We map all 13 PVM registers (ω₀-ω₁₂) to x86 registers
// RAX = scratch, RDI = context pointer, RSP = stack
var pvmToX86 = [13]int{
	REG_RCX, // ω₀
	REG_RDX, // ω₁
	REG_RBX, // ω₂  (callee-saved)
	REG_RBP, // ω₃  (callee-saved)
	REG_RSI, // ω₄
	REG_R8,  // ω₅
	REG_R9,  // ω₆
	REG_R10, // ω₇
	REG_R11, // ω₈
	REG_R12, // ω₉  (callee-saved)
	REG_R13, // ω₁₀ (callee-saved)
	REG_R14, // ω₁₁ (callee-saved)
	REG_R15, // ω₁₂ (callee-saved)
}

// Callee-saved registers we use (must push/pop)
var calleeSavedRegs = []int{REG_RBX, REG_RBP, REG_R12, REG_R13, REG_R14, REG_R15}

// =============================================================================
// CALLING CONVENTION FOR COMPILED BLOCKS
// =============================================================================
//
// Input (System V AMD64 ABI):
//   RDI = pointer to BlockContext struct
//
// Output:
//   RAX = exit code (see BlockExit* constants)
//
// Register mapping:
//   PVM ω₀-ω₁₂ are mapped directly to x86 registers (see pvmToX86)
//   RDI = context pointer (preserved, for gas/PC/memory access)
//   RAX = scratch register and return value
//   RSP = stack pointer (preserved)
//
// Prologue:
//   1. Push callee-saved registers (RBX, RBP, R12-R15)
//   2. Load PVM registers from BlockContext.Registers[] into x86 registers
//
// Epilogue:
//   1. Store x86 registers back to BlockContext.Registers[]
//   2. Pop callee-saved registers
//   3. Return exit code in RAX
//
// BlockContext layout (offsets in bytes):
//   +0:    Registers[0]  (ω₀)
//   +8:    Registers[1]  (ω₁)
//   ...
//   +96:   Registers[12] (ω₁₂)
//   +104:  Gas (int64)
//   +112:  PC (uint64) - next instruction to execute
//   +120:  ExitArg (uint64) - argument for exit (e.g., host call number)
//   +128:  RAMPtr (uintptr) - pointer to RAM data
//   +136:  RAMSize (uint64) - size of RAM for bounds checking
//
// =============================================================================

// BlockContext is passed to compiled code. Must match the layout above.
type BlockContext struct {
	Registers [13]uint64 // ω₀-ω₁₂
	Gas       int64      // remaining gas
	PC        uint64     // program counter (next instruction)
	ExitArg   uint64     // exit argument (host call number, fault address, etc.)
	RAMPtr    uintptr    // pointer to RAM.buffer for memory operations
}

// Offsets into BlockContext (must match struct layout)
const (
	OffsetRegisters = 0
	OffsetGas       = 13 * 8 // 104
	OffsetPC        = 14 * 8 // 112
	OffsetExitArg   = 15 * 8 // 120
	OffsetRAMPtr    = 16 * 8 // 128
)

// Exit codes returned by compiled blocks
const (
	BlockExitContinue  = 0 // Block completed, continue to next block at ctx.PC
	BlockExitHalt      = 1 // Program halted normally
	BlockExitPanic     = 2 // Panic/trap instruction
	BlockExitOutOfGas  = 3 // Ran out of gas
	BlockExitHostCall  = 4 // Host call, number in ctx.ExitArg
	BlockExitPageFault = 5 // Memory access fault, address in ctx.ExitArg
	BlockExitDivByZero = 6 // Division by zero
)

// CodeBuffer is a simple buffer for generating machine code
type CodeBuffer struct {
	code []byte
}

func newCodeBuffer() *CodeBuffer {
	return &CodeBuffer{
		code: make([]byte, 0, 4096),
	}
}

func (cb *CodeBuffer) emit(b byte) {
	cb.code = append(cb.code, b)
}

func (cb *CodeBuffer) emitBytes(bs ...byte) {
	cb.code = append(cb.code, bs...)
}

func (cb *CodeBuffer) emitU32(val uint32) {
	cb.emit(byte(val))
	cb.emit(byte(val >> 8))
	cb.emit(byte(val >> 16))
	cb.emit(byte(val >> 24))
}

func (cb *CodeBuffer) emitI32(val int32) {
	cb.emitU32(uint32(val))
}

func (cb *CodeBuffer) emitU64(val uint64) {
	cb.emitU32(uint32(val))
	cb.emitU32(uint32(val >> 32))
}

func (cb *CodeBuffer) len() int {
	return len(cb.code)
}

// REX prefix for 64-bit operations
// W: 64-bit operand size
// R: extension of ModRM reg field
// X: extension of SIB index field
// B: extension of ModRM r/m field or SIB base field
func rexByte(w, r, x, b bool) byte {
	rex := byte(0x40)
	if w {
		rex |= 0x08
	}
	if r {
		rex |= 0x04
	}
	if x {
		rex |= 0x02
	}
	if b {
		rex |= 0x01
	}
	return rex
}

// ModRM byte: mod (2 bits) | reg (3 bits) | rm (3 bits)
func modRM(mod, reg, rm byte) byte {
	return (mod << 6) | ((reg & 7) << 3) | (rm & 7)
}

// SIB byte: scale (2 bits) | index (3 bits) | base (3 bits)
func sib(scale, index, base byte) byte {
	return (scale << 6) | ((index & 7) << 3) | (base & 7)
}

// Emit: mov reg, [RDI + offset] - load PVM register from memory
func (cb *CodeBuffer) emitLoadPVMReg(x86Reg, pvmReg int) {
	offset := int32(pvmReg * 8)
	// REX.W prefix for 64-bit
	cb.emit(rexByte(true, x86Reg >= 8, false, false))
	// MOV r64, r/m64: opcode 8B /r
	cb.emit(0x8B)
	if offset == 0 {
		// [RDI] - mod=00, rm=111 (RDI)
		cb.emit(modRM(0, byte(x86Reg), REG_RDI))
	} else if offset >= -128 && offset <= 127 {
		// [RDI + disp8] - mod=01
		cb.emit(modRM(1, byte(x86Reg), REG_RDI))
		cb.emit(byte(offset))
	} else {
		// [RDI + disp32] - mod=10
		cb.emit(modRM(2, byte(x86Reg), REG_RDI))
		cb.emitI32(offset)
	}
}

// Emit: mov [RDI + offset], reg - store to PVM register
func (cb *CodeBuffer) emitStorePVMReg(pvmReg, x86Reg int) {
	offset := int32(pvmReg * 8)
	// REX.W prefix for 64-bit
	cb.emit(rexByte(true, x86Reg >= 8, false, false))
	// MOV r/m64, r64: opcode 89 /r
	cb.emit(0x89)
	if offset == 0 {
		cb.emit(modRM(0, byte(x86Reg), REG_RDI))
	} else if offset >= -128 && offset <= 127 {
		cb.emit(modRM(1, byte(x86Reg), REG_RDI))
		cb.emit(byte(offset))
	} else {
		cb.emit(modRM(2, byte(x86Reg), REG_RDI))
		cb.emitI32(offset)
	}
}

// Emit: mov rax, imm64
func (cb *CodeBuffer) emitMovImm64(reg int, val uint64) {
	// REX.W + B8+rd
	cb.emit(rexByte(true, false, false, reg >= 8))
	cb.emit(0xB8 + byte(reg&7))
	cb.emitU64(val)
}

// Emit: add rax, rbx (reg1 += reg2)
func (cb *CodeBuffer) emitAddReg(dst, src int) {
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x01) // ADD r/m64, r64
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// Emit: sub rax, rbx (reg1 -= reg2)
func (cb *CodeBuffer) emitSubReg(dst, src int) {
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x29) // SUB r/m64, r64
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// Emit: imul rax, rbx (rax *= rbx, signed)
func (cb *CodeBuffer) emitIMulReg(dst, src int) {
	cb.emit(rexByte(true, dst >= 8, false, src >= 8))
	cb.emitBytes(0x0F, 0xAF) // IMUL r64, r/m64
	cb.emit(modRM(3, byte(dst), byte(src)))
}

// Emit: and rax, rbx
func (cb *CodeBuffer) emitAndReg(dst, src int) {
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x21) // AND r/m64, r64
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// Emit: or rax, rbx
func (cb *CodeBuffer) emitOrReg(dst, src int) {
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x09) // OR r/m64, r64
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// Emit: xor rax, rbx
func (cb *CodeBuffer) emitXorReg(dst, src int) {
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x31) // XOR r/m64, r64
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// Emit: ret
func (cb *CodeBuffer) emitRet() {
	cb.emit(0xC3)
}

// Emit: xor eax, eax (zero RAX, smaller encoding)
func (cb *CodeBuffer) emitZeroRAX() {
	cb.emitBytes(0x31, 0xC0) // XOR EAX, EAX
}

// Emit: mov eax, imm32
func (cb *CodeBuffer) emitMovEaxImm32(val uint32) {
	cb.emit(0xB8) // MOV EAX, imm32
	cb.emitU32(val)
}

// allocateExecutableMemory allocates memory with execute permission
func allocateExecutableMemory(size int) ([]byte, error) {
	mem, err := syscall.Mmap(
		-1,
		0,
		size,
		syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
	)
	if err != nil {
		return nil, err
	}
	return mem, nil
}

// freeExecutableMemory frees mmap'd memory
func freeExecutableMemory(mem []byte) error {
	return syscall.Munmap(mem)
}

// compileBlock generates x86-64 machine code for a block of instructions
func (pvm *PVM) compileBlock(instructions []ParsedInstruction) []byte {
	cb := newCodeBuffer()

	// Emit prologue: save callee-saved regs, load PVM regs into x86 regs
	cb.emitPrologue()

	// For each instruction, generate native code
	for i, instr := range instructions {
		isLast := i == len(instructions)-1
		cb.compileInstruction(instr, isLast)
	}

	return cb.code
}

// emitPrologue saves callee-saved registers and loads PVM registers from memory
func (cb *CodeBuffer) emitPrologue() {
	// Push callee-saved registers we use: RBX, RBP, R12, R13, R14, R15
	for _, reg := range calleeSavedRegs {
		cb.emitPush(reg)
	}

	// Load all 13 PVM registers from BlockContext.Registers[] into x86 registers
	// RDI points to BlockContext, Registers are at offset 0
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		x86Reg := pvmToX86[pvmReg]
		offset := pvmReg * 8
		cb.emitLoadFromContext(x86Reg, offset)
	}
}

// emitEpilogue stores PVM registers back to memory, restores callee-saved, and returns
func (cb *CodeBuffer) emitEpilogue(exitCode uint32) {
	// Store all 13 PVM registers back to BlockContext.Registers[]
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		x86Reg := pvmToX86[pvmReg]
		offset := pvmReg * 8
		cb.emitStoreToContext(offset, x86Reg)
	}

	// Set return value
	cb.emitMovImm32(REG_RAX, exitCode)

	// Pop callee-saved registers in reverse order
	for i := len(calleeSavedRegs) - 1; i >= 0; i-- {
		cb.emitPop(calleeSavedRegs[i])
	}

	// Return
	cb.emit(0xC3)
}

// emitPush: push reg
func (cb *CodeBuffer) emitPush(reg int) {
	if reg >= 8 {
		cb.emit(0x41) // REX.B for R8-R15
	}
	cb.emit(0x50 + byte(reg&7))
}

// emitPop: pop reg
func (cb *CodeBuffer) emitPop(reg int) {
	if reg >= 8 {
		cb.emit(0x41) // REX.B for R8-R15
	}
	cb.emit(0x58 + byte(reg&7))
}

// emitLoadFromContext: mov reg, [rdi + offset]
func (cb *CodeBuffer) emitLoadFromContext(reg int, offset int) {
	cb.emit(rexByte(true, reg >= 8, false, false))
	cb.emit(0x8B) // MOV r64, r/m64
	if offset == 0 {
		cb.emit(modRM(0, byte(reg), REG_RDI))
	} else if offset >= -128 && offset <= 127 {
		cb.emit(modRM(1, byte(reg), REG_RDI))
		cb.emit(byte(offset))
	} else {
		cb.emit(modRM(2, byte(reg), REG_RDI))
		cb.emitI32(int32(offset))
	}
}

// emitStoreToContext: mov [rdi + offset], reg
func (cb *CodeBuffer) emitStoreToContext(offset int, reg int) {
	cb.emit(rexByte(true, reg >= 8, false, false))
	cb.emit(0x89) // MOV r/m64, r64
	if offset == 0 {
		cb.emit(modRM(0, byte(reg), REG_RDI))
	} else if offset >= -128 && offset <= 127 {
		cb.emit(modRM(1, byte(reg), REG_RDI))
		cb.emit(byte(offset))
	} else {
		cb.emit(modRM(2, byte(reg), REG_RDI))
		cb.emitI32(int32(offset))
	}
}

// emitMovImm32: mov reg, imm32 (32-bit, zero-extends to 64-bit)
func (cb *CodeBuffer) emitMovImm32(reg int, val uint32) {
	if reg >= 8 {
		cb.emit(0x41) // REX.B
	}
	cb.emit(0xB8 + byte(reg&7))
	cb.emitU32(val)
}

// emitMovReg: mov dst, src (64-bit register to register)
func (cb *CodeBuffer) emitMovReg(dst, src int) {
	if dst == src {
		return // no-op
	}
	// REX.W + 89 /r (MOV r/m64, r64)
	cb.emit(rexByte(true, src >= 8, false, dst >= 8))
	cb.emit(0x89)
	cb.emit(modRM(3, byte(src), byte(dst)))
}

// compileInstruction generates x86-64 code for a single PVM instruction
// isLast indicates if this is the last instruction in the block
func (cb *CodeBuffer) compileInstruction(instr ParsedInstruction, isLast bool) {
	// Gas cost for this instruction (1 gas per instruction for now)
	gasCost := int64(1)

	// 1. Deduct gas: ctx.Gas -= gasCost
	//    sub qword [rdi + OffsetGas], gasCost
	cb.emitSubMemImm(OffsetGas, gasCost)

	// 2. Check for out of gas: if ctx.Gas < 0, exit
	//    js out_of_gas (jump if sign flag set, i.e., negative)
	cb.emitGasCheck()

	// 3. Update PC to point to next instruction
	//    mov qword [rdi + OffsetPC], nextPC
	nextPC := uint64(instr.PC) + uint64(instr.SkipLength) + 1
	cb.emitStorePC(nextPC)

	// 4. Execute the instruction
	// Get x86 register mappings for PVM registers
	regA := pvmToX86[instr.Ra]
	regB := pvmToX86[instr.Rb]
	regD := pvmToX86[instr.Rd]

	switch instr.Opcode {
	case 0: // trap
		cb.emitEpilogue(BlockExitPanic)
		return

	case 3: // ecalli - host call
		// Store host call number in ExitArg
		cb.emitMovImm64(REG_RAX, uint64(instr.Vx))
		cb.emitStoreToContext(OffsetExitArg, REG_RAX)
		cb.emitEpilogue(BlockExitHostCall)
		return

	case 4: // load_imm64: ωa = vx (64-bit immediate)
		cb.emitMovImm64(regA, uint64(instr.Vx))

	case 51: // load_imm: ωa = vx (sign-extended immediate)
		cb.emitMovImm64(regA, uint64(instr.Vx))

	case 100: // move_reg: ωd = ωa
		// mov regD, regA
		cb.emitMovReg(regD, regA)

	case 8: // add_32: ωd = (ωa + ωb) mod 2^32
		// Use RAX as scratch: mov rax, regA; add rax, regB; mov regD, eax
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAddReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 20: // add_64: ωd = (ωa + ωb) mod 2^64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAddReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 9: // sub_32
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSubReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 21: // sub_64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSubReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 12: // and
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAndReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 14: // xor
		cb.emitMovReg(REG_RAX, regA)
		cb.emitXorReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 13: // or
		cb.emitMovReg(REG_RAX, regA)
		cb.emitOrReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 10: // mul_32
		cb.emitMovReg(REG_RAX, regA)
		cb.emitIMulReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 22: // mul_64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitIMulReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	// =========================================================================
	// Memory operations - load from RAM
	// Format: ωa = RAM[vx] (immediate address)
	// =========================================================================

	case 52: // load_u8: ωa = zero_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 1, false)

	case 53: // load_i8: ωa = sign_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 1, true)

	case 54: // load_u16: ωa = zero_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 2, false)

	case 55: // load_i16: ωa = sign_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 2, true)

	case 56: // load_u32: ωa = zero_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 4, false)

	case 57: // load_i32: ωa = sign_extend(RAM[vx])
		cb.emitLoadImm(regA, uint64(instr.Vx), 4, true)

	case 58: // load_u64: ωa = RAM[vx]
		cb.emitLoadImm(regA, uint64(instr.Vx), 8, false)

	// =========================================================================
	// Memory operations - store to RAM
	// Format: RAM[vx] = ωa
	// =========================================================================

	case 59: // store_u8: RAM[vx] = ωa (low 8 bits)
		cb.emitStoreImm(regA, uint64(instr.Vx), 1)

	case 60: // store_u16: RAM[vx] = ωa (low 16 bits)
		cb.emitStoreImm(regA, uint64(instr.Vx), 2)

	case 61: // store_u32: RAM[vx] = ωa (low 32 bits)
		cb.emitStoreImm(regA, uint64(instr.Vx), 4)

	case 62: // store_u64: RAM[vx] = ωa
		cb.emitStoreImm(regA, uint64(instr.Vx), 8)

	// =========================================================================
	// TwoReg ops (100-111) - bit manipulation, sign extension
	// =========================================================================

	case 102: // count_set_bits_64 (popcnt)
		cb.emitPopcnt(regD, regA, false)

	case 103: // count_set_bits_32
		cb.emitPopcnt(regD, regA, true)

	case 104: // leading_zero_bits_64 (lzcnt)
		cb.emitLzcnt(regD, regA, false)

	case 105: // leading_zero_bits_32
		cb.emitLzcnt(regD, regA, true)

	case 106: // trailing_zero_bits_64 (tzcnt)
		cb.emitTzcnt(regD, regA, false)

	case 107: // trailing_zero_bits_32
		cb.emitTzcnt(regD, regA, true)

	case 108: // sign_extend_8: ωd = sign_extend(ωa[7:0])
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSignExtend8(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 109: // sign_extend_16: ωd = sign_extend(ωa[15:0])
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSignExtend16(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 110: // zero_extend_16: ωd = zero_extend(ωa[15:0])
		cb.emitMovReg(REG_RAX, regA)
		cb.emitZeroExtend16(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 111: // reverse_bytes: ωd = bswap(ωa)
		cb.emitMovReg(REG_RAX, regA)
		cb.emitBswap(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	// =========================================================================
	// TwoRegOneImm - indirect memory ops (120-130)
	// Format: RAM[ωb + vx] = ωa or ωa = RAM[ωb + vx]
	// =========================================================================

	case 120: // store_ind_u8
		cb.emitStoreInd(regA, regB, int64(instr.Vx), 1)

	case 121: // store_ind_u16
		cb.emitStoreInd(regA, regB, int64(instr.Vx), 2)

	case 122: // store_ind_u32
		cb.emitStoreInd(regA, regB, int64(instr.Vx), 4)

	case 123: // store_ind_u64
		cb.emitStoreInd(regA, regB, int64(instr.Vx), 8)

	case 124: // load_ind_u8
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 1, false)

	case 125: // load_ind_i8
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 1, true)

	case 126: // load_ind_u16
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 2, false)

	case 127: // load_ind_i16
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 2, true)

	case 128: // load_ind_u32
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 4, false)

	case 129: // load_ind_i32
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 4, true)

	case 130: // load_ind_u64
		cb.emitLoadInd(regA, regB, int64(instr.Vx), 8, false)

	// =========================================================================
	// TwoRegOneImm - arithmetic with immediate (131-154)
	// =========================================================================

	case 131: // add_imm_32: ωa = (ωb + vx) mod 2^32
		cb.emitMovReg(REG_RAX, regB)
		cb.emitAddImm(REG_RAX, int64(instr.Vx))
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regA, REG_RAX)

	case 132: // and_imm: ωa = ωb & vx
		cb.emitMovReg(REG_RAX, regB)
		cb.emitAndImm(REG_RAX, int64(instr.Vx))
		cb.emitMovReg(regA, REG_RAX)

	case 133: // xor_imm: ωa = ωb ^ vx
		cb.emitMovReg(REG_RAX, regB)
		cb.emitXorImm(REG_RAX, int64(instr.Vx))
		cb.emitMovReg(regA, REG_RAX)

	case 134: // or_imm: ωa = ωb | vx
		cb.emitMovReg(REG_RAX, regB)
		cb.emitOrImm(REG_RAX, int64(instr.Vx))
		cb.emitMovReg(regA, REG_RAX)

	case 135: // mul_imm_32: ωa = (ωb * vx) mod 2^32
		cb.emitMovReg(REG_RAX, regB)
		cb.emitIMulImm(REG_RAX, int64(instr.Vx))
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regA, REG_RAX)

	case 136: // set_lt_u_imm: ωa = (ωb < vx) ? 1 : 0 (unsigned)
		cb.emitSetCC(regA, regB, uint64(instr.Vx), 0x72) // JB/SETB

	case 137: // set_lt_s_imm: ωa = (ωb < vx) ? 1 : 0 (signed)
		cb.emitSetCC(regA, regB, uint64(instr.Vx), 0x7C) // JL/SETL

	case 138: // shlo_l_imm_32: ωa = (ωb << (vx % 32)) mod 2^32
		cb.emitShiftImm(regA, regB, int(instr.Vx)%32, 0xE0, true) // SHL, truncate

	case 139: // shlo_r_imm_32: ωa = (ωb >> (vx % 32)) mod 2^32 (logical)
		cb.emitShiftImm(regA, regB, int(instr.Vx)%32, 0xE8, true) // SHR, truncate

	case 140: // shar_r_imm_32: ωa = (ωb >> (vx % 32)) (arithmetic)
		cb.emitShiftImm(regA, regB, int(instr.Vx)%32, 0xF8, true) // SAR, truncate

	case 141: // neg_add_imm_32: ωa = (vx - ωb) mod 2^32
		cb.emitMovImm64(REG_RAX, uint64(instr.Vx))
		cb.emitSubReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regA, REG_RAX)

	case 142: // set_gt_u_imm: ωa = (ωb > vx) ? 1 : 0 (unsigned)
		cb.emitSetCC(regA, regB, uint64(instr.Vx), 0x77) // JA/SETA

	case 143: // set_gt_s_imm: ωa = (ωb > vx) ? 1 : 0 (signed)
		cb.emitSetCC(regA, regB, uint64(instr.Vx), 0x7F) // JG/SETG

	case 144: // shlo_l_imm_alt_32: ωa = (vx << (ωb % 32)) mod 2^32
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xE0, true, 32) // SHL

	case 145: // shlo_r_imm_alt_32: ωa = (vx >> (ωb % 32)) mod 2^32
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xE8, true, 32) // SHR

	case 146: // shar_r_imm_alt_32: ωa = (vx >> (ωb % 32)) (arithmetic)
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xF8, true, 32) // SAR

	case 147: // cmov_iz_imm: if ωb == 0 then ωa = vx
		cb.emitCmovImm(regA, regB, uint64(instr.Vx), true)

	case 148: // cmov_nz_imm: if ωb != 0 then ωa = vx
		cb.emitCmovImm(regA, regB, uint64(instr.Vx), false)

	case 149: // add_imm_64: ωa = ωb + vx
		cb.emitMovReg(REG_RAX, regB)
		cb.emitAddImm(REG_RAX, int64(instr.Vx))
		cb.emitMovReg(regA, REG_RAX)

	case 150: // mul_imm_64: ωa = ωb * vx
		cb.emitMovReg(REG_RAX, regB)
		cb.emitIMulImm(REG_RAX, int64(instr.Vx))
		cb.emitMovReg(regA, REG_RAX)

	case 151: // shlo_l_imm_64: ωa = ωb << (vx % 64)
		cb.emitShiftImm(regA, regB, int(instr.Vx)%64, 0xE0, false) // SHL

	case 152: // shlo_r_imm_64: ωa = ωb >> (vx % 64) (logical)
		cb.emitShiftImm(regA, regB, int(instr.Vx)%64, 0xE8, false) // SHR

	case 153: // shar_r_imm_64: ωa = ωb >> (vx % 64) (arithmetic)
		cb.emitShiftImm(regA, regB, int(instr.Vx)%64, 0xF8, false) // SAR

	case 154: // neg_add_imm_64: ωa = vx - ωb
		cb.emitMovImm64(REG_RAX, uint64(instr.Vx))
		cb.emitSubReg(REG_RAX, regB)
		cb.emitMovReg(regA, REG_RAX)

	case 155: // shlo_l_imm_alt_64: ωa = vx << (ωb % 64)
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xE0, false, 64) // SHL

	case 156: // shlo_r_imm_alt_64: ωa = vx >> (ωb % 64)
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xE8, false, 64) // SHR

	case 157: // shar_r_imm_alt_64: ωa = vx >> (ωb % 64) (arithmetic)
		cb.emitShiftRegCL(regA, uint64(instr.Vx), regB, 0xF8, false, 64) // SAR

	case 158: // rot_r_64_imm: ωa = rotate_right(ωb, vx % 64)
		cb.emitRotateImm(regA, regB, int(instr.Vx)%64, false, false) // ROR 64

	case 159: // rot_r_64_imm_alt: ωa = rotate_right(vx, ωb % 64)
		cb.emitRotateRegCL(regA, uint64(instr.Vx), regB, false, 64) // ROR

	case 160: // rot_r_32_imm: ωa = rotate_right(ωb, vx % 32)
		cb.emitRotateImm(regA, regB, int(instr.Vx)%32, true, false) // ROR 32

	case 161: // rot_r_32_imm_alt: ωa = rotate_right(vx, ωb % 32)
		cb.emitRotateRegCL(regA, uint64(instr.Vx), regB, true, 32) // ROR

	// =========================================================================
	// ThreeReg ops (190-230) - arithmetic, division, shifts
	// =========================================================================

	case 190: // add_32
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAddReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 191: // sub_32
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSubReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 192: // mul_32
		cb.emitMovReg(REG_RAX, regA)
		cb.emitIMulReg(REG_RAX, regB)
		cb.emitTruncate32(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 193: // div_u_32
		cb.emitDivU32(regD, regA, regB)

	case 194: // div_s_32
		cb.emitDivS32(regD, regA, regB)

	case 195: // rem_u_32
		cb.emitRemU32(regD, regA, regB)

	case 196: // rem_s_32
		cb.emitRemS32(regD, regA, regB)

	case 197: // shlo_l_32: ωd = (ωa << (ωb % 32)) mod 2^32
		cb.emitShiftReg(regD, regA, regB, 0xE0, true, 32) // SHL

	case 198: // shlo_r_32: ωd = (ωa >> (ωb % 32)) mod 2^32 (logical)
		cb.emitShiftReg(regD, regA, regB, 0xE8, true, 32) // SHR

	case 199: // shar_r_32: ωd = (ωa >> (ωb % 32)) (arithmetic)
		cb.emitShiftReg(regD, regA, regB, 0xF8, true, 32) // SAR

	case 200: // add_64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAddReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 201: // sub_64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitSubReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 202: // mul_64
		cb.emitMovReg(REG_RAX, regA)
		cb.emitIMulReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 203: // div_u_64
		cb.emitDivU64(regD, regA, regB)

	case 204: // div_s_64
		cb.emitDivS64(regD, regA, regB)

	case 205: // rem_u_64
		cb.emitRemU64(regD, regA, regB)

	case 206: // rem_s_64
		cb.emitRemS64(regD, regA, regB)

	case 207: // shlo_l_64
		cb.emitShiftReg(regD, regA, regB, 0xE0, false, 64) // SHL

	case 208: // shlo_r_64
		cb.emitShiftReg(regD, regA, regB, 0xE8, false, 64) // SHR

	case 209: // shar_r_64
		cb.emitShiftReg(regD, regA, regB, 0xF8, false, 64) // SAR

	case 210: // and
		cb.emitMovReg(REG_RAX, regA)
		cb.emitAndReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 211: // xor
		cb.emitMovReg(REG_RAX, regA)
		cb.emitXorReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 212: // or
		cb.emitMovReg(REG_RAX, regA)
		cb.emitOrReg(REG_RAX, regB)
		cb.emitMovReg(regD, REG_RAX)

	case 213: // mul_upper_s_s
		cb.emitMulUpperSS(regD, regA, regB)

	case 214: // mul_upper_u_u
		cb.emitMulUpperUU(regD, regA, regB)

	case 215: // mul_upper_s_u
		cb.emitMulUpperSU(regD, regA, regB)

	case 216: // set_lt_u: ωd = (ωa < ωb) ? 1 : 0 (unsigned)
		cb.emitSetLt(regD, regA, regB, false)

	case 217: // set_lt_s: ωd = (ωa < ωb) ? 1 : 0 (signed)
		cb.emitSetLt(regD, regA, regB, true)

	case 218: // cmov_iz: if ωb == 0 then ωd = ωa
		cb.emitCmov(regD, regA, regB, true)

	case 219: // cmov_nz: if ωb != 0 then ωd = ωa
		cb.emitCmov(regD, regA, regB, false)

	case 220: // rot_l_64
		cb.emitRotateReg(regD, regA, regB, false, true) // ROL 64

	case 221: // rot_l_32
		cb.emitRotateReg(regD, regA, regB, true, true) // ROL 32

	case 222: // rot_r_64
		cb.emitRotateReg(regD, regA, regB, false, false) // ROR 64

	case 223: // rot_r_32
		cb.emitRotateReg(regD, regA, regB, true, false) // ROR 32

	case 224: // and_inv: ωd = ωa & ~ωb
		cb.emitMovReg(REG_RAX, regB)
		cb.emitNot(REG_RAX)
		cb.emitAndReg(REG_RAX, regA)
		cb.emitMovReg(regD, REG_RAX)

	case 225: // or_inv: ωd = ωa | ~ωb
		cb.emitMovReg(REG_RAX, regB)
		cb.emitNot(REG_RAX)
		cb.emitOrReg(REG_RAX, regA)
		cb.emitMovReg(regD, REG_RAX)

	case 226: // xnor: ωd = ~(ωa ^ ωb)
		cb.emitMovReg(REG_RAX, regA)
		cb.emitXorReg(REG_RAX, regB)
		cb.emitNot(REG_RAX)
		cb.emitMovReg(regD, REG_RAX)

	case 227: // max (signed)
		cb.emitMaxMin(regD, regA, regB, true, true)

	case 228: // max_u (unsigned)
		cb.emitMaxMin(regD, regA, regB, false, true)

	case 229: // min (signed)
		cb.emitMaxMin(regD, regA, regB, true, false)

	case 230: // min_u (unsigned)
		cb.emitMaxMin(regD, regA, regB, false, false)

	// =========================================================================
	// Control flow - these always exit the block
	// =========================================================================

	case 5: // jump (unconditional)
		// PC already set to next instruction, but jump overrides it
		cb.emitStorePC(uint64(instr.Vx))
		cb.emitEpilogue(BlockExitContinue)
		return

	case 170, 171, 172, 173, 174, 175: // branch_* (register comparisons)
		cb.emitBranchRegMapped(instr, regA, regB)
		return

	case 81, 82, 83, 84, 85, 86, 87, 88, 89, 90: // branch_*_imm
		cb.emitBranchImmMapped(instr, regA)
		return

	default:
		// Unimplemented opcode - exit block and let interpreter handle it
		// Set PC back to this instruction so interpreter can execute it
		cb.emitStorePC(uint64(instr.PC))
		cb.emitEpilogue(BlockExitContinue)
		return
	}

	// 5. If last instruction, return continue
	if isLast {
		cb.emitEpilogue(BlockExitContinue)
	}
}

// emitSubMemImm: sub qword [rdi + offset], imm8
func (cb *CodeBuffer) emitSubMemImm(offset int, val int64) {
	// REX.W + 83 /5 ib (SUB r/m64, imm8)
	cb.emit(rexByte(true, false, false, false))
	cb.emit(0x83)
	if offset >= -128 && offset <= 127 {
		cb.emit(modRM(1, 5, REG_RDI)) // /5 = SUB, mod=01 for disp8
		cb.emit(byte(offset))
	} else {
		cb.emit(modRM(2, 5, REG_RDI)) // mod=10 for disp32
		cb.emitI32(int32(offset))
	}
	cb.emit(byte(val))
}

// emitGasCheck: js to out_of_gas exit
func (cb *CodeBuffer) emitGasCheck() {
	// JS rel8 (0x78) - jump if sign flag (negative result)
	// We'll emit: js +N where N jumps to exit code
	// For now, emit a short forward jump that we'll patch
	// Actually, simpler: test and conditional exit inline

	// jns skip (jump if not sign = positive, skip the exit)
	cb.emit(0x79) // JNS rel8
	cb.emit(7)    // skip 7 bytes (the exit sequence below)

	// Exit with out of gas:
	// mov eax, BlockExitOutOfGas
	cb.emit(0xB8)
	cb.emitU32(BlockExitOutOfGas)
	// ret
	cb.emit(0xC3)
}

// emitStorePC: mov qword [rdi + OffsetPC], imm64
func (cb *CodeBuffer) emitStorePC(pc uint64) {
	// mov rax, imm64
	cb.emitMovImm64(REG_RAX, pc)
	// mov [rdi + OffsetPC], rax
	cb.emit(rexByte(true, false, false, false))
	cb.emit(0x89) // MOV r/m64, r64
	cb.emit(modRM(2, REG_RAX, REG_RDI))
	cb.emitI32(int32(OffsetPC))
}

// emitTruncate32: zero-extend 32-bit value in register (clears upper 32 bits)
func (cb *CodeBuffer) emitTruncate32(reg int) {
	// mov eax, eax (32-bit mov clears upper 32 bits)
	cb.emit(0x89)
	cb.emit(modRM(3, byte(reg), byte(reg)))
}

// emitExitWithCode: mov eax, code; ret
func (cb *CodeBuffer) emitExitWithCode(code uint32) {
	cb.emit(0xB8) // MOV EAX, imm32
	cb.emitU32(code)
	cb.emit(0xC3) // RET
}

// emitBranchRegMapped emits code for branch instructions using register-mapped PVM regs
// regA and regB are the x86 registers holding the PVM register values
func (cb *CodeBuffer) emitBranchRegMapped(instr ParsedInstruction, regA, regB int) {
	nextPC := uint64(instr.PC) + uint64(instr.SkipLength) + 1
	targetPC := uint64(instr.Vx)

	// CMP regA, regB
	cb.emitCmpReg(regA, regB)

	// Get condition code based on opcode
	var jccOpcode byte
	switch instr.Opcode {
	case 170: // branch_eq
		jccOpcode = 0x74 // JE
	case 171: // branch_ne
		jccOpcode = 0x75 // JNE
	case 172: // branch_lt_u
		jccOpcode = 0x72 // JB
	case 173: // branch_lt_s
		jccOpcode = 0x7C // JL
	case 174: // branch_ge_u
		jccOpcode = 0x73 // JAE
	case 175: // branch_ge_s
		jccOpcode = 0x7D // JGE
	}

	// For branches, we need to use a forward jump over the not-taken epilogue
	// Since epilogue is variable size, we use a near jump (0F 8x rel32)
	// Jump to taken path if condition is true
	cb.emitJccNear(jccOpcode)
	notTakenPatchPos := cb.len() // position to patch

	// Not taken path: PC = nextPC, epilogue
	cb.emitStorePC(nextPC)
	cb.emitEpilogue(BlockExitContinue)

	// Patch the jump offset
	takenPos := cb.len()
	jumpOffset := int32(takenPos - notTakenPatchPos)
	cb.patchI32(notTakenPatchPos-4, jumpOffset)

	// Taken path: PC = targetPC, epilogue
	cb.emitStorePC(targetPC)
	cb.emitEpilogue(BlockExitContinue)
}

// emitBranchImmMapped emits code for branch instructions comparing register to immediate
func (cb *CodeBuffer) emitBranchImmMapped(instr ParsedInstruction, regA int) {
	nextPC := uint64(instr.PC) + uint64(instr.SkipLength) + 1
	targetPC := uint64(instr.Vy)
	immVal := uint64(instr.Vx)

	// Load immediate into RAX for comparison
	cb.emitMovImm64(REG_RAX, immVal)

	// CMP regA, RAX
	cb.emitCmpReg(regA, REG_RAX)

	// Get condition code based on opcode
	var jccOpcode byte
	switch instr.Opcode {
	case 81: // branch_eq_imm
		jccOpcode = 0x74 // JE
	case 82: // branch_ne_imm
		jccOpcode = 0x75 // JNE
	case 83: // branch_lt_u_imm
		jccOpcode = 0x72 // JB
	case 84: // branch_le_u_imm
		jccOpcode = 0x76 // JBE
	case 85: // branch_ge_u_imm
		jccOpcode = 0x73 // JAE
	case 86: // branch_gt_u_imm
		jccOpcode = 0x77 // JA
	case 87: // branch_lt_s_imm
		jccOpcode = 0x7C // JL
	case 88: // branch_le_s_imm
		jccOpcode = 0x7E // JLE
	case 89: // branch_ge_s_imm
		jccOpcode = 0x7D // JGE
	case 90: // branch_gt_s_imm
		jccOpcode = 0x7F // JG
	}

	// Jump to taken path if condition is true
	cb.emitJccNear(jccOpcode)
	notTakenPatchPos := cb.len()

	// Not taken path
	cb.emitStorePC(nextPC)
	cb.emitEpilogue(BlockExitContinue)

	// Patch the jump offset
	takenPos := cb.len()
	jumpOffset := int32(takenPos - notTakenPatchPos)
	cb.patchI32(notTakenPatchPos-4, jumpOffset)

	// Taken path
	cb.emitStorePC(targetPC)
	cb.emitEpilogue(BlockExitContinue)
}

// emitCmpReg: cmp reg1, reg2
func (cb *CodeBuffer) emitCmpReg(reg1, reg2 int) {
	cb.emit(rexByte(true, reg2 >= 8, false, reg1 >= 8))
	cb.emit(0x39) // CMP r/m64, r64
	cb.emit(modRM(3, byte(reg2), byte(reg1)))
}

// emitJccNear: emit conditional jump with 32-bit offset (to be patched)
func (cb *CodeBuffer) emitJccNear(cc byte) {
	// Convert short JCC opcode to near JCC: 0x7X -> 0x0F 0x8X
	cb.emit(0x0F)
	cb.emit(0x80 | (cc & 0x0F))
	cb.emitI32(0) // placeholder, will be patched
}

// patchI32: patch a 32-bit value at the given position
func (cb *CodeBuffer) patchI32(pos int, val int32) {
	cb.code[pos] = byte(val)
	cb.code[pos+1] = byte(val >> 8)
	cb.code[pos+2] = byte(val >> 16)
	cb.code[pos+3] = byte(val >> 24)
}

// emitLoadImm emits code to load from RAM at immediate address
// Uses hardware memory protection (mprotect) - no software checks needed
func (cb *CodeBuffer) emitLoadImm(destReg int, addr uint64, size int, signExtend bool) {
	// Wrap address to 32-bit
	addr32 := uint32(addr)

	// Load RAM buffer pointer
	cb.emitLoadFromContext(REG_R8, OffsetRAMPtr)

	// Load address into RAX
	cb.emitMovImm32(REG_RAX, addr32)

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

// emitStoreImm emits code to store to RAM at immediate address
// Uses hardware memory protection (mprotect) - no software checks needed
func (cb *CodeBuffer) emitStoreImm(srcReg int, addr uint64, size int) {
	// Wrap address to 32-bit
	addr32 := uint32(addr)

	// Load RAM buffer pointer
	cb.emitLoadFromContext(REG_R8, OffsetRAMPtr)

	// Load address into RAX
	cb.emitMovImm32(REG_RAX, addr32)

	// Store value directly - hardware protection will fault on invalid access
	switch size {
	case 1:
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

// patchByte: patch a single byte at the given position
func (cb *CodeBuffer) patchByte(pos int, val byte) {
	cb.code[pos] = val
}

// CompiledBlock holds executable code and metadata
type CompiledBlock struct {
	code     []byte // The executable memory (mmap'd with PROT_EXEC)
	codeFunc uintptr
}

// NewCompiledBlock creates a compiled block from generated machine code
func NewCompiledBlock(code []byte) (*CompiledBlock, error) {
	if len(code) == 0 {
		return nil, nil
	}

	// Allocate executable memory
	execMem, err := allocateExecutableMemory(len(code))
	if err != nil {
		return nil, err
	}

	// Copy code to executable memory
	copy(execMem, code)

	return &CompiledBlock{
		code:     execMem,
		codeFunc: uintptr(unsafe.Pointer(&execMem[0])),
	}, nil
}

// Free releases the executable memory
func (cb *CompiledBlock) Free() error {
	if cb.code != nil {
		return freeExecutableMemory(cb.code)
	}
	return nil
}

// Execute runs the compiled code with the given context
// Returns the exit code from the compiled block
func (cb *CompiledBlock) Execute(ctx *BlockContext) uint32 {
	// Call the compiled code
	// The function signature is: func(ctx *BlockContext) uint64
	// RDI = pointer to BlockContext (System V AMD64 ABI)
	ret := callCompiledCode(cb.codeFunc, unsafe.Pointer(ctx))
	return uint32(ret)
}

// callCompiledCode calls the compiled machine code at the given address
// This uses Go's ability to call arbitrary function pointers
//
//go:noescape
func callCompiledCode(codePtr uintptr, ctx unsafe.Pointer) uint64

// ExecuteBlock runs a compiled block, updating PVM state
// Returns the exit code and whether execution should continue
func (pvm *PVM) ExecuteBlock(block *BasicBlock) (exitCode uint32, err error) {
	if block.CompiledCode == nil || len(block.CompiledCode) == 0 {
		return BlockExitPanic, nil
	}

	// Create compiled block (allocates executable memory)
	compiled, err := NewCompiledBlock(block.CompiledCode)
	if err != nil {
		return BlockExitPanic, err
	}
	defer compiled.Free()

	// Set up BlockContext
	ctx := &BlockContext{}

	// Copy registers to context
	for i := 0; i < 13; i++ {
		ctx.Registers[i] = uint64(pvm.State.Registers[i])
	}

	// Set gas and PC
	ctx.Gas = int64(pvm.State.Gas)
	ctx.PC = uint64(pvm.InstructionCounter)

	// Set RAM pointer
	ramBuffer := getRAMBuffer(pvm.State.RAM)
	if len(ramBuffer) > 0 {
		ctx.RAMPtr = uintptr(unsafe.Pointer(&ramBuffer[0]))
	}

	// Execute
	exitCode = compiled.Execute(ctx)

	// Copy registers back
	for i := 0; i < 13; i++ {
		pvm.State.Registers[i] = types.Register(ctx.Registers[i])
	}

	// Update gas and PC
	pvm.State.Gas = types.SignedGasValue(ctx.Gas)
	pvm.InstructionCounter = types.Register(ctx.PC)

	return exitCode, nil
}

// getRAMBuffer returns the RAM buffer for JIT access
func getRAMBuffer(r *ram.RAM) []byte {
	return r.GetBuffer()
}
