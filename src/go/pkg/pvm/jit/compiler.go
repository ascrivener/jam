//go:build linux && amd64

package jit

import (
	"jam/pkg/types"
	"unsafe"
)

// PVM register to x86-64 register mapping
// PVM has 13 registers (R0-R12), we map them to callee-saved registers
// so they persist across function calls (for host calls)
//
// Register allocation:
//   PVM R0  -> RBX
//   PVM R1  -> R12
//   PVM R2  -> R13
//   PVM R3  -> R14
//   PVM R4  -> R15
//   PVM R5  -> RBP (be careful - frame pointer)
//   PVM R6  -> [State + offset] (spilled)
//   PVM R7  -> [State + offset] (spilled)
//   PVM R8  -> [State + offset] (spilled)
//   PVM R9  -> [State + offset] (spilled)
//   PVM R10 -> [State + offset] (spilled)
//   PVM R11 -> [State + offset] (spilled)
//   PVM R12 -> [State + offset] (spilled)
//
// Reserved registers:
//   RDI = State pointer (first argument, preserved)
//   RSI = RAM base pointer (cached from State.RAM.buffer)
//   RAX, RCX, RDX, R8-R11 = scratch registers

const (
	// Offsets within State struct (must match pvm.State layout)
	StateGasOffset       = 0   // Gas is first field (int64)
	StateRegistersOffset = 8   // Registers array starts at offset 8
	StateRAMOffset       = 112 // RAM pointer after 13 registers (8 + 13*8 = 112)
)

// PVM register indices
const (
	PvmR0  = 0
	PvmR1  = 1
	PvmR2  = 2
	PvmR3  = 3
	PvmR4  = 4
	PvmR5  = 5
	PvmR6  = 6
	PvmR7  = 7
	PvmR8  = 8
	PvmR9  = 9
	PvmR10 = 10
	PvmR11 = 11
	PvmR12 = 12
)

// x86-64 register assignments for PVM registers in hardware
var pvmRegToX86 = [13]Reg{
	PvmR0: RBX,
	PvmR1: R12,
	PvmR2: R13,
	PvmR3: R14,
	PvmR4: R15,
	PvmR5: RBP, // Note: using RBP means we can't use frame pointer
}

// Whether a PVM register is kept in an x86 register (true) or spilled to memory (false)
var pvmRegInHardware = [13]bool{
	PvmR0:  true,
	PvmR1:  true,
	PvmR2:  true,
	PvmR3:  true,
	PvmR4:  true,
	PvmR5:  true,
	PvmR6:  false,
	PvmR7:  false,
	PvmR8:  false,
	PvmR9:  false,
	PvmR10: false,
	PvmR11: false,
	PvmR12: false,
}

// Scratch registers available for temporary use
const (
	ScratchReg1 = RAX
	ScratchReg2 = RCX
	ScratchReg3 = RDX
	ScratchReg4 = R8
	ScratchReg5 = R9
	ScratchReg6 = R10
	ScratchReg7 = R11

	StateReg = RDI // Holds pointer to State struct
	RAMReg   = RSI // Holds pointer to RAM buffer base
)

// CompiledBlock represents a compiled basic block
type CompiledBlock struct {
	StartPC      types.Register
	EndPC        types.Register
	EntryPoint   uintptr
	CodeSize     int
	LabelOffsets map[types.Register]int // PC -> byte offset within block (for mid-block entry)
}

// Compiler generates x86-64 code from PVM instructions
type Compiler struct {
	execMem *ExecutableMemory
	asm     *Assembler

	// Compilation state
	currentBlock *CompiledBlock
	labelOffsets map[types.Register]int // PC -> offset in current block
	pendingJumps []pendingJump          // jumps that need patching
}

type pendingJump struct {
	offset   int            // offset in code where jump displacement is
	targetPC types.Register // target PVM PC
	isNear   bool           // true for 32-bit displacement, false for 8-bit
}

// NewCompiler creates a new JIT compiler
func NewCompiler(execMem *ExecutableMemory) *Compiler {
	return &Compiler{
		execMem: execMem,
	}
}

// CompileBlock compiles a single basic block starting at the given PC
func (c *Compiler) CompileBlock(instructions []*ParsedInstruction, startPC types.Register) (*CompiledBlock, error) {
	// Count instructions in this block to estimate size
	blockInstrCount := 0
	for pc := int(startPC); pc < len(instructions); {
		instr := instructions[pc]
		if instr == nil {
			blockInstrCount++
			break
		}
		if pc != int(startPC) && instr.BeginsBlock {
			break
		}
		blockInstrCount++
		pc = pc + 1 + instr.SkipLength
	}
	// 256 bytes per instruction (branches emit 2 exits), minimum 1024 bytes for prologue/epilogue overhead
	estimatedSize := max(256*blockInstrCount, 1024)

	addr, buf, err := c.execMem.Allocate(estimatedSize)
	if err != nil {
		return nil, err
	}

	c.asm = NewAssembler(buf)
	c.labelOffsets = make(map[types.Register]int)
	c.pendingJumps = nil

	block := &CompiledBlock{
		StartPC:    startPC,
		EntryPoint: addr,
	}
	c.currentBlock = block

	// Emit block prologue
	c.emitPrologue()

	// Compile instructions until we hit a block boundary
	pc := startPC
	lastPC := startPC
	for {
		if int(pc) >= len(instructions) {
			block.EndPC = lastPC
			break
		}

		instr := instructions[pc]

		// Check for block boundary (BeginsBlock signals previous instruction was terminating)
		if pc != startPC && instr != nil && instr.BeginsBlock {
			// Previous instruction ended the block, no need to emit exit
			// (terminating instructions already emit their own exits)
			block.EndPC = lastPC
			break
		}

		// Record label for this PC (for intra-block jumps)
		c.labelOffsets[pc] = c.asm.Offset()

		// Emit gas decrement first (matching interpreter which does Gas-- before checking nil)
		c.emitGasCheck()

		if instr == nil {
			// Invalid instruction - emit panic exit (gas already charged above)
			c.emitExitPanic()
			block.EndPC = pc
			break
		}

		// Compile the instruction
		nextPC := c.compileInstruction(instr)

		lastPC = pc
		pc = nextPC
	}

	// Patch any pending jumps within the block
	c.patchPendingJumps()

	block.CodeSize = c.asm.Offset()
	block.LabelOffsets = c.labelOffsets // Preserve for mid-block entry

	return block, nil
}

// emitPrologue generates code to set up the execution environment
func (c *Compiler) emitPrologue() {
	emitPrologueTo(c.asm)
}

// emitPrologueTo generates prologue code to the given assembler
func emitPrologueTo(asm *Assembler) {
	// Save callee-saved registers we're using
	asm.Push(RBX)
	asm.Push(R12)
	asm.Push(R13)
	asm.Push(R14)
	asm.Push(R15)
	asm.Push(RBP)

	// RDI already contains State pointer (first argument)
	// Load RAM base into RSI
	// RSI = State->RAM->buffer.data
	// State->RAM is a *ram.RAM pointer at offset 112
	// ram.RAM.buffer is a []byte slice (first field), slice.data is at offset 0
	asm.MovRegMem64(RSI, RDI, StateRAMOffset) // RSI = RAM pointer
	asm.MovRegMem64(RSI, RSI, 0)              // RSI = buffer.data

	// Load PVM registers from State into x86 registers
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			asm.MovRegMem64(pvmRegToX86[pvmReg], StateReg, offset)
		}
	}
}

// emitEpilogue generates code to save state and return
func (c *Compiler) emitEpilogue(exitReason uint64, nextPC types.Register) {
	// Save PVM registers back to State
	for pvmReg := 0; pvmReg < 13; pvmReg++ {
		if pvmRegInHardware[pvmReg] {
			offset := int32(StateRegistersOffset + pvmReg*8)
			c.asm.MovMemReg64(StateReg, offset, pvmRegToX86[pvmReg])
		}
	}

	// Set return values: RAX = exit reason, RDX = next PC
	c.asm.MovRegImm64(RAX, exitReason)
	c.asm.MovRegImm64(RDX, uint64(nextPC))

	// Restore callee-saved registers
	c.asm.Pop(RBP)
	c.asm.Pop(R15)
	c.asm.Pop(R14)
	c.asm.Pop(R13)
	c.asm.Pop(R12)
	c.asm.Pop(RBX)

	c.asm.Ret()
}

// emitExitGo generates code to continue to the next block
func (c *Compiler) emitExitGo(nextPC types.Register) {
	c.emitEpilogue(0, nextPC) // ExitGo = 0
}

// emitExitPanic generates code for panic exit
func (c *Compiler) emitExitPanic() {
	c.emitEpilogue(2, 0) // ExitPanic = 2
}

// emitExitHalt generates code for halt exit
func (c *Compiler) emitExitHalt() {
	c.emitEpilogue(1, 0) // ExitHalt = 1
}

// emitGasCheck decrements gas and checks for out-of-gas
func (c *Compiler) emitGasCheck() {
	// Load gas, decrement, store: State->Gas--
	c.asm.MovRegMem64(ScratchReg1, StateReg, StateGasOffset)
	c.asm.SubRegImm32(ScratchReg1, 1)
	c.asm.MovMemReg64(StateReg, StateGasOffset, ScratchReg1)

	// Check if gas < 0 (signed comparison)
	c.asm.CmpRegImm32(ScratchReg1, 0)

	// Jump over out-of-gas exit if gas >= 0
	okJumpOffset := c.asm.Offset()
	c.asm.JgeNear(0) // placeholder, will patch to skip OOG exit

	// Out-of-gas exit (inline)
	c.emitEpilogue(3, 0) // ExitOutOfGas = 3

	// Patch the jump to skip over OOG exit
	okTarget := c.asm.Offset()
	rel := int32(okTarget - okJumpOffset - 6) // 6 = size of JgeNear instruction
	buf := c.asm.Bytes()
	buf[okJumpOffset+2] = byte(rel)
	buf[okJumpOffset+3] = byte(rel >> 8)
	buf[okJumpOffset+4] = byte(rel >> 16)
	buf[okJumpOffset+5] = byte(rel >> 24)
}

// loadPvmReg loads a PVM register value into a scratch register
func (c *Compiler) loadPvmReg(pvmReg int, scratch Reg) {
	if pvmRegInHardware[pvmReg] {
		c.asm.MovRegReg(scratch, pvmRegToX86[pvmReg])
	} else {
		offset := int32(StateRegistersOffset + pvmReg*8)
		c.asm.MovRegMem64(scratch, StateReg, offset)
	}
}

// storePvmReg stores a value from scratch register to a PVM register
func (c *Compiler) storePvmReg(pvmReg int, scratch Reg) {
	if pvmRegInHardware[pvmReg] {
		c.asm.MovRegReg(pvmRegToX86[pvmReg], scratch)
	} else {
		offset := int32(StateRegistersOffset + pvmReg*8)
		c.asm.MovMemReg64(StateReg, offset, scratch)
	}
}

// getPvmReg returns the x86 register for a PVM register, or loads it into scratch
func (c *Compiler) getPvmReg(pvmReg int, scratch Reg) Reg {
	if pvmRegInHardware[pvmReg] {
		return pvmRegToX86[pvmReg]
	}
	c.loadPvmReg(pvmReg, scratch)
	return scratch
}

// compileInstruction generates code for a single PVM instruction
func (c *Compiler) compileInstruction(instr *ParsedInstruction) types.Register {
	nextPC := instr.PC + 1 + types.Register(instr.SkipLength)

	switch instr.Opcode {
	case 0: // trap
		c.emitExitPanic()

	case 1: // fallthrough
		// Exit block and continue to next instruction
		c.emitExitGo(nextPC)

	case 10: // ecalli (host call)
		c.emitHostCall(instr.Vx, nextPC)

	case 20: // load_imm_64
		c.emitLoadImm64(instr.Ra, instr.Vx)

	case 30, 31, 32, 33: // store_imm_u8/u16/u32/u64
		c.emitStoreImm(instr.Opcode, instr.Vx, instr.Vy)

	case 40: // jump
		c.emitJump(instr.Vx)

	case 50: // jump_ind
		c.emitJumpInd(instr.Ra, instr.Vx)

	case 51: // load_imm
		c.emitLoadImm(instr.Ra, instr.Vx)

	case 52, 53, 54, 55, 56, 57, 58: // load_u8/i8/u16/i16/u32/i32/u64
		c.emitLoad(instr.Opcode, instr.Ra, instr.Vx)

	case 59, 60, 61, 62: // store_u8/u16/u32/u64
		c.emitStore(instr.Opcode, instr.Ra, instr.Vx)

	case 70, 71, 72, 73: // store_imm_ind_u8/u16/u32/u64
		c.emitStoreImmInd(instr.Opcode, instr.Ra, instr.Vx, instr.Vy)

	case 80: // load_imm_jump
		c.emitLoadImmJump(instr.Ra, instr.Vx, instr.Vy)

	case 81, 82, 83, 84, 85, 86, 87, 88, 89, 90: // branch_*_imm
		c.emitBranchImm(instr.Opcode, instr.Ra, instr.Vx, instr.Vy, nextPC)

	case 100: // move_reg
		c.emitMoveReg(instr.Rd, instr.Ra)

	case 101: // sbrk - needs special handling (calls into Go)
		c.emitSbrk(instr.Rd, instr.Ra)

	case 102, 103: // count_set_bits_64/32
		c.emitPopcnt(instr.Opcode, instr.Rd, instr.Ra)

	case 104, 105: // leading_zero_bits_64/32
		c.emitLzcnt(instr.Opcode, instr.Rd, instr.Ra)

	case 106, 107: // trailing_zero_bits_64/32
		c.emitTzcnt(instr.Opcode, instr.Rd, instr.Ra)

	case 108: // sign_extend_8
		c.emitSignExtend8(instr.Rd, instr.Ra)

	case 109: // sign_extend_16
		c.emitSignExtend16(instr.Rd, instr.Ra)

	case 110: // zero_extend_16
		c.emitZeroExtend16(instr.Rd, instr.Ra)

	case 111: // reverse_bytes
		c.emitBswap(instr.Rd, instr.Ra)

	case 120, 121, 122, 123: // store_ind_u8/u16/u32/u64
		c.emitStoreInd(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 124, 125, 126, 127, 128, 129, 130: // load_ind_*
		c.emitLoadInd(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 131: // add_imm_32
		c.emitAddImm32(instr.Ra, instr.Rb, instr.Vx)

	case 132: // and_imm
		c.emitAndImm(instr.Ra, instr.Rb, instr.Vx)

	case 133: // xor_imm
		c.emitXorImm(instr.Ra, instr.Rb, instr.Vx)

	case 134: // or_imm
		c.emitOrImm(instr.Ra, instr.Rb, instr.Vx)

	case 135: // mul_imm_32
		c.emitMulImm32(instr.Ra, instr.Rb, instr.Vx)

	case 136, 137: // set_lt_u_imm, set_lt_s_imm
		c.emitSetLtImm(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 138, 139, 140: // shlo_l_imm_32, shlo_r_imm_32, shar_r_imm_32
		c.emitShiftImm32(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 141: // neg_add_imm_32
		c.emitNegAddImm32(instr.Ra, instr.Rb, instr.Vx)

	case 142, 143: // set_gt_u_imm, set_gt_s_imm
		c.emitSetGtImm(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 144, 145, 146: // shlo_l_imm_alt_32, shlo_r_imm_alt_32, shar_r_imm_alt_32
		c.emitShiftImmAlt32(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 147: // cmov_iz_imm
		c.emitCmovIzImm(instr.Ra, instr.Rb, instr.Vx)

	case 148: // cmov_nz_imm
		c.emitCmovNzImm(instr.Ra, instr.Rb, instr.Vx)

	case 149: // add_imm_64
		c.emitAddImm64(instr.Ra, instr.Rb, instr.Vx)

	case 150: // mul_imm_64
		c.emitMulImm64(instr.Ra, instr.Rb, instr.Vx)

	case 151, 152, 153: // shlo_l_imm_64, shlo_r_imm_64, shar_r_imm_64
		c.emitShiftImm64(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 154: // neg_add_imm_64
		c.emitNegAddImm64(instr.Ra, instr.Rb, instr.Vx)

	case 155, 156, 157: // shlo_l_imm_alt_64, shlo_r_imm_alt_64, shar_r_imm_alt_64
		c.emitShiftImmAlt64(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 158, 159: // rot_r_64_imm, rot_r_64_imm_alt
		c.emitRotR64Imm(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 160, 161: // rot_r_32_imm, rot_r_32_imm_alt
		c.emitRotR32Imm(instr.Opcode, instr.Ra, instr.Rb, instr.Vx)

	case 170, 171, 172, 173, 174, 175: // branch_eq/ne/lt_u/lt_s/ge_u/ge_s
		c.emitBranchReg(instr.Opcode, instr.Ra, instr.Rb, instr.Vx, nextPC)

	case 180: // load_imm_jump_ind
		c.emitLoadImmJumpInd(instr.Ra, instr.Rb, instr.Vx, instr.Vy)

	case 190, 191, 192: // add_32, sub_32, mul_32
		c.emitArith32(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 193, 194: // div_u_32, div_s_32
		c.emitDiv32(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 195, 196: // rem_u_32, rem_s_32
		c.emitRem32(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 197, 198, 199: // shlo_l_32, shlo_r_32, shar_r_32
		c.emitShift32(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 200, 201, 202: // add_64, sub_64, mul_64
		c.emitArith64(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 203, 204: // div_u_64, div_s_64
		c.emitDiv64(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 205, 206: // rem_u_64, rem_s_64
		c.emitRem64(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 207, 208, 209: // shlo_l_64, shlo_r_64, shar_r_64
		c.emitShift64(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 210: // and
		c.emitAnd(instr.Rd, instr.Ra, instr.Rb)

	case 211: // xor
		c.emitXor(instr.Rd, instr.Ra, instr.Rb)

	case 212: // or
		c.emitOr(instr.Rd, instr.Ra, instr.Rb)

	case 213, 214, 215: // mul_upper_s_s, mul_upper_u_u, mul_upper_s_u
		c.emitMulUpper(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 216, 217: // set_lt_u, set_lt_s
		c.emitSetLt(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 218: // cmov_iz
		c.emitCmovIz(instr.Rd, instr.Ra, instr.Rb)

	case 219: // cmov_nz
		c.emitCmovNz(instr.Rd, instr.Ra, instr.Rb)

	case 220, 221: // rot_l_64, rot_l_32
		c.emitRotL(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 222, 223: // rot_r_64, rot_r_32
		c.emitRotR(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 224: // and_inv
		c.emitAndInv(instr.Rd, instr.Ra, instr.Rb)

	case 225: // or_inv
		c.emitOrInv(instr.Rd, instr.Ra, instr.Rb)

	case 226: // xnor
		c.emitXnor(instr.Rd, instr.Ra, instr.Rb)

	case 227, 228: // max, max_u
		c.emitMax(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	case 229, 230: // min, min_u
		c.emitMin(instr.Opcode, instr.Rd, instr.Ra, instr.Rb)

	default:
		// Unknown opcode - emit panic
		c.emitExitPanic()
	}

	return nextPC
}

// patchPendingJumps patches jump instructions that target within the same block
func (c *Compiler) patchPendingJumps() {
	for _, pj := range c.pendingJumps {
		targetOffset, ok := c.labelOffsets[pj.targetPC]
		if !ok {
			// Target is outside this block - leave as exit
			continue
		}

		// Calculate relative offset (from end of jump instruction)
		var rel int32
		if pj.isNear {
			rel = int32(targetOffset - (pj.offset + 4))
		} else {
			rel = int32(targetOffset - (pj.offset + 1))
		}

		// Patch the displacement
		if pj.isNear {
			buf := c.asm.Bytes()
			buf[pj.offset] = byte(rel)
			buf[pj.offset+1] = byte(rel >> 8)
			buf[pj.offset+2] = byte(rel >> 16)
			buf[pj.offset+3] = byte(rel >> 24)
		} else {
			c.asm.Bytes()[pj.offset] = byte(rel)
		}
	}
}

// GenerateTrampoline creates a small code stub that does prologue then jumps mid-block
func (c *Compiler) GenerateTrampoline(targetBlock *CompiledBlock, pc types.Register, labelOffset int) (*CompiledBlock, error) {
	// Trampoline size: prologue (~50 bytes) + absolute jump (~12 bytes)
	estimatedSize := 128

	addr, buf, err := c.execMem.Allocate(estimatedSize)
	if err != nil {
		return nil, err
	}

	asm := NewAssembler(buf)

	// Emit prologue (same as normal block)
	emitPrologueTo(asm)

	// Absolute jump to target block + label offset
	// mov rax, imm64; jmp rax
	targetAddr := uint64(targetBlock.EntryPoint) + uint64(labelOffset)
	asm.MovRegImm64(RAX, targetAddr)
	asm.JmpReg(RAX)

	tramp := &CompiledBlock{
		StartPC:    pc,
		EndPC:      pc,
		EntryPoint: addr,
		CodeSize:   asm.Offset(),
	}

	return tramp, nil
}

// ParsedInstruction mirrors the PVM's ParsedInstruction for the JIT
type ParsedInstruction struct {
	PC          types.Register
	Opcode      byte
	SkipLength  int
	Ra, Rb, Rd  int
	Vx, Vy      types.Register
	BeginsBlock bool
}

// CompiledBlockFunc is the signature of compiled blocks
// Returns: (exitReasonEncoded uint64, nextPC uint64)
type CompiledBlockFunc func(state unsafe.Pointer) (uint64, uint64)
