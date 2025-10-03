package pvm

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"

	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

func handleTrap(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	return ExitReasonPanic, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractTrap(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	return 0, 0, 0, 0, 0
}

func handleFallthrough(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractFallthrough(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	return 0, 0, 0, 0, 0
}

func handleEcalli(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	return NewComplexExitReason(ExitHostCall, instruction.Vx), pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractEcalli(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	lx := min(4, skipLength)
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(instructions[pc+1:pc+1+lx]))
	return 0, 0, 0, vx, 0
}

func handleLoadImm64(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	pvm.State.Registers[instruction.Ra] = instruction.Vx
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractLoadImm64(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	ra = min(12, int(instructions[pc+1]%16))
	vx = types.Register(binary.LittleEndian.Uint64(instructions[pc+2 : pc+2+8]))
	return ra, 0, 0, vx, 0
}

func handleTwoImmValues(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	// Use the opcode from the instruction parameter
	switch instruction.Opcode {
	case 30: // store_imm_u8
		pvm.State.RAM.Mutate(uint64(instruction.Vx), byte(instruction.Vy), ram.Wrap, true)
	case 31: // store_imm_u16
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 2, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint16(dest, uint16(instruction.Vy))
		})
	case 32: // store_imm_u32
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 4, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint32(dest, uint32(instruction.Vy))
		})
	case 33: // store_imm_u64
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 8, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint64(dest, uint64(instruction.Vy))
		})
	default:
		panic(fmt.Sprintf("handleStoreImmGroup: unexpected opcode %d", instruction.Opcode))
	}
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractTwoImmValues(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Precompute the common immediate values.
	lx := min(4, int(instructions[pc+1]%8))
	ly := min(4, max(0, skipLength-lx-1))
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(instructions[pc+2:pc+2+lx]))
	vy = signExtendImmediate(ly, serializer.DecodeLittleEndian(instructions[pc+2+lx:pc+2+lx+ly]))
	return 0, 0, 0, vx, vy
}

func handleJump(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	return branch(pvm, instruction.SkipLength, instruction.Vx, true)
}

func extractJump(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	lx := min(4, skipLength)
	vx = types.Register(int64(pc) + serializer.UnsignedToSigned(lx, serializer.DecodeLittleEndian(instructions[pc+1:pc+1+lx])))
	return 0, 0, 0, vx, 0
}

func handleOneRegOneImm(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	switch instruction.Opcode {
	case 50: // jump_ind
		// Jump to the target address computed from (register[ra] + vx)
		targetAddr := uint32(pvm.State.Registers[instruction.Ra] + instruction.Vx)
		return djump(targetAddr, pvm.InstructionCounter, pvm.DynamicJumpTable, pvm.InstructionSlice)
	case 51: // load_imm
		pvm.State.Registers[instruction.Ra] = instruction.Vx
	case 52: // load_u8
		pvm.State.Registers[instruction.Ra] = types.Register(pvm.State.RAM.Inspect(uint64(instruction.Vx), ram.Wrap, true))
	case 53: // load_i8
		val := pvm.State.RAM.Inspect(uint64(instruction.Vx), ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = signExtendImmediate(1, uint64(val))
	case 54: // load_u16
		data := pvm.State.RAM.InspectRange(uint64(instruction.Vx), 2, ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = types.Register(binary.LittleEndian.Uint16(data))
	case 55: // load_i16
		data := pvm.State.RAM.InspectRange(uint64(instruction.Vx), 2, ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = signExtendImmediate(2, uint64(binary.LittleEndian.Uint16(data)))
	case 56: // load_u32
		data := pvm.State.RAM.InspectRange(uint64(instruction.Vx), 4, ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = types.Register(binary.LittleEndian.Uint32(data))
	case 57: // load_i32
		data := pvm.State.RAM.InspectRange(uint64(instruction.Vx), 4, ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(binary.LittleEndian.Uint32(data)))
	case 58: // load_u64
		data := pvm.State.RAM.InspectRange(uint64(instruction.Vx), 8, ram.Wrap, true)
		pvm.State.Registers[instruction.Ra] = types.Register(binary.LittleEndian.Uint64(data))
	case 59: // store_u8
		pvm.State.RAM.Mutate(uint64(instruction.Vx), uint8(pvm.State.Registers[instruction.Ra]), ram.Wrap, true)
	case 60: // store_u16
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 2, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint16(dest, uint16(pvm.State.Registers[instruction.Ra]))
		})
	case 61: // store_u32
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 4, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint32(dest, uint32(pvm.State.Registers[instruction.Ra]))
		})
	case 62: // store_u64
		pvm.State.RAM.MutateRange(uint64(instruction.Vx), 8, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint64(dest, uint64(pvm.State.Registers[instruction.Ra]))
		})
	default:
		panic(fmt.Sprintf("handleOneRegOneImm: unexpected opcode %d", instruction))
	}
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractOneRegOneImm(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Compute the register operand from the next byte (mod 16, capped to 12).
	ra = min(12, int(instructions[pc+1]%16))
	// Compute how many bytes remain for the immediate (skipLength-1).
	lx := min(4, max(0, skipLength-1))
	// Decode the immediate value (and sign-extend it).
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(instructions[pc+2:pc+2+lx]))
	return ra, 0, 0, vx, 0
}

func handleOneRegTwoImm(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	// Calculate the effective memory address.
	addr := pvm.State.Registers[instruction.Ra] + instruction.Vx

	// Use the opcode from the context to choose the correct store operation.
	switch instruction.Opcode {
	case 70: // store_imm_ind_u8
		pvm.State.RAM.Mutate(uint64(addr), byte(instruction.Vy), ram.Wrap, true)
	case 71: // store_imm_ind_u16
		pvm.State.RAM.MutateRange(uint64(addr), 2, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint16(dest, uint16(instruction.Vy))
		})
	case 72: // store_imm_ind_u32
		pvm.State.RAM.MutateRange(uint64(addr), 4, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint32(dest, uint32(instruction.Vy))
		})
	case 73: // store_imm_ind_u64
		pvm.State.RAM.MutateRange(uint64(addr), 8, ram.Wrap, true, func(dest []byte) {
			binary.LittleEndian.PutUint64(dest, uint64(instruction.Vy))
		})
	default:
		panic(fmt.Sprintf("handleTwoImmValuesIndirect: unexpected opcode %d", instruction.Opcode))
	}
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractOneRegTwoImm(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Precompute the common immediate values, including the base register.
	// Extract the base register (ra) from the first instruction byte.
	ra = min(12, int(instructions[pc+1])%16)
	// For lx, extract the upper 4 bits (by dividing by 16) and limit to 4 bytes.
	lx := min(4, int(instructions[pc+1]/16)%8)
	// Compute vx from the next lx bytes.
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(instructions[pc+2:pc+2+lx]))
	// Determine ly based on the remaining skip length.
	ly := min(4, max(0, skipLength-lx-1))
	// Compute vy from the following ly bytes.
	vy = signExtendImmediate(ly, serializer.DecodeLittleEndian(instructions[pc+2+lx:pc+2+lx+ly]))
	return ra, rb, 0, vx, vy
}

func handleOneRegOneImmOneOff(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	var cond bool
	switch instruction.Opcode {
	case 80: // load_imm_jump
		// For load-imm-jump, store vx into the destination register.
		pvm.State.Registers[instruction.Ra] = instruction.Vx
		cond = true
	case 81: // branch_eq_imm
		cond = pvm.State.Registers[instruction.Ra] == instruction.Vx
	case 82: // branch_ne_imm
		cond = pvm.State.Registers[instruction.Ra] != instruction.Vx
	case 83: // branch_lt_u_imm
		cond = pvm.State.Registers[instruction.Ra] < instruction.Vx
	case 84: // branch_le_u_imm
		cond = pvm.State.Registers[instruction.Ra] <= instruction.Vx
	case 85: // branch_ge_u_imm
		cond = pvm.State.Registers[instruction.Ra] >= instruction.Vx
	case 86: // branch_gt_u_imm
		cond = pvm.State.Registers[instruction.Ra] > instruction.Vx
	case 87: // branch_lt_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) < serializer.UnsignedToSigned(8, uint64(instruction.Vx))
	case 88: // branch_le_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) <= serializer.UnsignedToSigned(8, uint64(instruction.Vx))
	case 89: // branch_ge_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) >= serializer.UnsignedToSigned(8, uint64(instruction.Vx))
	case 90: // branch_gt_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) > serializer.UnsignedToSigned(8, uint64(instruction.Vx))
	default:
		panic(fmt.Sprintf("handleBranchImm: unexpected opcode %d", instruction))
	}

	// Execute the branch. The branch() function returns the exit reason
	// and the next instruction counter based on the branch condition.
	return branch(pvm, instruction.SkipLength, instruction.Vy, cond)
}

func extractOneRegOneImmOneOff(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Precompute the immediate values and the register operand.
	ra = min(12, int(instructions[pc+1]%16))
	lx := min(4, int(instructions[pc+1]/16%8))
	// vx is the first immediate.
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(instructions[pc+2:pc+2+lx]))
	ly := min(4, max(0, skipLength-lx-1))
	// For branch instructions the second immediate is an offset,
	// so add it to the current instruction counter.
	branchOffset := serializer.UnsignedToSigned(ly, serializer.DecodeLittleEndian(instructions[pc+2+lx:pc+2+lx+ly]))
	vy = types.Register(int64(pc) + branchOffset)
	return ra, 0, 0, vx, vy
}

func handleTwoReg(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	switch instruction.Opcode {
	case 100: // move_reg
		// Copy the value from source register to destination register.
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra]

	case 101: // sbrk
		// Allocate memory from the heap.
		h := types.Register(0)
		if pvm.State.RAM.BeginningOfHeap != nil {
			h = types.Register(*pvm.State.RAM.BeginningOfHeap)
		}
		size := uint64(pvm.State.Registers[instruction.Ra])
		if size == 0 {
			pvm.State.Registers[instruction.Rd] = h
		} else {
			pvm.State.Registers[instruction.Rd] = h
			pvm.State.RAM.MutateAccessRange(uint64(h), size, ram.Mutable, ram.NoWrap)
			h += types.Register(size)
			var heapIndex ram.RamIndex = ram.RamIndex(h)
			pvm.State.RAM.BeginningOfHeap = &heapIndex
		}

	case 102: // count_set_bits_64
		pvm.State.Registers[instruction.Rd] = types.Register(bits.OnesCount64(uint64(pvm.State.Registers[instruction.Ra])))

	case 103: // count_set_bits_32
		pvm.State.Registers[instruction.Rd] = types.Register(bits.OnesCount32(uint32(pvm.State.Registers[instruction.Ra])))

	case 104: // leading_zero_bits_64
		pvm.State.Registers[instruction.Rd] = types.Register(bits.LeadingZeros64(uint64(pvm.State.Registers[instruction.Ra])))

	case 105: // leading_zero_bits_32
		pvm.State.Registers[instruction.Rd] = types.Register(bits.LeadingZeros32(uint32(pvm.State.Registers[instruction.Ra])))

	case 106: // trailing_zero_bits_64
		pvm.State.Registers[instruction.Rd] = types.Register(bits.TrailingZeros64(uint64(pvm.State.Registers[instruction.Ra])))

	case 107: // trailing_zero_bits_32
		pvm.State.Registers[instruction.Rd] = types.Register(bits.TrailingZeros32(uint32(pvm.State.Registers[instruction.Ra])))

	case 108: // sign_extend_8
		pvm.State.Registers[instruction.Rd] = types.Register(
			serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(1, uint64(uint8(pvm.State.Registers[instruction.Ra])))),
		)

	case 109: // sign_extend_16
		pvm.State.Registers[instruction.Rd] = types.Register(
			serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(2, uint64(uint16(pvm.State.Registers[instruction.Ra])))),
		)

	case 110: // zero_extend_16
		pvm.State.Registers[instruction.Rd] = types.Register(uint16(pvm.State.Registers[instruction.Ra]))

	case 111: // reverse_bytes
		bytes := serializer.EncodeLittleEndian(8, uint64(pvm.State.Registers[instruction.Ra]))
		slices.Reverse(bytes)
		pvm.State.Registers[instruction.Rd] = types.Register(binary.LittleEndian.Uint64(bytes))

	default:
		panic(fmt.Sprintf("handleTwoReg: unexpected opcode %d", instruction))
	}
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractTwoReg(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Extract the two register operands from the same instruction byte.
	// The lower 4 bits specify the destination register (rd),
	// and the upper 4 bits specify the source register (ra).
	rd = min(12, int(instructions[pc+1])%16)
	ra = min(12, int(instructions[pc+1])/16)
	return ra, rb, rd, vx, vy
}

type twoRegOneImmHandler func(pvm *PVM, instruction ParsedInstruction)

var twoRegOneImmDispatch = [256]twoRegOneImmHandler{
	120: handleStoreIndU8,
	121: handleStoreIndU16,
	122: handleStoreIndU32,
	123: handleStoreIndU64,
	124: handleLoadIndU8,
	125: handleLoadIndI8,
	126: handleLoadIndU16,
	127: handleLoadIndI16,
	128: handleLoadIndU32,
	129: handleLoadIndI32,
	130: handleLoadIndU64,
	131: handleAddImm32,
	132: handleAndImm,
	133: handleXorImm,
	134: handleOrImm,
	135: handleMulImm32,
	136: handleSetLtUImm,
	137: handleSetLtSImm,
	138: handleShloLImm32,
	139: handleShloRImm32,
	140: handleSharRImm32,
	141: handleNegAddImm32,
	142: handleSetGtUImm,
	143: handleSetGtSImm,
	144: handleShloLImmAlt32,
	145: handleShloRImmAlt32,
	146: handleSharRImmAlt32,
	147: handleCmovIzImm,
	148: handleCmovNzImm,
	149: handleAddImm64,
	150: handleMulImm64,
	151: handleShloLImm64,
	152: handleShloRImm64,
	153: handleSharRImm64,
	154: handleNegAddImm64,
	155: handleShloLImmAlt64,
	156: handleShloRImmAlt64,
	157: handleSharRImmAlt64,
	158: handleRotR64Imm,
	159: handleRotR64ImmAlt,
	160: handleRotR32Imm,
	161: handleRotR32ImmAlt,
}

func handleTwoRegOneImm(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	twoRegOneImmDispatch[instruction.Opcode](pvm, instruction)
	return ExitReasonGo, instruction.NextPC
}

func extractTwoRegOneImm(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	ra = min(12, int(instructions[pc+1])%16)
	rb = min(12, int(instructions[pc+1])/16)
	lx := min(4, max(0, skipLength-1))
	vx = signExtendImmediate(lx, uint64(serializer.DecodeLittleEndian(
		instructions[pc+2:pc+2+lx])))
	return ra, rb, 0, vx, 0
}

func handleTwoRegOneOffset(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	var cond bool
	switch instruction.Opcode {
	case 170: // branch_eq
		cond = pvm.State.Registers[instruction.Ra] == pvm.State.Registers[instruction.Rb]
	case 171: // branch_ne
		cond = pvm.State.Registers[instruction.Ra] != pvm.State.Registers[instruction.Rb]
	case 172: // branch_lt_u
		cond = pvm.State.Registers[instruction.Ra] < pvm.State.Registers[instruction.Rb]
	case 173: // branch_lt_s
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) < serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))
	case 174: // branch_ge_u
		cond = pvm.State.Registers[instruction.Ra] >= pvm.State.Registers[instruction.Rb]
	case 175: // branch_ge_s
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) >= serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))
	default:
		panic(fmt.Sprintf("handleTwoRegOneOffset: unexpected opcode %d", instruction.Opcode))
	}

	// Execute the branch based on the computed condition.
	return branch(pvm, instruction.SkipLength, instruction.Vx, cond)
}

func extractTwoRegOneOffset(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Extract two register operands from the same instruction byte.
	// Lower 4 bits for 'ra', upper 4 bits for 'rb'.
	ra = min(12, int(instructions[pc+1])%16)
	rb = min(12, int(instructions[pc+1])/16)

	// Compute the immediate branch offset.
	lx := min(4, max(0, skipLength-1))
	vx = types.Register(int64(pc) + serializer.UnsignedToSigned(lx,
		serializer.DecodeLittleEndian(instructions[pc+2:pc+2+lx])))

	return ra, rb, 0, vx, 0
}

func handleLoadImmJumpInd(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	// Perform a dynamic jump based on the computed offset (rb + vy).
	// Store the immediate value vx into the destination register.
	pvm.State.Registers[instruction.Ra] = instruction.Vx
	return djump(
		uint32(pvm.State.Registers[instruction.Rb]+instruction.Vy),
		pvm.InstructionCounter,
		pvm.DynamicJumpTable,
		pvm.InstructionSlice,
	)
}

func extractLoadImmJumpInd(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Extract the register operands from the same instruction byte.
	// Lower 4 bits: destination register (ra); upper 4 bits: base register (rb).
	ra = min(12, int(instructions[pc+1])%16)
	rb = min(12, int(instructions[pc+1])/16)

	// Extract the immediate length for the first immediate.
	lx := min(4, int(instructions[pc+2])%8)
	// Compute the length for the second immediate.
	ly := min(4, max(0, skipLength-lx-2))

	// Decode the first immediate value.
	vx = signExtendImmediate(lx, serializer.DecodeLittleEndian(
		instructions[pc+3:pc+3+lx]))
	// Decode the second immediate value.
	vy = signExtendImmediate(ly, serializer.DecodeLittleEndian(
		instructions[pc+3+lx:pc+3+lx+ly]))
	return ra, rb, 0, vx, vy
}

func handleThreeReg(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register) {
	switch instruction.Opcode {
	case 190: // add_32
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra]+pvm.State.Registers[instruction.Rb])))
	case 191: // sub_32
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra]-pvm.State.Registers[instruction.Rb])))
	case 192: // mul_32
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra]*pvm.State.Registers[instruction.Rb])))
	case 193: // div_u_32
		if uint32(pvm.State.Registers[instruction.Rb]) == 0 {
			pvm.State.Registers[instruction.Rd] = (1 << 64) - 1
		} else {
			pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra])/uint32(pvm.State.Registers[instruction.Rb])))
		}
	case 194: // div_s_32
		a := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Ra])))
		b := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Rb])))
		if b == 0 {
			pvm.State.Registers[instruction.Rd] = (1 << 64) - 1
		} else if a == -(1<<31) && b == -1 {
			pvm.State.Registers[instruction.Rd] = types.Register(a)
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, a/b))
		}
	case 195: // rem_u_32
		if uint32(pvm.State.Registers[instruction.Rb]) == 0 {
			pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra])))
		} else {
			pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra])%uint32(pvm.State.Registers[instruction.Rb])))
		}
	case 196: // rem_s_32
		a := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Ra])))
		b := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Rb])))
		if a == -(1<<31) && b == -1 {
			pvm.State.Registers[instruction.Rd] = 0
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, smod(a, b)))
		}
	case 197: // shlo_l_32
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra]<<(pvm.State.Registers[instruction.Rb]%32))))
	case 198: // shlo_r_32
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Ra])>>(pvm.State.Registers[instruction.Rb]%32)))
	case 199: // shar_r_32
		pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Ra])))>>(pvm.State.Registers[instruction.Rb]%32)))
	case 200: // add_64
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] + pvm.State.Registers[instruction.Rb]
	case 201: // sub_64
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] - pvm.State.Registers[instruction.Rb]
	case 202: // mul_64
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] * pvm.State.Registers[instruction.Rb]
	case 203: // div_u_64
		if pvm.State.Registers[instruction.Rb] == 0 {
			pvm.State.Registers[instruction.Rd] = (1 << 64) - 1
		} else {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] / pvm.State.Registers[instruction.Rb]
		}
	case 204: // div_s_64
		if pvm.State.Registers[instruction.Rb] == 0 {
			pvm.State.Registers[instruction.Rd] = (1 << 64) - 1
		} else if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) == -(1<<63) &&
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])) == -1 {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra]
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8,
				serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra]))/
					serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))))
		}
	case 205: // rem_u_64
		if pvm.State.Registers[instruction.Rb] == 0 {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra]
		} else {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] % pvm.State.Registers[instruction.Rb]
		}
	case 206: // rem_s_64
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) == -(1<<63) &&
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])) == -1 {
			pvm.State.Registers[instruction.Rd] = 0
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8,
				smod(serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])),
					serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])))))
		}
	case 207: // shlo_l_64
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] << (pvm.State.Registers[instruction.Rb] % 64)
	case 208: // shlo_r_64
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] >> (pvm.State.Registers[instruction.Rb] % 64)
	case 209: // shar_r_64
		pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra]))>>(pvm.State.Registers[instruction.Rb]%64)))
	case 210: // and
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] & pvm.State.Registers[instruction.Rb]
	case 211: // xor
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] ^ pvm.State.Registers[instruction.Rb]
	case 212: // or
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] | pvm.State.Registers[instruction.Rb]
	case 213: // mul_upper_s_s
		pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, floorProductDiv2Pow64Signed(
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])),
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])))))
	case 214: // mul_upper_u_u
		hi, _ := bits.Mul64(uint64(pvm.State.Registers[instruction.Ra]), uint64(pvm.State.Registers[instruction.Rb]))
		pvm.State.Registers[instruction.Rd] = types.Register(hi)
	case 215: // mul_upper_s_u
		pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, mulDiv2Pow64(
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])),
			uint64(pvm.State.Registers[instruction.Rb]))))
	case 216: // set_lt_u
		if pvm.State.Registers[instruction.Ra] < pvm.State.Registers[instruction.Rb] {
			pvm.State.Registers[instruction.Rd] = 1
		} else {
			pvm.State.Registers[instruction.Rd] = 0
		}
	case 217: // set_lt_s
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra])) < serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])) {
			pvm.State.Registers[instruction.Rd] = 1
		} else {
			pvm.State.Registers[instruction.Rd] = 0
		}
	case 218: // cmov_iz
		if pvm.State.Registers[instruction.Rb] == 0 {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra]
		}
	case 219: // cmov_nz
		if pvm.State.Registers[instruction.Rb] != 0 {
			pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra]
		}
	case 220: // rot_l_64
		val := uint64(pvm.State.Registers[instruction.Ra])
		shift := pvm.State.Registers[instruction.Rb] % 64
		pvm.State.Registers[instruction.Rd] = types.Register((val << shift) | (val >> (64 - shift)))
	case 221: // rot_l_32
		val := uint32(pvm.State.Registers[instruction.Ra])
		shift := pvm.State.Registers[instruction.Rb] % 32
		rotated := (val << shift) | (val >> (32 - shift))
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(rotated))
	case 222: // rot_r_64
		val := uint64(pvm.State.Registers[instruction.Ra])
		shift := pvm.State.Registers[instruction.Rb] % 64
		pvm.State.Registers[instruction.Rd] = types.Register((val >> shift) | (val << (64 - shift)))
	case 223: // rot_r_32
		val := uint32(pvm.State.Registers[instruction.Ra])
		shift := pvm.State.Registers[instruction.Rb] % 32
		rotated := (val >> shift) | (val << (32 - shift))
		pvm.State.Registers[instruction.Rd] = signExtendImmediate(4, uint64(rotated))
	case 224: // and_inv
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] & ^pvm.State.Registers[instruction.Rb]
	case 225: // or_inv
		pvm.State.Registers[instruction.Rd] = pvm.State.Registers[instruction.Ra] | ^pvm.State.Registers[instruction.Rb]
	case 226: // xnor
		pvm.State.Registers[instruction.Rd] = ^(pvm.State.Registers[instruction.Ra] ^ pvm.State.Registers[instruction.Rb])
	case 227: // max
		l := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra]))
		r := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))
		if l > r {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, l))
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, r))
		}
	case 228: // max_u
		pvm.State.Registers[instruction.Rd] = max(pvm.State.Registers[instruction.Ra], pvm.State.Registers[instruction.Rb])
	case 229: // min
		l := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Ra]))
		r := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))
		if l < r {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, l))
		} else {
			pvm.State.Registers[instruction.Rd] = types.Register(serializer.SignedToUnsigned(8, r))
		}
	case 230: // min_u
		pvm.State.Registers[instruction.Rd] = min(pvm.State.Registers[instruction.Ra], pvm.State.Registers[instruction.Rb])
	default:
		panic(fmt.Sprintf("handleThreeReg: unexpected opcode %d", instruction.Opcode))
	}
	return ExitReasonGo, pvm.nextInstructionCounter(instruction.SkipLength)
}

func extractThreeReg(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register) {
	// Extract source registers from the same instruction byte.
	// Lower 4 bits: ra; upper 4 bits: rb.
	ra = min(12, int(instructions[pc+1])%16)
	rb = min(12, int(instructions[pc+1])/16)
	// Extract destination register from the following byte.
	rd = min(12, int(instructions[pc+2]))
	return ra, rb, rd, vx, vy
}

// nextInstructionCounter returns the next instruction counter position
// after executing the current instruction with the given skip length
func (pvm *PVM) nextInstructionCounter(skipLength int) types.Register {
	return pvm.InstructionCounter + 1 + types.Register(skipLength)
}

func handleStoreIndU8(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.RAM.Mutate(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)),
		byte(pvm.State.Registers[instruction.Ra]), ram.Wrap, true)
}

func handleStoreIndU16(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.RAM.MutateRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 2, ram.Wrap, true, func(dest []byte) {
		binary.LittleEndian.PutUint16(dest, uint16(pvm.State.Registers[instruction.Ra]))
	})
}

func handleStoreIndU32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.RAM.MutateRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 4, ram.Wrap, true, func(dest []byte) {
		binary.LittleEndian.PutUint32(dest, uint32(pvm.State.Registers[instruction.Ra]))
	})
}

func handleStoreIndU64(pvm *PVM, instruction ParsedInstruction) {
	addr := uint64(pvm.State.Registers[instruction.Rb] + types.Register(instruction.Vx))
	pvm.State.RAM.MutateRange(addr, 8, ram.Wrap, true, func(dest []byte) {
		binary.LittleEndian.PutUint64(dest, uint64(pvm.State.Registers[instruction.Ra]))
	})
}

func handleLoadIndU8(pvm *PVM, instruction ParsedInstruction) {
	addr := uint64(pvm.State.Registers[instruction.Rb] + types.Register(instruction.Vx))
	value := pvm.State.RAM.Inspect(addr, ram.Wrap, true)
	pvm.State.Registers[instruction.Ra] = types.Register(value)
}

func handleLoadIndI8(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(1, uint64(pvm.State.RAM.Inspect(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), ram.Wrap, true)))))
}

func handleLoadIndU16(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(binary.LittleEndian.Uint16(
		pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 2, ram.Wrap, true)))
}

func handleLoadIndI16(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(2, uint64(binary.LittleEndian.Uint16(
			pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 2, ram.Wrap, true))))))
}

func handleLoadIndU32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(binary.LittleEndian.Uint32(
		pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 4, ram.Wrap, true)))
}

func handleLoadIndI32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(4, uint64(binary.LittleEndian.Uint32(
			pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[instruction.Rb]+types.Register(instruction.Vx)), 4, ram.Wrap, true))))))
}

func handleLoadIndU64(pvm *PVM, instruction ParsedInstruction) {
	addr := uint64(pvm.State.Registers[instruction.Rb] + types.Register(instruction.Vx))
	data := pvm.State.RAM.InspectRange(addr, 8, ram.Wrap, true)
	value := types.Register(binary.LittleEndian.Uint64(data))
	pvm.State.Registers[instruction.Ra] = value
}

func handleAddImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Rb]+instruction.Vx)))
}

func handleAndImm(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = pvm.State.Registers[instruction.Rb] & instruction.Vx
}

func handleXorImm(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = pvm.State.Registers[instruction.Rb] ^ instruction.Vx
}

func handleOrImm(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = pvm.State.Registers[instruction.Rb] | instruction.Vx
}

func handleMulImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Rb]*instruction.Vx)))
}

func handleSetLtUImm(pvm *PVM, instruction ParsedInstruction) {
	if pvm.State.Registers[instruction.Rb] < instruction.Vx {
		pvm.State.Registers[instruction.Ra] = 1
	} else {
		pvm.State.Registers[instruction.Ra] = 0
	}
}

func handleSetLtSImm(pvm *PVM, instruction ParsedInstruction) {
	if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])) < serializer.UnsignedToSigned(8, uint64(instruction.Vx)) {
		pvm.State.Registers[instruction.Ra] = 1
	} else {
		pvm.State.Registers[instruction.Ra] = 0
	}
}

func handleShloLImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Rb]<<(instruction.Vx%32))))
}

func handleShloRImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[instruction.Rb])>>(instruction.Vx%32)))
}

func handleSharRImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[instruction.Rb])))>>(instruction.Vx%32)))
}

func handleNegAddImm32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(instruction.Vx-pvm.State.Registers[instruction.Rb])))
}

func handleSetGtUImm(pvm *PVM, instruction ParsedInstruction) {
	if pvm.State.Registers[instruction.Rb] > instruction.Vx {
		pvm.State.Registers[instruction.Ra] = 1
	} else {
		pvm.State.Registers[instruction.Ra] = 0
	}
}

func handleSetGtSImm(pvm *PVM, instruction ParsedInstruction) {
	if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb])) > serializer.UnsignedToSigned(8, uint64(instruction.Vx)) {
		pvm.State.Registers[instruction.Ra] = 1
	} else {
		pvm.State.Registers[instruction.Ra] = 0
	}
}

func handleShloLImmAlt32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(instruction.Vx<<(pvm.State.Registers[instruction.Rb]%32))))
}

func handleShloRImmAlt32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(uint32(instruction.Vx)>>(pvm.State.Registers[instruction.Rb]%32)))
}

func handleSharRImmAlt32(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(4, uint64(uint32(instruction.Vx)))>>(pvm.State.Registers[instruction.Rb]%32)))
}

func handleCmovIzImm(pvm *PVM, instruction ParsedInstruction) {
	if pvm.State.Registers[instruction.Rb] == 0 {
		pvm.State.Registers[instruction.Ra] = instruction.Vx
	}
}

func handleCmovNzImm(pvm *PVM, instruction ParsedInstruction) {
	if pvm.State.Registers[instruction.Rb] != 0 {
		pvm.State.Registers[instruction.Ra] = instruction.Vx
	}
}

func handleAddImm64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = pvm.State.Registers[instruction.Rb] + instruction.Vx
}

func handleMulImm64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = pvm.State.Registers[instruction.Rb] * instruction.Vx
}

func handleShloLImm64(pvm *PVM, instruction ParsedInstruction) {
	shiftAmount := instruction.Vx % 64
	shifted := uint64(pvm.State.Registers[instruction.Rb] << shiftAmount)
	result := signExtendImmediate(8, shifted)
	pvm.State.Registers[instruction.Ra] = result
}

func handleShloRImm64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(8, uint64(pvm.State.Registers[instruction.Rb]>>(instruction.Vx%64)))
}

func handleSharRImm64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[instruction.Rb]))>>(instruction.Vx%64)))
}

func handleNegAddImm64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = instruction.Vx - pvm.State.Registers[instruction.Rb]
}

func handleShloLImmAlt64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = instruction.Vx << (pvm.State.Registers[instruction.Rb] % 64)
}

func handleShloRImmAlt64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = instruction.Vx >> (pvm.State.Registers[instruction.Rb] % 64)
}

func handleSharRImmAlt64(pvm *PVM, instruction ParsedInstruction) {
	pvm.State.Registers[instruction.Ra] = types.Register(serializer.SignedToUnsigned(8,
		serializer.UnsignedToSigned(8, uint64(instruction.Vx))>>(pvm.State.Registers[instruction.Rb]%64)))
}

func handleRotR64Imm(pvm *PVM, instruction ParsedInstruction) {
	val := uint64(pvm.State.Registers[instruction.Rb])
	shift := instruction.Vx % 64
	pvm.State.Registers[instruction.Ra] = types.Register((val >> shift) | (val << (64 - shift)))
}

func handleRotR64ImmAlt(pvm *PVM, instruction ParsedInstruction) {
	val := uint64(instruction.Vx)
	shift := pvm.State.Registers[instruction.Rb] % 64
	pvm.State.Registers[instruction.Ra] = types.Register((val >> shift) | (val << (64 - shift)))
}

func handleRotR32Imm(pvm *PVM, instruction ParsedInstruction) {
	val := uint32(pvm.State.Registers[instruction.Rb])
	shift := instruction.Vx % 32
	rotated := (val >> shift) | (val << (32 - shift))
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(rotated))
}

func handleRotR32ImmAlt(pvm *PVM, instruction ParsedInstruction) {
	val := uint32(instruction.Vx)
	shift := pvm.State.Registers[instruction.Rb] % 32
	rotated := (val >> shift) | (val << (32 - shift))
	pvm.State.Registers[instruction.Ra] = signExtendImmediate(4, uint64(rotated))
}
