package pvm

import (
	"fmt"
	"math/bits"
	"slices"

	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

func handleTrap(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	return NewSimpleExitReason(ExitPanic), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleFallthrough(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleEcalli(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	lx := min(4, ctx.SkipLength)
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+1, lx)))
	return NewComplexExitReason(ExitHostCall, vx), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleLoadImm64(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)%16))
	vx := serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, 8))
	pvm.State.Registers[ra] = types.Register(vx)
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleTwoImmValues(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Precompute the common immediate values.
	lx := min(4, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)%8))
	ly := min(4, max(0, ctx.SkipLength-lx-1))
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx)))
	vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2+types.Register(lx), ly)))

	// Use the opcode from the context (assuming it's been set)
	switch ctx.Instruction {
	case 30: // store_imm_u8
		pvm.State.RAM.Mutate(uint64(vx), byte(vy), ram.Wrap, true)
	case 31: // store_imm_u16
		serialized := serializer.EncodeLittleEndian(2, uint64(uint16(vy)))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	case 32: // store_imm_u32
		serialized := serializer.EncodeLittleEndian(4, uint64(uint32(vy)))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	case 33: // store_imm_u64
		serialized := serializer.EncodeLittleEndian(8, uint64(vy))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	default:
		panic(fmt.Sprintf("handleStoreImmGroup: unexpected opcode %d", ctx.Instruction))
	}
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleJump(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	lx := min(4, ctx.SkipLength)
	vx := pvm.InstructionCounter + types.Register(serializer.UnsignedToSigned(lx, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+1, lx))))
	return branch(vx, true, pvm.nextInstructionCounter(ctx.SkipLength), pvm.BasicBlockBeginningOpcodes)
}

func handleOneRegOneImm(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	exitReason := NewSimpleExitReason(ExitGo)
	// Compute the register operand from the next byte (mod 16, capped to 12).
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)%16))
	// Compute how many bytes remain for the immediate (skipLength-1).
	lx := min(4, max(0, ctx.SkipLength-1))
	// Decode the immediate value (and sign-extend it).
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx)))

	switch ctx.Instruction {
	case 50: // jump_ind
		// Jump to the target address computed from (register[ra] + vx)
		targetAddr := uint32(pvm.State.Registers[ra] + vx)
		return djump(targetAddr, pvm.nextInstructionCounter(ctx.SkipLength), pvm.DynamicJumpTable, pvm.BasicBlockBeginningOpcodes)
	case 51: // load_imm
		pvm.State.Registers[ra] = vx
	case 52: // load_u8
		pvm.State.Registers[ra] = types.Register(pvm.State.RAM.Inspect(uint64(vx), ram.Wrap, true))
	case 53: // load_i8
		val := pvm.State.RAM.Inspect(uint64(vx), ram.Wrap, true)
		pvm.State.Registers[ra] = signExtendImmediate(1, uint64(val))
	case 54: // load_u16
		data := pvm.State.RAM.InspectRange(uint64(vx), 2, ram.Wrap, true)
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(data))
	case 55: // load_i16
		data := pvm.State.RAM.InspectRange(uint64(vx), 2, ram.Wrap, true)
		pvm.State.Registers[ra] = signExtendImmediate(2, serializer.DecodeLittleEndian(data))
	case 56: // load_u32
		data := pvm.State.RAM.InspectRange(uint64(vx), 4, ram.Wrap, true)
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(data))
	case 57: // load_i32
		data := pvm.State.RAM.InspectRange(uint64(vx), 4, ram.Wrap, true)
		pvm.State.Registers[ra] = signExtendImmediate(4, serializer.DecodeLittleEndian(data))
	case 58: // load_u64
		data := pvm.State.RAM.InspectRange(uint64(vx), 8, ram.Wrap, true)
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(data))
	case 59: // store_u8
		pvm.State.RAM.Mutate(uint64(vx), uint8(pvm.State.Registers[ra]), ram.Wrap, true)
	case 60: // store_u16
		serialized := serializer.EncodeLittleEndian(2, uint64(uint16(pvm.State.Registers[ra])))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	case 61: // store_u32
		serialized := serializer.EncodeLittleEndian(4, uint64(uint32(pvm.State.Registers[ra])))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	case 62: // store_u64
		serialized := serializer.EncodeLittleEndian(8, uint64(pvm.State.Registers[ra]))
		pvm.State.RAM.MutateRange(uint64(vx), serialized, ram.Wrap, true)
	default:
		panic(fmt.Sprintf("handleOneRegOneImm: unexpected opcode %d", ctx.Instruction))
	}
	return exitReason, pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleOneRegTwoImm(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Precompute the common immediate values, including the base register.
	// Extract the base register (ra) from the first instruction byte.
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	// For lx, extract the upper 4 bits (by dividing by 16) and limit to 4 bytes.
	lx := min(4, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)/16)%8)
	// Compute vx from the next lx bytes.
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx)))
	// Determine ly based on the remaining skip length.
	ly := min(4, max(0, ctx.SkipLength-lx-1))
	// Compute vy from the following ly bytes.
	vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2+types.Register(lx), ly)))

	// Calculate the effective memory address.
	addr := pvm.State.Registers[ra] + vx

	// Use the opcode from the context to choose the correct store operation.
	switch ctx.Instruction {
	case 70: // store_imm_ind_u8
		pvm.State.RAM.Mutate(uint64(addr), uint8(vy), ram.Wrap, true)
	case 71: // store_imm_ind_u16
		serialized := serializer.EncodeLittleEndian(2, uint64(uint16(vy)))
		pvm.State.RAM.MutateRange(uint64(addr), serialized, ram.Wrap, true)
	case 72: // store_imm_ind_u32
		serialized := serializer.EncodeLittleEndian(4, uint64(uint32(vy)))
		pvm.State.RAM.MutateRange(uint64(addr), serialized, ram.Wrap, true)
	case 73: // store_imm_ind_u64
		serialized := serializer.EncodeLittleEndian(8, uint64(vy))
		pvm.State.RAM.MutateRange(uint64(addr), serialized, ram.Wrap, true)
	default:
		panic(fmt.Sprintf("handleTwoImmValuesIndirect: unexpected opcode %d", ctx.Instruction))
	}
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleOneRegOneImmOneOff(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Precompute the immediate values and the register operand.
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)%16))
	lx := min(4, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1)/16%8))
	// vx is the first immediate.
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(
		getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx)))
	ly := min(4, max(0, ctx.SkipLength-lx-1))
	// For branch instructions the second immediate is an offset,
	// so add it to the current instruction counter.
	branchOffset := serializer.UnsignedToSigned(ly, serializer.DecodeLittleEndian(
		getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2+types.Register(lx), ly)))
	vy := pvm.InstructionCounter + types.Register(branchOffset)

	var cond bool
	switch ctx.Instruction {
	case 80: // load_imm_jump
		// For load-imm-jump, store vx into the destination register.
		pvm.State.Registers[ra] = vx
		cond = true
	case 81: // branch_eq_imm
		cond = pvm.State.Registers[ra] == vx
	case 82: // branch_ne_imm
		cond = pvm.State.Registers[ra] != vx
	case 83: // branch_lt_u_imm
		cond = pvm.State.Registers[ra] < vx
	case 84: // branch_le_u_imm
		cond = pvm.State.Registers[ra] <= vx
	case 85: // branch_ge_u_imm
		cond = pvm.State.Registers[ra] >= vx
	case 86: // branch_gt_u_imm
		cond = pvm.State.Registers[ra] > vx
	case 87: // branch_lt_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) < serializer.UnsignedToSigned(8, uint64(vx))
	case 88: // branch_le_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) <= serializer.UnsignedToSigned(8, uint64(vx))
	case 89: // branch_ge_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) >= serializer.UnsignedToSigned(8, uint64(vx))
	case 90: // branch_gt_s_imm
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) > serializer.UnsignedToSigned(8, uint64(vx))
	default:
		panic(fmt.Sprintf("handleBranchImm: unexpected opcode %d", ctx.Instruction))
	}

	// Execute the branch. The branch() function returns the exit reason
	// and the next instruction counter based on the branch condition.
	return branch(vy, cond, pvm.nextInstructionCounter(ctx.SkipLength), pvm.BasicBlockBeginningOpcodes)
}

func handleTwoReg(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Extract the two register operands from the same instruction byte.
	// The lower 4 bits specify the destination register (rd),
	// and the upper 4 bits specify the source register (ra).
	rd := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))/16)

	switch ctx.Instruction {
	case 100: // move_reg
		// Copy the value from source register to destination register.
		pvm.State.Registers[rd] = pvm.State.Registers[ra]

	case 101: // sbrk
		// Allocate memory from the heap.
		h := types.Register(0)
		if pvm.State.RAM.BeginningOfHeap != nil {
			h = types.Register(*pvm.State.RAM.BeginningOfHeap)
		}
		size := uint64(pvm.State.Registers[ra])
		if size == 0 {
			pvm.State.Registers[rd] = h
		} else {
			pvm.State.Registers[rd] = h
			pvm.State.RAM.MutateAccessRange(uint64(h), size, ram.Mutable, ram.NoWrap)
			h += types.Register(size)
			var heapIndex ram.RamIndex = ram.RamIndex(h)
			pvm.State.RAM.BeginningOfHeap = &heapIndex
		}

	case 102: // count_set_bits_64
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).SumBits(),
		)

	case 103: // count_set_bits_32
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(4, uint64(uint32(pvm.State.Registers[ra]))).SumBits(),
		)

	case 104: // leading_zero_bits_64
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).LeadingZeros(),
		)

	case 105: // leading_zero_bits_32
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(4, uint64(uint32(pvm.State.Registers[ra]))).LeadingZeros(),
		)

	case 106: // trailing_zero_bits_64
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).TrailingZeros(),
		)

	case 107: // trailing_zero_bits_32
		pvm.State.Registers[rd] = types.Register(
			serializer.UintToBitSequenceBE(4, uint64(uint32(pvm.State.Registers[ra]))).TrailingZeros(),
		)

	case 108: // sign_extend_8
		pvm.State.Registers[rd] = types.Register(
			serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(1, uint64(uint8(pvm.State.Registers[ra])))),
		)

	case 109: // sign_extend_16
		pvm.State.Registers[rd] = types.Register(
			serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(2, uint64(uint16(pvm.State.Registers[ra])))),
		)

	case 110: // zero_extend_16
		pvm.State.Registers[rd] = types.Register(uint16(pvm.State.Registers[ra]))

	case 111: // reverse_bytes
		bytes := serializer.EncodeLittleEndian(8, uint64(pvm.State.Registers[ra]))
		slices.Reverse(bytes)
		pvm.State.Registers[rd] = types.Register(serializer.DecodeLittleEndian(bytes))

	default:
		panic(fmt.Sprintf("handleTwoReg: unexpected opcode %d", ctx.Instruction))
	}
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleTwoRegOneImm(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Extract the two register operands from the same instruction byte.
	// Lower 4 bits for 'ra' (destination) and upper 4 bits for 'rb' (source).
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	rb := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))/16)

	// Compute the immediate value.
	lx := min(4, max(0, ctx.SkipLength-1))
	vx := signExtendImmediate(lx, uint64(serializer.DecodeLittleEndian(
		getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx))))

	switch ctx.Instruction {
	case 120: // store_ind_u8
		pvm.State.RAM.Mutate(uint64(pvm.State.Registers[rb]+types.Register(vx)),
			byte(pvm.State.Registers[ra]), ram.Wrap, true)
	case 121: // store_ind_u16
		pvm.State.RAM.MutateRange(uint64(pvm.State.Registers[rb]+types.Register(vx)),
			serializer.EncodeLittleEndian(2, uint64(uint16(pvm.State.Registers[ra]))), ram.Wrap, true)
	case 122: // store_ind_u32
		pvm.State.RAM.MutateRange(uint64(pvm.State.Registers[rb]+types.Register(vx)),
			serializer.EncodeLittleEndian(4, uint64(uint32(pvm.State.Registers[ra]))), ram.Wrap, true)
	case 123: // store_ind_u64
		pvm.State.RAM.MutateRange(uint64(pvm.State.Registers[rb]+types.Register(vx)),
			serializer.EncodeLittleEndian(8, uint64(pvm.State.Registers[ra])), ram.Wrap, true)
	case 124: // load_ind_u8
		pvm.State.Registers[ra] = types.Register(pvm.State.RAM.Inspect(uint64(pvm.State.Registers[rb]+types.Register(vx)), ram.Wrap, true))
	case 125: // load_ind_i8
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(1, uint64(pvm.State.RAM.Inspect(uint64(pvm.State.Registers[rb]+types.Register(vx)), ram.Wrap, true)))))
	case 126: // load_ind_u16
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(
			pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[rb]+types.Register(vx)), 2, ram.Wrap, true)))
	case 127: // load_ind_i16
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(2, serializer.DecodeLittleEndian(
				pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[rb]+types.Register(vx)), 2, ram.Wrap, true)))))
	case 128: // load_ind_u32
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(
			pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[rb]+types.Register(vx)), 4, ram.Wrap, true)))
	case 129: // load_ind_i32
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(4, serializer.DecodeLittleEndian(
				pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[rb]+types.Register(vx)), 4, ram.Wrap, true)))))
	case 130: // load_ind_u64
		pvm.State.Registers[ra] = types.Register(serializer.DecodeLittleEndian(
			pvm.State.RAM.InspectRange(uint64(pvm.State.Registers[rb]+types.Register(vx)), 8, ram.Wrap, true)))
	case 131: // add_imm_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[rb]+vx)))
	case 132: // and_imm
		pvm.State.Registers[ra] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])).
				And(serializer.UintToBitSequenceLE(8, uint64(vx)))))
	case 133: // xor_imm
		pvm.State.Registers[ra] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])).
				Xor(serializer.UintToBitSequenceLE(8, uint64(vx)))))
	case 134: // or_imm
		pvm.State.Registers[ra] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])).
				Or(serializer.UintToBitSequenceLE(8, uint64(vx)))))
	case 135: // mul_imm_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[rb]*vx)))
	case 136: // set_lt_u_imm
		if pvm.State.Registers[rb] < vx {
			pvm.State.Registers[ra] = 1
		} else {
			pvm.State.Registers[ra] = 0
		}
	case 137: // set_lt_s_imm
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])) < serializer.UnsignedToSigned(8, uint64(vx)) {
			pvm.State.Registers[ra] = 1
		} else {
			pvm.State.Registers[ra] = 0
		}
	case 138: // shlo_l_imm_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[rb]<<(vx%32))))
	case 139: // shlo_r_imm_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[rb])>>(vx%32)))
	case 140: // shar_r_imm_32
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[rb])))>>(vx%32)))
	case 141: // neg_add_imm_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(vx-pvm.State.Registers[rb])))
	case 142: // set_gt_u_imm
		if pvm.State.Registers[rb] > vx {
			pvm.State.Registers[ra] = 1
		} else {
			pvm.State.Registers[ra] = 0
		}
	case 143: // set_get_s_imm
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])) > serializer.UnsignedToSigned(8, uint64(vx)) {
			pvm.State.Registers[ra] = 1
		} else {
			pvm.State.Registers[ra] = 0
		}
	case 144: // shlo_l_imm_alt_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(vx<<(pvm.State.Registers[rb]%32))))
	case 145: // shlo_r_imm_alt_32
		pvm.State.Registers[ra] = signExtendImmediate(4, uint64(uint32(vx)>>(pvm.State.Registers[rb]%32)))
	case 146: // shar_r_imm_alt_32
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(4, uint64(uint32(vx)))>>(pvm.State.Registers[rb]%32)))
	case 147: // cmov_iz_imm
		if pvm.State.Registers[rb] == 0 {
			pvm.State.Registers[ra] = vx
		}
	case 148: // cmov_nz_imm
		if pvm.State.Registers[rb] != 0 {
			pvm.State.Registers[ra] = vx
		}
	case 149: // add_imm_64
		pvm.State.Registers[ra] = pvm.State.Registers[rb] + vx
	case 150: // mul_imm_64
		pvm.State.Registers[ra] = pvm.State.Registers[rb] * vx
	case 151: // shlo_l_imm_64
		pvm.State.Registers[ra] = signExtendImmediate(8, uint64(pvm.State.Registers[rb]<<(vx%64)))
	case 152: // shlo_r_imm_64
		pvm.State.Registers[ra] = signExtendImmediate(8, uint64(pvm.State.Registers[rb]>>(vx%64)))
	case 153: // shar_r_imm_64
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))>>(vx%64)))
	case 154: // neg_add_imm_64
		pvm.State.Registers[ra] = vx - pvm.State.Registers[rb]
	case 155: // shlo_l_imm_alt_64
		pvm.State.Registers[ra] = vx << (pvm.State.Registers[rb] % 64)
	case 156: // shlo_r_imm_alt_64
		pvm.State.Registers[ra] = vx >> (pvm.State.Registers[rb] % 64)
	case 157: // shar_r_imm_alt_64
		pvm.State.Registers[ra] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(8, uint64(vx))>>(pvm.State.Registers[rb]%64)))
	case 158: // rot_r_64_imm
		pvm.State.Registers[ra] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])).Rotate(int(vx))))
	case 159: // rot_r_64_imm_alt
		pvm.State.Registers[ra] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(vx)).Rotate(int(pvm.State.Registers[rb]))))
	case 160: // rot_r_32_imm
		pvm.State.Registers[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(4, uint64(pvm.State.Registers[rb])).Rotate(int(vx))))
	case 161: // rot_r_32_imm_alt
		pvm.State.Registers[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(4, uint64(vx)).Rotate(int(pvm.State.Registers[rb]))))
	default:
		panic(fmt.Sprintf("handleTwoRegOneImm: unexpected opcode %d", ctx.Instruction))
	}
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

func handleTwoRegOneOffset(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Extract two register operands from the same instruction byte.
	// Lower 4 bits for 'ra', upper 4 bits for 'rb'.
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	rb := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))/16)

	// Compute the immediate branch offset.
	lx := min(4, max(0, ctx.SkipLength-1))
	vx := pvm.InstructionCounter + types.Register(serializer.UnsignedToSigned(lx,
		serializer.DecodeLittleEndian(getInstructionRange(pvm.Instructions, pvm.InstructionCounter+2, lx))))

	var cond bool
	switch ctx.Instruction {
	case 170: // branch_eq
		cond = pvm.State.Registers[ra] == pvm.State.Registers[rb]
	case 171: // branch_ne
		cond = pvm.State.Registers[ra] != pvm.State.Registers[rb]
	case 172: // branch_lt_u
		cond = pvm.State.Registers[ra] < pvm.State.Registers[rb]
	case 173: // branch_lt_s
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) < serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))
	case 174: // branch_ge_u
		cond = pvm.State.Registers[ra] >= pvm.State.Registers[rb]
	case 175: // branch_ge_s
		cond = serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) >= serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))
	default:
		panic(fmt.Sprintf("handleTwoRegOneOffset: unexpected opcode %d", ctx.Instruction))
	}

	// Execute the branch based on the computed condition.
	return branch(vx, cond, pvm.nextInstructionCounter(ctx.SkipLength), pvm.BasicBlockBeginningOpcodes)
}

func handleLoadImmJumpInd(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Extract the register operands from the same instruction byte.
	// Lower 4 bits: destination register (ra); upper 4 bits: base register (rb).
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	rb := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))/16)

	// Extract the immediate length for the first immediate.
	lx := min(4, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+2))%8)
	// Compute the length for the second immediate.
	ly := min(4, max(0, ctx.SkipLength-lx-2))

	// Decode the first immediate value.
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(
		getInstructionRange(pvm.Instructions, pvm.InstructionCounter+3, lx)))
	// Decode the second immediate value.
	vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(
		getInstructionRange(pvm.Instructions, pvm.InstructionCounter+3+types.Register(lx), ly)))

	// Perform a dynamic jump based on the computed offset (rb + vy).

	// Store the immediate value vx into the destination register.
	pvm.State.Registers[ra] = vx
	return djump(
		uint32(pvm.State.Registers[rb]+vy),
		pvm.nextInstructionCounter(ctx.SkipLength),
		pvm.DynamicJumpTable,
		pvm.BasicBlockBeginningOpcodes,
	)
}

func handleThreeReg(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register) {
	// Extract source registers from the same instruction byte.
	// Lower 4 bits: ra; upper 4 bits: rb.
	ra := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))%16)
	rb := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+1))/16)
	// Extract destination register from the following byte.
	rd := min(12, int(getInstruction(pvm.Instructions, pvm.InstructionCounter+2)))

	switch ctx.Instruction {
	case 190: // add_32
		pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra]+pvm.State.Registers[rb])))
	case 191: // sub_32
		pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra]-pvm.State.Registers[rb])))
	case 192: // mul_32
		pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra]*pvm.State.Registers[rb])))
	case 193: // div_u_32
		if uint32(pvm.State.Registers[rb]) == 0 {
			pvm.State.Registers[rd] = (1 << 64) - 1
		} else {
			pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra])/uint32(pvm.State.Registers[rb])))
		}
	case 194: // div_s_32
		a := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[ra])))
		b := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[rb])))
		if b == 0 {
			pvm.State.Registers[rd] = (1 << 64) - 1
		} else if a == -(1<<31) && b == -1 {
			pvm.State.Registers[rd] = types.Register(a)
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, a/b))
		}
	case 195: // rem_u_32
		if uint32(pvm.State.Registers[rb]) == 0 {
			pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra])))
		} else {
			pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra])%uint32(pvm.State.Registers[rb])))
		}
	case 196: // rem_s_32
		a := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[ra])))
		b := serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[rb])))
		if a == -(1<<31) && b == -1 {
			pvm.State.Registers[rd] = 0
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, smod(a, b)))
		}
	case 197: // shlo_l_32
		pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra]<<(pvm.State.Registers[rb]%32))))
	case 198: // shlo_r_32
		pvm.State.Registers[rd] = signExtendImmediate(4, uint64(uint32(pvm.State.Registers[ra])>>(pvm.State.Registers[rb]%32)))
	case 199: // shar_r_32
		pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(4, uint64(uint32(pvm.State.Registers[ra])))>>(pvm.State.Registers[rb]%32)))
	case 200: // add_64
		pvm.State.Registers[rd] = pvm.State.Registers[ra] + pvm.State.Registers[rb]
	case 201: // sub_64
		pvm.State.Registers[rd] = pvm.State.Registers[ra] - pvm.State.Registers[rb] // TODO: change in GP
	case 202: // mul_64
		pvm.State.Registers[rd] = pvm.State.Registers[ra] * pvm.State.Registers[rb]
	case 203: // div_u_64
		if pvm.State.Registers[rb] == 0 {
			pvm.State.Registers[rd] = (1 << 64) - 1
		} else {
			pvm.State.Registers[rd] = pvm.State.Registers[ra] / pvm.State.Registers[rb]
		}
	case 204: // div_s_64
		if pvm.State.Registers[rb] == 0 {
			pvm.State.Registers[rd] = (1 << 64) - 1
		} else if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) == -(1<<63) &&
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])) == -1 {
			pvm.State.Registers[rd] = pvm.State.Registers[ra]
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8,
				serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra]))/
					serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))))
		}
	case 205: // rem_u_64
		if pvm.State.Registers[rb] == 0 {
			pvm.State.Registers[rd] = pvm.State.Registers[ra]
		} else {
			pvm.State.Registers[rd] = pvm.State.Registers[ra] % pvm.State.Registers[rb]
		}
	case 206: // rem_s_64
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) == -(1<<63) &&
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])) == -1 {
			pvm.State.Registers[rd] = 0
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8,
				smod(serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])),
					serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])))))
		}
	case 207: // shlo_l_64
		pvm.State.Registers[rd] = pvm.State.Registers[ra] << (pvm.State.Registers[rb] % 64)
	case 208: // shlo_r_64
		pvm.State.Registers[rd] = pvm.State.Registers[ra] >> (pvm.State.Registers[rb] % 64)
	case 209: // shar_r_64
		pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8,
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra]))>>(pvm.State.Registers[rb]%64)))
	case 210: // and
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[ra])).And(
				serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])))))
	case 211: // xor
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[ra])).Xor(
				serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])))))
	case 212: // or
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[ra])).Or(
				serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[rb])))))
	case 213: // mul_upper_s_s
		pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, floorProductDiv2Pow64Signed(
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])),
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])))))
	case 214: // mul_upper_u_u
		hi, _ := bits.Mul64(uint64(pvm.State.Registers[ra]), uint64(pvm.State.Registers[rb]))
		pvm.State.Registers[rd] = types.Register(hi)
	case 215: // mul_upper_s_u
		pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, mulDiv2Pow64(
			serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])),
			uint64(pvm.State.Registers[rb]))))
	case 216: // set_lt_u
		if pvm.State.Registers[ra] < pvm.State.Registers[rb] {
			pvm.State.Registers[rd] = 1
		} else {
			pvm.State.Registers[rd] = 0
		}
	case 217: // set_lt_s
		if serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra])) < serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb])) {
			pvm.State.Registers[rd] = 1
		} else {
			pvm.State.Registers[rd] = 0
		}
	case 218: // cmov_iz
		if pvm.State.Registers[rb] == 0 {
			pvm.State.Registers[rd] = pvm.State.Registers[ra]
		}
	case 219: // cmov_nz
		if pvm.State.Registers[rb] != 0 {
			pvm.State.Registers[rd] = pvm.State.Registers[ra]
		}
	case 220: // rot_l_64
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[ra])).Rotate(-int(pvm.State.Registers[rb]))))
	case 221: // rot_l_32
		pvm.State.Registers[rd] = signExtendImmediate(4, serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(4, uint64(pvm.State.Registers[ra])).Rotate(-int(pvm.State.Registers[rb]))))
	case 222: // rot_r_64
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(8, uint64(pvm.State.Registers[ra])).Rotate(int(pvm.State.Registers[rb]))))
	case 223: // rot_r_32
		pvm.State.Registers[rd] = signExtendImmediate(4, serializer.BitSequenceToUintLE(
			serializer.UintToBitSequenceLE(4, uint64(pvm.State.Registers[ra])).Rotate(int(pvm.State.Registers[rb]))))
	case 224: // and_inv
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintBE(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).And(
				serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[rb])).Invert())))
	case 225: // or_inv
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintBE(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).Or(
				serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[rb])).Invert())))
	case 226: // xnor
		pvm.State.Registers[rd] = types.Register(serializer.BitSequenceToUintBE(
			serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[ra])).Xor(
				serializer.UintToBitSequenceBE(8, uint64(pvm.State.Registers[rb]))).Invert()))
	case 227: // max
		l := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra]))
		r := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))
		if l > r {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, l))
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, r))
		}
	case 228: // max_u
		pvm.State.Registers[rd] = max(pvm.State.Registers[ra], pvm.State.Registers[rb])
	case 229: // min
		l := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[ra]))
		r := serializer.UnsignedToSigned(8, uint64(pvm.State.Registers[rb]))
		if l < r {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, l))
		} else {
			pvm.State.Registers[rd] = types.Register(serializer.SignedToUnsigned(8, r))
		}
	case 230: // min_u
		pvm.State.Registers[rd] = min(pvm.State.Registers[ra], pvm.State.Registers[rb])
	default:
		panic(fmt.Sprintf("handleThreeReg: unexpected opcode %d", ctx.Instruction))
	}
	return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
}

// nextInstructionCounter returns the next instruction counter position
// after executing the current instruction with the given skip length
func (pvm *PVM) nextInstructionCounter(skipLength int) types.Register {
	return pvm.InstructionCounter + 1 + types.Register(skipLength)
}
