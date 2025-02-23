package pvm

import (
	"log"
	"slices"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

func SingleStep(instructions []byte, opcodes bitsequence.BitSequence, dynamicJumpTable []Register, instructionCounter Register, gas types.GasValue, registers [13]Register, ram *RAM) (ExitReason, Register, types.SignedGasValue, [13]Register, *RAM, error) {
	exitReason := NewSimpleExitReason(ExitGo)
	skipLength := skip(instructionCounter, opcodes)
	basicBlockBeginningOpcodes := basicBlockBeginningOpcodes(instructions, opcodes)
	memoryAccessExceptionIndices := []RamIndex{}
	nextInstructionCounter := instructionCounter + 1 + Register(skipLength)
	nextGas := types.SignedGasValue(gas)
	nextRegisters := registers
	nextRam := ram
	instruction := getInstruction(instructions, instructionCounter)
	switch instruction {
	case 0: // trap
		exitReason = NewSimpleExitReason(ExitPanic)
	case 1: // fallthrough
	case 10: // ecalli
		lx := minInt(4, skipLength)
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+1, lx)))
		exitReason = NewComplexExitReason(ExitHostCall, vx)
	case 20: // load_imm_64
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+Register(1))%16))
		vx := serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, 8))
		nextRegisters[ra] = Register(vx)
	case 30:
	case 31:
	case 32:
	case 33:
		lx := minInt(4, int(getInstruction(instructions, instructionCounter+1)%8))
		ly := minInt(4, maxInt(0, skipLength-lx-1))
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2+Register(lx), ly)))
		if instruction == 30 { // store_imm_u8
			nextRam.mutate(vx, byte(vy), &memoryAccessExceptionIndices)
		} else if instruction == 31 { // store_imm_u16
			serializedVy := serializer.EncodeLittleEndian(2, uint64(vy))
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		} else if instruction == 32 { // store_imm_u32
			serializedVy := serializer.EncodeLittleEndian(4, uint64(vy))
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		} else { // // store_imm_u64
			serializedVy := serializer.EncodeLittleEndian(8, uint64(vy))
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		}
	case 40: // jump
		lx := minInt(4, skipLength)
		vx := instructionCounter + Register(serializer.UnsignedToSigned(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+1, lx))))
		exitReason, nextInstructionCounter = branch(vx, true, instructionCounter, basicBlockBeginningOpcodes)
	case 50:
	case 51:
	case 52:
	case 53:
	case 54:
	case 55:
	case 56:
	case 57:
	case 58:
	case 59:
	case 60:
	case 61:
	case 62:
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+1)%16))
		lx := minInt(4, maxInt(0, skipLength-1))
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		if instruction == 50 { // jump_ind
			exitReason, nextInstructionCounter = djump(uint32(registers[ra]+vx), instructionCounter, dynamicJumpTable, basicBlockBeginningOpcodes)
		} else if instruction == 51 { // load_imm
			nextRegisters[ra] = vx
		} else if instruction == 52 { // load_u8
			nextRegisters[ra] = Register(ram.inspect(vx, &memoryAccessExceptionIndices))
		} else if instruction == 53 { // load_i8
			nextRegisters[ra] = signExtendImmediate(1, uint64(ram.inspect(vx, &memoryAccessExceptionIndices)))
		} else if instruction == 54 { // load_u16
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(vx, 2, &memoryAccessExceptionIndices)))
		} else if instruction == 55 { // load_i16
			nextRegisters[ra] = signExtendImmediate(2, serializer.DecodeLittleEndian(ram.inspectRange(vx, 2, &memoryAccessExceptionIndices)))
		} else if instruction == 56 { // load_u32
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(vx, 4, &memoryAccessExceptionIndices)))
		} else if instruction == 57 { // load_i32
			nextRegisters[ra] = signExtendImmediate(4, serializer.DecodeLittleEndian(ram.inspectRange(vx, 4, &memoryAccessExceptionIndices)))
		} else if instruction == 58 { // load_u64
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(vx, 8, &memoryAccessExceptionIndices)))
		} else if instruction == 59 { // store_u8
			nextRam.mutate(vx, uint8(registers[ra]), &memoryAccessExceptionIndices)
		} else if instruction == 60 { // store_u16
			serialized := serializer.EncodeLittleEndian(2, uint64(registers[ra]))
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		} else if instruction == 61 { // store_u32
			serialized := serializer.EncodeLittleEndian(4, uint64(registers[ra]))
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		} else { // store_u64
			serialized := serializer.EncodeLittleEndian(8, uint64(registers[ra]))
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		}
	case 70:
	case 71:
	case 72:
	case 73:
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+1)%16))
		lx := minInt(4, int(getInstruction(instructions, instructionCounter+1)/16)%8)
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		ly := minInt(4, maxInt(0, skipLength-lx-1))
		vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2+Register(lx), ly)))
		if instruction == 70 { // store_imm_ind_u8
			ram.mutate(registers[ra]+vx, uint8(vy), &memoryAccessExceptionIndices)
		} else if instruction == 71 { // store_imm_ind_u16
			serialized := serializer.EncodeLittleEndian(2, uint64(vy))
			ram.mutateRange(registers[ra]+vx, serialized, &memoryAccessExceptionIndices)
		} else if instruction == 72 { // store_imm_ind_u32
			serialized := serializer.EncodeLittleEndian(4, uint64(vy))
			ram.mutateRange(registers[ra]+vx, serialized, &memoryAccessExceptionIndices)
		} else { // store_imm_ind_u64
			serialized := serializer.EncodeLittleEndian(8, uint64(vy))
			ram.mutateRange(registers[ra]+vx, serialized, &memoryAccessExceptionIndices)
		}
	case 80:
	case 81:
	case 82:
	case 83:
	case 84:
	case 85:
	case 86:
	case 87:
	case 88:
	case 89:
	case 90:
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+1)%16))
		lx := minInt(4, int(getInstruction(instructions, instructionCounter+1)/16)%8)
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		ly := minInt(4, maxInt(0, skipLength-lx-1))
		vy := instructionCounter + Register(serializer.UnsignedToSigned(ly, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2+Register(lx), ly))))
		var cond bool
		if instruction == 80 { // load_imm_jump
			nextRegisters[ra] = vx
			cond = true
		} else if instruction == 81 { // branch_eq_imm
			cond = registers[ra] == vx
		} else if instruction == 82 { // branch_ne_imm
			cond = registers[ra] != vx
		} else if instruction == 83 { // branch_lt_u_imm
			cond = registers[ra] < vx
		} else if instruction == 84 { // branch_le_u_imm
			cond = registers[ra] <= vx
		} else if instruction == 85 { // branch_ge_u_imm
			cond = registers[ra] >= vx
		} else if instruction == 86 { // branch_gt_u_imm
			cond = registers[ra] > vx
		} else if instruction == 87 { // branch_lt_s_imm
			cond = (serializer.UnsignedToSigned(8, uint64(registers[ra])) < serializer.UnsignedToSigned(8, uint64(vx)))
		} else if instruction == 88 { // branch_le_s_imm
			cond = (serializer.UnsignedToSigned(8, uint64(registers[ra])) <= serializer.UnsignedToSigned(8, uint64(vx)))
		} else if instruction == 89 { // branch_ge_s_imm
			cond = (serializer.UnsignedToSigned(8, uint64(registers[ra])) >= serializer.UnsignedToSigned(8, uint64(vx)))
		} else { // branch_gt_s_imm
			cond = (serializer.UnsignedToSigned(8, uint64(registers[ra])) > serializer.UnsignedToSigned(8, uint64(vx)))
		}
		exitReason, nextInstructionCounter = branch(vy, cond, instructionCounter, basicBlockBeginningOpcodes)
	case 100:
	case 101:
	case 102:
	case 103:
	case 104:
	case 105:
	case 106:
	case 107:
	case 108:
	case 109:
	case 110:
	case 111:
		rd := minInt(12, int(getInstruction(instructions, instructionCounter+1)%16))
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+1)/16))
		if instruction == 100 { // move_reg
			nextRegisters[rd] = registers[ra]
		} else if instruction == 101 { // sbrk
			h := Register(0)
			if ram.BeginningOfHeap != nil {
				h = Register(*ram.BeginningOfHeap)
			}
		outer:
			for ; h < MaxRegister; h++ {
				for i := h; i < h+registers[ra]; i++ {
					if ram.accessForIndex(RamIndex(i)) != Inaccessible {
						continue outer
					}
				}
				for i := h; i < h+registers[ra]; i++ {
					ram.setAccessForIndex(RamIndex(i), Mutable)
				}
				nextRegisters[rd] = h
				break
			}
		} else if instruction == 102 { // count_set_bits_64
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).SumBits())
		} else if instruction == 103 { // count_set_bits_32
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(4, uint64(registers[ra])).SumBits())
		} else if instruction == 104 { // leading_zero_bits_64
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).LeadingZeros())
		} else if instruction == 105 { // leading_zero_bits_32
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(4, uint64(registers[ra])).LeadingZeros())
		} else if instruction == 106 { // trailing_zero_bits_64
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).TrailingZeros())
		} else if instruction == 107 { // trailing_zero_bits_32
			nextRegisters[rd] = Register(serializer.UintToBitSequenceLE(4, uint64(registers[ra])).TrailingZeros())
		} else if instruction == 108 { // sign_extend_8
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(1, uint64(registers[ra]))))
		} else if instruction == 109 { // sign_extend_16
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(2, uint64(registers[ra]))))
		} else if instruction == 110 { // zero_extend_16
			nextRegisters[rd] = Register(uint16(registers[ra]))
		} else if instruction == 111 { // reverse_bytes
			bytes := serializer.EncodeLittleEndian(8, uint64(registers[ra]))
			slices.Reverse(bytes)
			nextRegisters[rd] = Register(serializer.DecodeLittleEndian(bytes))
		}
	case 120:
	case 121:
	case 122:
	case 123:
	case 124:
	case 125:
	case 126:
	case 127:
	case 128:
	case 129:
	case 130:
	case 131:
	case 132:
	case 133:
	case 134:
	case 135:
	case 136:
	case 137:
	case 138:
	case 139:
	case 140:
	case 141:
	case 142:
	case 143:
	case 144:
	case 145:
	case 146:
	case 147:
	case 148:
	case 149:
	case 150:
	case 151:
	case 152:
	case 153:
	case 154:
	case 155:
	case 156:
	case 157:
	case 158:
	case 159:
	case 160:
	case 161:
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+1))%16)
		rb := minInt(12, int(getInstruction(instructions, instructionCounter+1)/16))
		lx := minInt(4, maxInt(0, skipLength-1))
		vx := signExtendImmediate(lx, uint64(serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx))))
		switch instruction {
		case 120: // store_ind_u8
			ram.mutate(registers[rb]+Register(vx), byte(registers[ra]), &memoryAccessExceptionIndices)
		case 121: // store_ind_u16
			ram.mutateRange(registers[rb]+Register(vx), serializer.EncodeLittleEndian(2, uint64(registers[ra])), &memoryAccessExceptionIndices)
		case 122: // store_ind_u32
			ram.mutateRange(registers[rb]+Register(vx), serializer.EncodeLittleEndian(4, uint64(registers[ra])), &memoryAccessExceptionIndices)
		case 123: // store_ind_u64
			ram.mutateRange(registers[rb]+Register(vx), serializer.EncodeLittleEndian(8, uint64(registers[ra])), &memoryAccessExceptionIndices)
		case 124: // load_ind_u8
			nextRegisters[ra] = Register(ram.inspect(registers[rb]+Register(vx), &memoryAccessExceptionIndices))
		case 125: // load_ind_i8
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(1, uint64(ram.inspect(registers[rb]+Register(vx), &memoryAccessExceptionIndices)))))
		case 126: // load_ind_u16
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(registers[rb]+Register(vx), 2, &memoryAccessExceptionIndices)))
		case 127: // load_ind_i16
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(2, serializer.DecodeLittleEndian(ram.inspectRange(registers[rb]+Register(vx), 2, &memoryAccessExceptionIndices)))))
		case 128: // load_ind_u32
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(registers[rb]+Register(vx), 4, &memoryAccessExceptionIndices)))
		case 129: // load_ind_i32
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(4, serializer.DecodeLittleEndian(ram.inspectRange(registers[rb]+Register(vx), 4, &memoryAccessExceptionIndices)))))
		case 130: // load_ind_u64
			nextRegisters[ra] = Register(serializer.DecodeLittleEndian(ram.inspectRange(registers[rb]+Register(vx), 8, &memoryAccessExceptionIndices)))
		case 131: // add_imm_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(registers[rb]+vx))
		case 132: // and_imm
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[rb])).And(serializer.UintToBitSequenceLE(8, uint64(vx)))))
		case 133: // xor_imm
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[rb])).Xor(serializer.UintToBitSequenceLE(8, uint64(vx)))))
		case 134: // or_imm
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[rb])).Or(serializer.UintToBitSequenceLE(8, uint64(vx)))))
		case 135: // mul_imm_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(registers[rb]*vx))
		case 136: // set_lt_u_imm
			if registers[rb] < vx {
				nextRegisters[ra] = 1
			} else {
				nextRegisters[ra] = 0
			}
		case 137: // set_lt_s_imm
			if serializer.UnsignedToSigned(8, uint64(registers[rb])) < serializer.UnsignedToSigned(8, uint64(vx)) {
				nextRegisters[ra] = 1
			} else {
				nextRegisters[ra] = 0
			}
		case 138: // shlo_l_imm_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(registers[rb]*Register(1<<vx%32)))
		case 139: // shlo_r_imm_32
			nextRegisters[ra] = signExtendImmediate(4, uint64((registers[rb]%(1<<32))/(1<<vx%32)))
		case 140: // shar_r_imm_32
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(4, uint64(registers[rb]))/int64(1<<vx%32)))
		case 141: // neg_add_imm_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(vx+(1<<32)-registers[rb]))
		case 142: // set_gt_u_imm
			if registers[rb] > vx {
				nextRegisters[ra] = 1
			} else {
				nextRegisters[ra] = 0
			}
		case 143: // set_get_s_imm
			if serializer.UnsignedToSigned(8, uint64(registers[rb])) > serializer.UnsignedToSigned(8, uint64(vx)) {
				nextRegisters[ra] = 1
			} else {
				nextRegisters[ra] = 0
			}
		case 144: // shlo_l_imm_alt_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(vx*(1<<(registers[rb]%32))))
		case 145: // shlo_r_imm_alt_32
			nextRegisters[ra] = signExtendImmediate(4, uint64(vx%(1<<32)/(1<<(registers[rb]%32))))
		case 146: // shar_r_imm_alt_32
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(4, uint64(vx))/(1<<(registers[rb]%32))))
		case 147: // cmov_iz_imm
			if registers[rb] == 0 {
				nextRegisters[ra] = vx
			} else {
				nextRegisters[ra] = registers[ra]
			}
		case 148: // cmov_nz_imm
			if registers[rb] != 0 {
				nextRegisters[ra] = vx
			} else {
				nextRegisters[ra] = registers[ra]
			}
		case 149: // add_imm_64
			nextRegisters[ra] = registers[rb] + vx
		case 150: // mul_imm_64
			nextRegisters[ra] = registers[rb] * vx
		case 151: // shlo_l_imm_64
			nextRegisters[ra] = signExtendImmediate(8, uint64(registers[rb]*(1<<(vx%64))))
		case 152: // shlo_r_imm_64
			nextRegisters[ra] = signExtendImmediate(8, uint64(registers[rb]/(1<<(vx%64))))
		case 153: // shar_r_imm_64
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(8, uint64(registers[rb]))/(1<<(vx%64))))
		case 154: // neg_add_imm_64
			nextRegisters[ra] = vx - registers[rb]
		case 155: // shlo_l_imm_alt_64
			nextRegisters[ra] = vx * (1 << (registers[rb] % 64))
		case 156: // shlo_r_imm_alt_64
			nextRegisters[ra] = vx / (1 << (registers[rb] % 64))
		case 157: // shar_r_imm_alt_64
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(8, uint64(vx))/(1<<(registers[rb]%64))))
		case 158: // rot_r_64_imm
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[rb])).Rotate(int(vx))))
		case 159: // rot_r_64_imm_alt
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(vx)).Rotate(int(registers[rb]))))
		case 160: // rot_r_32_imm
			nextRegisters[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(registers[rb])).Rotate(int(vx))))
		case 161: // rot_r_32_imm_alt
			nextRegisters[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(vx)).Rotate(int(registers[rb]))))
		}
	}
	// memory access exception handling
	minRamIndex := minRamIndex(memoryAccessExceptionIndices)
	if minRamIndex != nil {
		if *minRamIndex < MinValidRamIndex {
			exitReason = NewSimpleExitReason(ExitPanic)
		} else {
			exitReason = NewComplexExitReason(ExitPageFault, Register(PageSize*(*minRamIndex/PageSize)))
		}
	}

	return exitReason, nextInstructionCounter, nextGas, nextRegisters, nextRam, nil
}

func getInstruction(instructions []byte, instructionCounter Register) byte {
	if instructionCounter >= Register(len(instructions)) {
		return 0
	}
	return instructions[instructionCounter]
}

func getInstructionRange(instructions []byte, instructionCounter Register, count int) []byte {
	start := int(instructionCounter)
	if start >= len(instructions) {
		return []byte{}
	}
	end := start + count
	if end > len(instructions) {
		end = len(instructions)
	}
	return instructions[start:end]
}

func skip(instructionCounter Register, opcodes bitsequence.BitSequence) int {
	j := 0
	for j < 24 {
		idx := instructionCounter + Register(1+j)
		if idx >= Register(opcodes.Len()) || opcodes.BitAt(int(idx)) {
			break
		}
		j++
	}
	return j
}

func signExtendImmediate(n int, x uint64) Register {
	// Check that n is one of the allowed sizes.
	switch n {
	case 1, 2, 3, 4, 8:
		// ok
	default:
		log.Fatalf("signExtendImmediate: invalid byte length %d (must be 1,2,3,4, or 8)", n)
	}

	// Compute the bit position of the sign bit: 8*n - 1.
	signBitPos := uint64(8*n - 1)
	// signThreshold = 2^(8*n - 1)
	signThreshold := uint64(1) << signBitPos

	// floor(x / 2^(8*n - 1)) will be 0 if the sign bit is not set,
	// or 1 if it is set (since x is in the range [0, 2^(8*n))).
	sign := x / signThreshold

	// Compute offset = 2^64 - 2^(8*n).
	// Because 1<<64 is not representable as a uint64 constant in Go, we compute the mask for the lower 8*n bits:
	//   mask = 2^(8*n) - 1,
	// so that ^mask (the bitwise complement) equals 2^64 - 2^(8*n).
	mask := (uint64(1) << (8 * n)) - 1
	offset := ^mask

	// The sign extension function is then:
	return Register(x + sign*offset)
}

func branch(b Register, C bool, instructionCounter Register, basicBlockBeginningOpcodes bitsequence.BitSequence) (ExitReason, Register) {
	if !C {
		return NewSimpleExitReason(ExitGo), instructionCounter
	}
	if !basicBlockBeginningOpcodes.BitAt(int(b)) {
		return NewSimpleExitReason(ExitPanic), instructionCounter
	}
	return NewSimpleExitReason(ExitGo), b
}

func djump(a uint32, instructionCounter Register, dynamicJumpTable []Register, basicBlockBeginningOpcodes bitsequence.BitSequence) (ExitReason, Register) {
	if a == (1<<32)-(1<<16) { // ??
		return NewSimpleExitReason(ExitHalt), instructionCounter
	}
	nextInstructionCounter := dynamicJumpTable[a/DynamicAddressAlignmentFactor-1]
	if a == 0 || a > uint32(len(dynamicJumpTable)*DynamicAddressAlignmentFactor) || a%DynamicAddressAlignmentFactor != 0 || !basicBlockBeginningOpcodes.BitAt(int(nextInstructionCounter)) {
		return NewSimpleExitReason(ExitPanic), instructionCounter
	}
	return NewSimpleExitReason(ExitGo), nextInstructionCounter
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a < b {
		return b
	}
	return a
}

func minRamIndex(ramIndices []RamIndex) *RamIndex {
	if len(ramIndices) == 0 {
		return nil
	}
	minRamIndex := ramIndices[0]
	for _, ramIndex := range ramIndices {
		if ramIndex < minRamIndex {
			minRamIndex = ramIndex
		}
	}
	return &minRamIndex
}

func instructionIsBasicBlockTermination(b byte) bool {
	switch b {
	case 0:
	case 1:
	case 40:
	case 50:
	case 80:
	case 81:
	case 82:
	case 83:
	case 84:
	case 85:
	case 86:
	case 87:
	case 88:
	case 89:
	case 90:
	case 170:
	case 171:
	case 174:
	case 175:
	case 172:
	case 173:
	case 180:
		return true
	}
	return false
}

func basicBlockBeginningOpcodes(instructions []byte, opcodes bitsequence.BitSequence) bitsequence.BitSequence {
	basicBlockBeginningOpcodes := bitsequence.New()
	bits := make([]bool, len(instructions))
	basicBlockBeginningOpcodes.AppendBits(bits)
	basicBlockBeginningOpcodes.SetBitAt(0, true)
	for n, instruction := range instructions {
		if opcodes.BitAt(n) && instructionIsBasicBlockTermination(instruction) {
			basicBlockBeginningOpcodes.SetBitAt(n+1+skip(Register(n), opcodes), true)
		}
	}
	return *basicBlockBeginningOpcodes
}
