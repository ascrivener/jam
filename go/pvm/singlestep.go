package pvm

import (
	"log"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

func SingleStep(instructions []byte, opcodeBitmask bitsequence.BitSequence, dynamicJumpTable []Register, instructionCounter Register, gas types.GasValue, registers [13]Register, ram RAM) (ExitReason, Register, types.SignedGasValue, [13]Register, RAM, error) {
	exitReason := NewSimpleExitReason(ExitGo)
	l := skip(instructionCounter, opcodeBitmask)
	memoryAccessExceptionIndices := []RamIndex{}
	nextInstructionCounter := instructionCounter + 1 + l
	nextGas := types.SignedGasValue(gas)
	nextRegisters := registers
	nextRam := ram
	instruction := getInstruction(instructions, instructionCounter)
	switch instruction {
	case 0: // trap
		gas = gas - 0
		exitReason = NewSimpleExitReason(ExitPanic)
	case 1: // fallthrough
		gas = gas - 0
	case 10: // ecalli
		gas = gas - 0
		lx := minRegister(4, l)
		vx := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+1, lx)), int(lx))
		exitReason = NewComplexExitReason(ExitHostCall, vx)
	case 20: // load_imm_64
		gas = gas - 0
		ra := minRegister(12, Register(getInstruction(instructions, instructionCounter+Register(1))%16))
		vx := serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2, 8))
		nextRegisters[ra] = Register(vx)
	case 30:
	case 31:
	case 32:
	case 33:
		lx := minRegister(4, Register(getInstruction(instructions, instructionCounter+1)%8))
		ly := minRegister(4, maxRegister(0, l-lx-1))
		vx := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2, lx)), int(lx))
		vy := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2+lx, ly)), int(ly))
		gas = gas - 0
		if instruction == 30 { // store_imm_u8
			nextRam.mutate(vx, byte(vy), memoryAccessExceptionIndices)
		} else if instruction == 31 { // store_imm_u16
			serializedVy, err := serializer.Serialize(uint16(vy))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, memoryAccessExceptionIndices)
		} else if instruction == 32 { // store_imm_u32
			serializedVy, err := serializer.Serialize(uint32(vy))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, memoryAccessExceptionIndices)
		} else { // // store_imm_u64
			serializedVy, err := serializer.Serialize(vy)
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, memoryAccessExceptionIndices)
		}
	case 40: // jump
	}
	// memory access exception handling
	minRamIndex := minRamIndex(memoryAccessExceptionIndices)
	if minRamIndex != nil {
		if *minRamIndex < MinValidRamIndex {
			exitReason = NewSimpleExitReason(ExitPanic)
		} else {
			exitReason = NewComplexExitReason(ExitPageFault, Register(BytesInPage*(*minRamIndex/BytesInPage)))
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

func getInstructionRange(instructions []byte, instructionCounter Register, count Register) []byte {
	start := int(instructionCounter)
	if start >= len(instructions) {
		return []byte{}
	}
	end := start + int(count)
	if end > len(instructions) {
		end = len(instructions)
	}
	return instructions[start:end]
}

func skip(instructionCounter Register, opcodeBitmask bitsequence.BitSequence) Register {
	j := 0
	for j < 24 {
		idx := instructionCounter + Register(1+j)
		if idx >= Register(opcodeBitmask.Len()) || opcodeBitmask.BitAt(int(idx)) {
			break
		}
		j++
	}
	return Register(j)
}

func signExtendImmediate(x uint64, n int) Register {
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

func branch(b Register, C bool, instructionCounter Register) (ExitReason, Register) {
	if !C {
		return NewSimpleExitReason(ExitGo), instructionCounter
	}

}

func minRegister(a, b Register) Register {
	if a < b {
		return a
	}
	return b
}

func maxRegister(a, b Register) Register {
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
