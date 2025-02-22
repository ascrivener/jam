package pvm

import (
	"fmt"
	"log"

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
		vx := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+1, lx)), lx)
		exitReason = NewComplexExitReason(ExitHostCall, vx)
	case 20: // load_imm_64
		ra := minInt(12, int(getInstruction(instructions, instructionCounter+Register(1))%16))
		vx := serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2, 8))
		nextRegisters[ra] = Register(vx)
	case 30:
	case 31:
	case 32:
	case 33:
		lx := minInt(4, int(getInstruction(instructions, instructionCounter+1)%8))
		ly := minInt(4, maxInt(0, skipLength-lx-1))
		vx := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2, lx)), lx)
		vy := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2+Register(lx), ly)), ly)
		if instruction == 30 { // store_imm_u8
			nextRam.mutate(vx, byte(vy), &memoryAccessExceptionIndices)
		} else if instruction == 31 { // store_imm_u16
			serializedVy, err := serializer.Serialize(uint16(vy))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		} else if instruction == 32 { // store_imm_u32
			serializedVy, err := serializer.Serialize(uint32(vy))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		} else { // // store_imm_u64
			serializedVy, err := serializer.Serialize(vy)
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serializedVy, &memoryAccessExceptionIndices)
		}
	case 40: // jump
		lx := minInt(4, skipLength)
		vx := instructionCounter + Register(UnsignedToSigned(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+1, lx)), lx))
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
		vx := signExtendImmediate(serializer.DecodeLittleEndianValue(getInstructionRange(instructions, instructionCounter+2, lx)), lx)
		if instruction == 50 { // jump_ind
			exitReason, nextInstructionCounter = djump(uint32(registers[ra]+vx), instructionCounter, dynamicJumpTable, basicBlockBeginningOpcodes)
		} else if instruction == 51 { // load_imm
			nextRegisters[ra] = vx
		} else if instruction == 52 { // load_u8
			nextRegisters[ra] = Register(ram.inspect(vx, &memoryAccessExceptionIndices))
		} else if instruction == 53 { // load_i8
			nextRegisters[ra] = signExtendImmediate(uint64(ram.inspect(vx, &memoryAccessExceptionIndices)), 1)
		} else if instruction == 54 { // load_u16
			nextRegisters[ra] = Register(serializer.DecodeLittleEndianValue(ram.inspectRange(vx, 2, &memoryAccessExceptionIndices)))
		} else if instruction == 55 { // load_i16
			nextRegisters[ra] = signExtendImmediate(serializer.DecodeLittleEndianValue(ram.inspectRange(vx, 2, &memoryAccessExceptionIndices)), 2)
		} else if instruction == 56 { // load_u32
			nextRegisters[ra] = Register(serializer.DecodeLittleEndianValue(ram.inspectRange(vx, 4, &memoryAccessExceptionIndices)))
		} else if instruction == 57 { // load_i32
			nextRegisters[ra] = signExtendImmediate(serializer.DecodeLittleEndianValue(ram.inspectRange(vx, 4, &memoryAccessExceptionIndices)), 4)
		} else if instruction == 58 { // load_u64
			nextRegisters[ra] = Register(serializer.DecodeLittleEndianValue(ram.inspectRange(vx, 8, &memoryAccessExceptionIndices)))
		} else if instruction == 59 { // store_u8
			nextRam.mutate(vx, uint8(registers[ra]), &memoryAccessExceptionIndices)
		} else if instruction == 60 { // store_u16
			serialized, err := serializer.Serialize(uint16(registers[ra]))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		} else if instruction == 61 { // store_u32
			serialized, err := serializer.Serialize(uint32(registers[ra]))
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		} else { // store_u64
			serialized, err := serializer.Serialize(registers[ra])
			if err != nil {
				return ExitReason{}, 0, 0, [13]Register{}, &RAM{}, err
			}
			nextRam.mutateRange(vx, serialized, &memoryAccessExceptionIndices)
		}
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

// UnsignedToSigned converts an unsigned integer x (assumed to be in [0, 2^(8*n)))
// into its two's complement signed representation as an int64.
// If x is less than 2^(8*n-1), it is interpreted as positive; otherwise, we subtract 2^(8*n).
func UnsignedToSigned(x uint64, octets int) int64 {
	totalBits := 8 * octets
	if totalBits > 64 {
		panic(fmt.Sprintf("Unsupported octet width: %d (max 8 allowed)", octets))
	}
	signBit := uint64(1) << uint(totalBits-1)
	modVal := uint64(1) << uint(totalBits)
	if x < signBit {
		return int64(x)
	}
	return int64(x) - int64(modVal)
}

// SignedToUnsigned converts a signed integer a (assumed to be in the range
// [-2^(8*n-1), 2^(8*n-1)-1]) into its unsigned representation in [0, 2^(8*n)).
// It does so by computing (2^(8*n) + a) mod 2^(8*n).
func SignedToUnsigned(a int64, octets int) uint64 {
	totalBits := 8 * octets
	if totalBits > 64 {
		panic(fmt.Sprintf("Unsupported octet width: %d (max 8 allowed)", octets))
	}
	modVal := uint64(1) << uint(totalBits)
	// Adding modVal ensures a non-negative result even if a is negative.
	return (modVal + uint64(a)) % modVal
}

// UintToBitsLE converts an unsigned integer x (with x in [0, 2^(8*n)))
// into a bit vector of length 8*n in little-endian order. That is, the bit at index 0
// is the least-significant bit of x.
func UintToBitsLE(x uint64, octets int) []bool {
	total := 8 * octets
	bits := make([]bool, total)
	for i := 0; i < total; i++ {
		bits[i] = ((x >> uint(i)) & 1) == 1
	}
	return bits
}

// BitsToUintLE converts a bit vector (in little-endian order) back into an unsigned integer.
// It assumes bits[0] is the least-significant bit.
func BitsToUintLE(bits []bool) uint64 {
	var x uint64 = 0
	for i, bit := range bits {
		if bit {
			x |= 1 << uint(i)
		}
	}
	return x
}

// UintToBitsBE converts an unsigned integer x (with x in [0, 2^(8*n)))
// into a bit vector of length 8*n in big-endian order. That is, the bit at index 0
// is the most-significant bit.
func UintToBitsBE(x uint64, octets int) []bool {
	total := 8 * octets
	bits := make([]bool, total)
	for i := 0; i < total; i++ {
		// Compute the bit at position (total-1-i) in x.
		bits[i] = ((x >> uint(total-1-i)) & 1) == 1
	}
	return bits
}

// BitsToUintBE converts a bit vector (in big-endian order) back into an unsigned integer.
// It assumes bits[0] is the most-significant bit.
func BitsToUintBE(bits []bool) uint64 {
	total := len(bits)
	var x uint64 = 0
	for i, bit := range bits {
		if bit {
			x |= 1 << uint(total-1-i)
		}
	}
	return x
}
