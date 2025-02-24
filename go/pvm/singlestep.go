package pvm

import (
	"fmt"
	"log"
	"math/bits"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/types"
)

type State struct {
	InstructionCounter Register
	Gas                types.SignedGasValue
	Registers          [13]Register
	RAM                *RAM
	ExitReason         ExitReason
}

type InstructionContext struct {
	State                      *State // Contains instruction counter, registers, RAM, gas, etc.
	Instructions               []byte // The instruction stream.
	Instruction                byte
	CurInstructionCounter      Register
	Opcodes                    bitsequence.BitSequence // The bitsequence of special opcodes.
	DynamicJumpTable           []Register              // Jump table for dynamic jumps.
	BasicBlockBeginningOpcodes bitsequence.BitSequence // Precomputed basic block beginning opcodes.
	SkipLength                 int                     // Computed skip length for the current instruction.
	MemAccessExceptionIndices  *[]RamIndex             // Pointer to a slice collecting memory access exceptions.
}

type InstructionHandler func(ctx *InstructionContext)

var dispatchTable map[byte]InstructionHandler

func SingleStep(state *State, instructions []byte, opcodes bitsequence.BitSequence, dynamicJumpTable []Register) {
	instruction := getInstruction(instructions, state.InstructionCounter)
	skipLength := skip(state.InstructionCounter, opcodes)

	curIC := state.InstructionCounter
	state.InstructionCounter += 1 + Register(skipLength)

	ctx := InstructionContext{
		State:                      state,
		Instructions:               instructions,
		Instruction:                instruction,
		CurInstructionCounter:      curIC,
		Opcodes:                    opcodes,
		DynamicJumpTable:           dynamicJumpTable,
		BasicBlockBeginningOpcodes: basicBlockBeginningOpcodes(instructions, opcodes),
		SkipLength:                 skipLength,
		MemAccessExceptionIndices:  &[]RamIndex{},
	}

	if instructionHandler, ok := dispatchTable[instruction]; ok && instructionHandler != nil {
		instructionHandler(&ctx)
	} else {
		panic(fmt.Errorf("unknown instruction: %d", instruction))
	}

	minRamIndex := minRamIndex(*ctx.MemAccessExceptionIndices)
	if minRamIndex != nil {
		if *minRamIndex < MinValidRamIndex {
			state.ExitReason = NewSimpleExitReason(ExitPanic)
		} else {
			state.ExitReason = NewComplexExitReason(ExitPageFault, Register(PageSize*(*minRamIndex/PageSize)))
		}
	}
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
	end := min(start+count, len(instructions))
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

func smod(a, b int64) int64 {
	if b == 0 {
		return a
	}
	absB := b
	if b < 0 {
		absB = -b
	}
	return a % absB
}

// floorProductDiv2Pow64Signed computes
//
//	⌊(a * b) / 2^64⌋
//
// for any int64 values a and b. This function correctly handles negative inputs.
// The algorithm is based on first computing the 128‐bit product using bits.Mul64
// (which treats its arguments as unsigned) and then applying corrections for the signs
// of a and b.
func floorProductDiv2Pow64Signed(a, b int64) int64 {
	// Compute the full 128-bit product of a and b using unsigned arithmetic.
	// Here we convert a and b to uint64 (their two's complement representations).
	hi, _ := bits.Mul64(uint64(a), uint64(b))
	// Start with the unsigned high word interpreted as int64.
	res := int64(hi)
	// If a is negative, subtract b from the result.
	if a < 0 {
		res -= b
	}
	// If b is negative, subtract a from the result.
	if b < 0 {
		res -= a
	}
	return res
}

// mulDiv2Pow64 computes floor((a * b) / 2^64) for an int64 a and a uint64 b.
// It uses bits.Mul64 for the unsigned 128-bit product and applies a correction
// when a is negative.
func mulDiv2Pow64(a int64, b uint64) int64 {
	// Multiply treating a as unsigned (its two's complement representation).
	hi, _ := bits.Mul64(uint64(a), b)
	res := int64(hi)
	// For negative a, adjust by subtracting b.
	if a < 0 {
		res -= int64(b)
	}
	return res
}
