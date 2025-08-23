package pvm

import (
	"fmt"
	"log"
	"math/bits"
	"os"

	"jam/pkg/bitsequence"
	"jam/pkg/constants"
	"jam/pkg/ram"
	"jam/pkg/types"
)

type State struct {
	Gas       types.SignedGasValue
	Registers [13]types.Register
	RAM       *ram.RAM
}

type InstructionContext struct {
	Instruction byte
	SkipLength  int // Computed skip length for the current instruction.
}

type InstructionHandler func(pvm *PVM, ctx *InstructionContext) (ExitReason, types.Register)

var dispatchTable [256]InstructionHandler

var terminationOpcodes [256]bool

var fileLogger *log.Logger

func InitFileLogger(filename string) error {
	// Open the file with TRUNC flag instead of APPEND to clear existing content
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	fileLogger = log.New(file, "", log.LstdFlags)
	return nil
}

func (pvm *PVM) SingleStep() ExitReason {
	// Reset the pre-allocated slice without allocating new memory.
	pvm.State.RAM.ClearMemoryAccessExceptions()

	ctx := InstructionContext{
		Instruction: getInstruction(pvm.Instructions, pvm.InstructionCounter),
		SkipLength:  skip(pvm.InstructionCounter, pvm.Opcodes),
	}

	var exitReason ExitReason
	var nextIC types.Register

	if 11826 == pvm.InstructionCounter {
		fmt.Println("hi")
	}

	handler := dispatchTable[ctx.Instruction]
	if handler == nil || !pvm.Opcodes.BitAt(int(pvm.InstructionCounter)) {
		handler = dispatchTable[0]
	}

	exitReason, nextIC = handler(pvm, &ctx)

	pvm.State.Gas -= types.SignedGasValue(1)

	pvm.InstructionCounter = nextIC

	if fileLogger != nil {
		fileLogger.Printf("instruction=%d pc=%d g=%d Registers=%v", ctx.Instruction, pvm.InstructionCounter, pvm.State.Gas, pvm.State.Registers)
	}

	minRamIndex := minRamIndex(pvm.State.RAM.GetMemoryAccessExceptions())
	if minRamIndex != nil {
		if *minRamIndex < ram.MinValidRamIndex {
			return NewSimpleExitReason(ExitPanic)
		} else {
			return NewComplexExitReason(ExitPageFault, types.Register(ram.PageSize*(*minRamIndex/ram.PageSize)))
		}
	}
	return exitReason
}

func getInstruction(instructions []byte, instructionCounter types.Register) byte {
	if instructionCounter >= types.Register(len(instructions)) {
		return 0
	}
	return instructions[instructionCounter]
}

func getInstructionRange(instructions []byte, instructionCounter types.Register, count int) []byte {
	start := int(instructionCounter)
	if start >= len(instructions) {
		return []byte{}
	}
	end := min(start+count, len(instructions))
	return instructions[start:end]
}

func skip(instructionCounter types.Register, opcodes bitsequence.BitSequence) int {
	j := 0
	for j < 24 {
		idx := instructionCounter + types.Register(1+j)
		if idx >= types.Register(opcodes.Len()) || opcodes.BitAt(int(idx)) {
			break
		}
		j++
	}
	return j
}

func signExtendImmediate(n int, x uint64) types.Register {
	// Special case for n=0: no sign extension needed
	if n == 0 {
		return types.Register(x)
	}

	// Check that n is one of the allowed sizes.
	switch n {
	case 1, 2, 3, 4, 8:
		// ok
	default:
		log.Fatalf("signExtendImmediate: invalid byte length %d (must be 0,1,2,3,4, or 8)", n)
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
	return types.Register(x + sign*offset)
}

func branch(pvm *PVM, ctx *InstructionContext, b types.Register, C bool) (ExitReason, types.Register) {
	if !C {
		return NewSimpleExitReason(ExitGo), pvm.nextInstructionCounter(ctx.SkipLength)
	}
	if _, exists := pvm.BasicBlockBeginningOpcodes[int(b)]; !exists {
		return NewSimpleExitReason(ExitPanic), pvm.InstructionCounter
	}
	return NewSimpleExitReason(ExitGo), b
}

func djump(a uint32, defaultNextInstructionCounter types.Register, dynamicJumpTable []types.Register, basicBlockBeginningOpcodes map[int]struct{}) (ExitReason, types.Register) {
	if fileLogger != nil {
		fileLogger.Printf("djump: a=%d, defaultNextPC=%d, dynamicJumpTableLen=%d", a, defaultNextInstructionCounter, len(dynamicJumpTable))
	}

	if a == (1<<32)-(1<<16) { // ??
		if fileLogger != nil {
			fileLogger.Printf("djump: HALT condition (a == %d)", (1<<32)-(1<<16))
		}
		return NewSimpleExitReason(ExitHalt), defaultNextInstructionCounter
	}

	if a == 0 || a > uint32(len(dynamicJumpTable)*constants.DynamicAddressAlignmentFactor) || a%uint32(constants.DynamicAddressAlignmentFactor) != 0 {
		if fileLogger != nil {
			fileLogger.Printf("djump: PANIC condition (a=%d, maxAddr=%d, alignment=%d)",
				a, uint32(len(dynamicJumpTable)*constants.DynamicAddressAlignmentFactor), constants.DynamicAddressAlignmentFactor)
		}
		return NewSimpleExitReason(ExitPanic), defaultNextInstructionCounter
	}

	nextInstructionCounter := dynamicJumpTable[a/uint32(constants.DynamicAddressAlignmentFactor)-1]
	if fileLogger != nil {
		fileLogger.Printf("djump: calculated nextPC=%d from dynamicJumpTable[%d]",
			nextInstructionCounter, a/uint32(constants.DynamicAddressAlignmentFactor)-1)
	}

	_, exists := basicBlockBeginningOpcodes[int(nextInstructionCounter)]
	if !exists {
		if fileLogger != nil {
			fileLogger.Printf("djump: PANIC - nextPC=%d not in basicBlockBeginningOpcodes", nextInstructionCounter)
		}
		return NewSimpleExitReason(ExitPanic), defaultNextInstructionCounter
	}

	if fileLogger != nil {
		fileLogger.Printf("djump: SUCCESS - jumping to nextPC=%d", nextInstructionCounter)
	}
	return NewSimpleExitReason(ExitGo), nextInstructionCounter
}

func minRamIndex(ramIndices []ram.RamIndex) *ram.RamIndex {
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
