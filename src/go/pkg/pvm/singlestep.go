package pvm

import (
	"log"
	"math/bits"
	"os"

	"jam/pkg/constants"
	"jam/pkg/ram"
	"jam/pkg/types"
)

type State struct {
	Gas       types.SignedGasValue
	Registers [13]types.Register
	RAM       *ram.RAM
}

type InstructionHandler func(pvm *PVM, instruction *ParsedInstruction) (ExitReason, types.Register)

type OperandExtractor func(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register)

type InstructionInfo struct {
	ExtractOperands OperandExtractor
	Handler         InstructionHandler
}

var dispatchTable [256]*InstructionInfo

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

func branch(pvm *PVM, skipLength int, b types.Register, C bool) (ExitReason, types.Register) {
	if !C {
		return ExitReasonGo, pvm.nextInstructionCounter(skipLength)
	}
	if int(b) >= len(pvm.InstructionSlice) {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	targetInstruction := pvm.InstructionSlice[b]
	if targetInstruction == nil || !targetInstruction.IsBeginningBasicBlock {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	return ExitReasonGo, b
}

func djump(a uint32, defaultNextInstructionCounter types.Register, dynamicJumpTable []types.Register, parsedInstructions []*ParsedInstruction) (ExitReason, types.Register) {
	if fileLogger != nil {
		fileLogger.Printf("djump: a=%d, defaultNextPC=%d, dynamicJumpTableLen=%d", a, defaultNextInstructionCounter, len(dynamicJumpTable))
	}

	if a == (1<<32)-(1<<16) { // ??
		if fileLogger != nil {
			fileLogger.Printf("djump: HALT condition (a == %d)", (1<<32)-(1<<16))
		}
		return ExitReasonHalt, defaultNextInstructionCounter
	}

	if a == 0 || a > uint32(len(dynamicJumpTable)*constants.DynamicAddressAlignmentFactor) || a%uint32(constants.DynamicAddressAlignmentFactor) != 0 {
		if fileLogger != nil {
			fileLogger.Printf("djump: Invalid jump address a=%d", a)
		}
		return ExitReasonPanic, defaultNextInstructionCounter
	}

	index := (a / uint32(constants.DynamicAddressAlignmentFactor)) - 1
	target := dynamicJumpTable[index]

	if fileLogger != nil {
		fileLogger.Printf("djump: index=%d, target=%d", index, target)
	}

	if int(target) >= len(parsedInstructions) {
		if fileLogger != nil {
			fileLogger.Printf("djump: Target %d is out of range", target)
		}
		return ExitReasonPanic, defaultNextInstructionCounter
	}

	targetInstruction := parsedInstructions[target]

	if targetInstruction == nil || !targetInstruction.IsBeginningBasicBlock {
		if fileLogger != nil {
			fileLogger.Printf("djump: Target %d is not a valid basic block start", target)
		}
		return ExitReasonPanic, defaultNextInstructionCounter
	}

	return ExitReasonGo, target
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
