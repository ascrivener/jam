package pvm

import (
	"log"
	"math/bits"

	"jam/pkg/constants"
	"jam/pkg/ram"
	"jam/pkg/types"
)

type State struct {
	Gas       types.SignedGasValue
	Registers [13]types.Register
	RAM       *ram.RAM
}

type InstructionHandler func(pvm *PVM, instruction ParsedInstruction) (ExitReason, types.Register)

type OperandExtractor func(instructions []byte, pc int, skipLength int) (ra, rb, rd int, vx, vy types.Register)

type InstructionInfo struct {
	ExtractOperands OperandExtractor
	Handler         InstructionHandler
}

var dispatchTable [256]*InstructionInfo

var terminationOpcodes [256]bool

func signExtendImmediate(n int, x uint64) types.Register {
	if n == 0 {
		return types.Register(x)
	}

	switch n {
	case 1:
		return types.Register(int8(x))
	case 2:
		return types.Register(int16(x))
	case 3:
		if x&0x800000 != 0 {
			return types.Register(x | 0xFFFFFFFFFF000000)
		}
		return types.Register(x)
	case 4:
		return types.Register(int32(x))
	case 8:
		return types.Register(int64(x))
	default:
		log.Fatalf("signExtendImmediate: invalid byte length %d (must be 0,1,2,3,4, or 8)", n)
	}
	return 0
}

func branch(pvm *PVM, skipLength int, b types.Register, C bool) (ExitReason, types.Register) {
	if !C {
		return ExitReasonGo, pvm.nextInstructionCounter(skipLength)
	}
	// Bounds check before casting to int
	if b >= types.Register(len(pvm.program)) {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	if !pvm.validBlockStarts.BitAt(int(b)) {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	return ExitReasonGo, b
}

func djump(pvm *PVM, a uint32) (ExitReason, types.Register) {

	if a == (1<<32)-(1<<16) { // ??
		return ExitReasonHalt, pvm.InstructionCounter
	}

	if a == 0 || a > uint32(len(pvm.DynamicJumpTable)*constants.DynamicAddressAlignmentFactor) || a%uint32(constants.DynamicAddressAlignmentFactor) != 0 {
		return ExitReasonPanic, pvm.InstructionCounter
	}

	index := (a / uint32(constants.DynamicAddressAlignmentFactor)) - 1
	target := pvm.DynamicJumpTable[index]

	// Bounds check before casting to int
	if target >= types.Register(len(pvm.program)) {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	// Check if target is a valid basic block start
	if !pvm.validBlockStarts.BitAt(int(target)) {
		return ExitReasonPanic, pvm.InstructionCounter
	}
	return ExitReasonGo, target
}

func smod[T int32 | int64](a, b T) T {
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
