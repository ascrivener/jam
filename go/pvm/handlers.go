package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/serializer"
)

func handleTrap(ctx *InstructionContext) {
	ctx.State.ExitReason = NewSimpleExitReason(ExitPanic)
}

func handleFallthrough(ctx *InstructionContext) {
}

func handleEcalli(ctx *InstructionContext) {
	lx := min(4, ctx.SkipLength)
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+1, lx)))
	ctx.State.ExitReason = NewComplexExitReason(ExitHostCall, vx)
}

func handleLoadImm64(ctx *InstructionContext) {
	ra := min(12, int(getInstruction(ctx.Instructions, ctx.CurInstructionCounter+Register(1))%16))
	vx := serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+2, 8))
	ctx.State.Registers[ra] = Register(vx)
}

func handleTwoImmValues(ctx *InstructionContext) {
	// Precompute the common immediate values.
	lx := min(4, int(getInstruction(ctx.Instructions, ctx.CurInstructionCounter+1)%8))
	ly := min(4, max(0, ctx.SkipLength-lx-1))
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+2, lx)))
	vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+2+Register(lx), ly)))

	// Use the opcode from the context (assuming it's been set)
	switch ctx.Instruction {
	case 30: // store_imm_u8
		ctx.State.RAM.mutate(vx, byte(vy), ctx.MemAccessExceptionIndices)
	case 31: // store_imm_u16
		serialized := serializer.EncodeLittleEndian(2, uint64(vy))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	case 32: // store_imm_u32
		serialized := serializer.EncodeLittleEndian(4, uint64(vy))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	case 33: // store_imm_u64
		serialized := serializer.EncodeLittleEndian(8, uint64(vy))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	default:
		panic(fmt.Sprintf("handleStoreImmGroup: unexpected opcode %d", ctx.Instruction))
	}
}

func handleJump(ctx *InstructionContext) {
	lx := min(4, ctx.SkipLength)
	vx := ctx.CurInstructionCounter + Register(serializer.UnsignedToSigned(lx, serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+1, lx))))
	ctx.State.ExitReason, ctx.State.InstructionCounter = branch(vx, true, ctx.CurInstructionCounter, ctx.BasicBlockBeginningOpcodes)
}

func handleOneRegOneImm(ctx *InstructionContext) {
	// Compute the register operand from the next byte (mod 16, capped to 12).
	ra := min(12, int(getInstruction(ctx.Instructions, ctx.CurInstructionCounter+1)%16))
	// Compute how many bytes remain for the immediate (skipLength-1).
	lx := min(4, max(0, ctx.SkipLength-1))
	// Decode the immediate value (and sign-extend it).
	vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(ctx.Instructions, ctx.CurInstructionCounter+2, lx)))

	switch ctx.Instruction {
	case 50: // jump_ind
		// Jump to the target address computed from (register[ra] + vx)
		targetAddr := uint32(ctx.State.Registers[ra] + vx)
		exitReason, nextIC := djump(targetAddr, ctx.CurInstructionCounter, ctx.DynamicJumpTable, ctx.BasicBlockBeginningOpcodes)
		ctx.State.ExitReason = exitReason
		ctx.State.InstructionCounter = nextIC
	case 51: // load_imm
		ctx.State.Registers[ra] = vx
	case 52: // load_u8
		ctx.State.Registers[ra] = Register(ctx.State.RAM.inspect(vx, ctx.MemAccessExceptionIndices))
	case 53: // load_i8
		val := ctx.State.RAM.inspect(vx, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = signExtendImmediate(1, uint64(val))
	case 54: // load_u16
		data := ctx.State.RAM.inspectRange(vx, 2, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = Register(serializer.DecodeLittleEndian(data))
	case 55: // load_i16
		data := ctx.State.RAM.inspectRange(vx, 2, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = signExtendImmediate(2, serializer.DecodeLittleEndian(data))
	case 56: // load_u32
		data := ctx.State.RAM.inspectRange(vx, 4, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = Register(serializer.DecodeLittleEndian(data))
	case 57: // load_i32
		data := ctx.State.RAM.inspectRange(vx, 4, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = signExtendImmediate(4, serializer.DecodeLittleEndian(data))
	case 58: // load_u64
		data := ctx.State.RAM.inspectRange(vx, 8, ctx.MemAccessExceptionIndices)
		ctx.State.Registers[ra] = Register(serializer.DecodeLittleEndian(data))
	case 59: // store_u8
		ctx.State.RAM.mutate(vx, uint8(ctx.State.Registers[ra]), ctx.MemAccessExceptionIndices)
	case 60: // store_u16
		serialized := serializer.EncodeLittleEndian(2, uint64(ctx.State.Registers[ra]))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	case 61: // store_u32
		serialized := serializer.EncodeLittleEndian(4, uint64(ctx.State.Registers[ra]))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	case 62: // store_u64
		serialized := serializer.EncodeLittleEndian(8, uint64(ctx.State.Registers[ra]))
		ctx.State.RAM.mutateRange(vx, serialized, ctx.MemAccessExceptionIndices)
	default:
		panic(fmt.Sprintf("handleOneRegOneImm: unexpected opcode %d", ctx.Instruction))
	}
}
