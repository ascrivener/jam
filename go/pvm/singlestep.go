package pvm

import (
	"fmt"
	"log"
	"math/bits"
	"slices"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
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

	switch instruction {
	case 70:
	case 71:
	case 72:
	case 73:
		ra := min(12, getInstruction(instructions, instructionCounter+1)%16)
		lx := min(4, int(getInstruction(instructions, instructionCounter+1)/16)%8)
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		ly := min(4, max(0, skipLength-lx-1))
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
		ra := min(12, int(getInstruction(instructions, instructionCounter+1)%16))
		lx := min(4, int(getInstruction(instructions, instructionCounter+1)/16)%8)
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx)))
		ly := min(4, max(0, skipLength-lx-1))
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
		rd := min(12, int(getInstruction(instructions, instructionCounter+1)%16))
		ra := min(12, int(getInstruction(instructions, instructionCounter+1)/16))
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
		ra := min(12, int(getInstruction(instructions, instructionCounter+1))%16)
		rb := min(12, int(getInstruction(instructions, instructionCounter+1)/16))
		lx := min(4, max(0, skipLength-1))
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
			nextRegisters[ra] = signExtendImmediate(4, uint64(vx-registers[rb])) // TODO: change in GP
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
			nextRegisters[ra] = vx - registers[rb] // TODO: change in GP
		case 155: // shlo_l_imm_alt_64
			nextRegisters[ra] = vx * (1 << (registers[rb] % 64))
		case 156: // shlo_r_imm_alt_64
			nextRegisters[ra] = vx / (1 << (registers[rb] % 64))
		case 157: // shar_r_imm_alt_64
			nextRegisters[ra] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(8, uint64(vx))/(1<<(registers[rb]%64))))
		case 158: // rot_r_64_imm TODO: these are left shifts but the name suggests right shifts, change in GP
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[rb])).Rotate(int(vx))))
		case 159: // rot_r_64_imm_alt
			nextRegisters[ra] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(vx)).Rotate(int(registers[rb]))))
		case 160: // rot_r_32_imm
			nextRegisters[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(registers[rb])).Rotate(int(vx))))
		case 161: // rot_r_32_imm_alt
			nextRegisters[ra] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(vx)).Rotate(int(registers[rb]))))
		}
	case 170:
	case 171:
	case 172:
	case 173:
	case 174:
	case 175:
		ra := min(12, int(getInstruction(instructions, instructionCounter+1)%16))
		rb := min(12, int(getInstruction(instructions, instructionCounter+1)/16))
		lx := min(4, max(0, skipLength-1))
		vx := instructionCounter + Register(serializer.UnsignedToSigned(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+2, lx))))
		switch instruction {
		case 170: // branch_eq
			exitReason, nextInstructionCounter = branch(vx, registers[ra] == registers[rb], instructionCounter, basicBlockBeginningOpcodes)
		case 171: // branch_ne
			exitReason, nextInstructionCounter = branch(vx, registers[ra] != registers[rb], instructionCounter, basicBlockBeginningOpcodes)
		case 172: // branch_lt_u
			exitReason, nextInstructionCounter = branch(vx, registers[ra] < registers[rb], instructionCounter, basicBlockBeginningOpcodes)
		case 173: // branch_lt_s
			exitReason, nextInstructionCounter = branch(vx, serializer.UnsignedToSigned(8, uint64(registers[ra])) == serializer.UnsignedToSigned(8, uint64(registers[rb])), instructionCounter, basicBlockBeginningOpcodes)
		case 174: // branch_ge_u
			exitReason, nextInstructionCounter = branch(vx, registers[ra] >= registers[rb], instructionCounter, basicBlockBeginningOpcodes)
		case 175: // branch_ge_s
			exitReason, nextInstructionCounter = branch(vx, serializer.UnsignedToSigned(8, uint64(registers[ra])) >= serializer.UnsignedToSigned(8, uint64(registers[rb])), instructionCounter, basicBlockBeginningOpcodes)
		}
	case 180: // load_imm_jump_ind
		ra := min(12, int(getInstruction(instructions, instructionCounter+1)%16))
		rb := min(12, int(getInstruction(instructions, instructionCounter+1)/16))
		lx := min(4, int(getInstruction(instructions, instructionCounter+2)%8))
		ly := min(4, max(0, skipLength-lx-2))
		vx := signExtendImmediate(lx, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+3, lx)))
		vy := signExtendImmediate(ly, serializer.DecodeLittleEndian(getInstructionRange(instructions, instructionCounter+3+Register(lx), ly)))
		exitReason, nextInstructionCounter = djump(uint32(registers[rb]+vy), instructionCounter, dynamicJumpTable, basicBlockBeginningOpcodes)
		nextRegisters[ra] = vx
	case 190:
	case 191:
	case 192:
	case 193:
	case 194:
	case 195:
	case 196:
	case 197:
	case 198:
	case 199:
	case 200:
	case 201:
	case 202:
	case 203:
	case 204:
	case 205:
	case 206:
	case 207:
	case 208:
	case 209:
	case 210:
	case 211:
	case 212:
	case 213:
	case 214:
	case 215:
	case 216:
	case 217:
	case 218:
	case 219:
	case 220:
	case 221:
	case 222:
	case 223:
	case 224:
	case 225:
	case 226:
	case 227:
	case 228:
	case 229:
	case 230:
		ra := min(12, int(getInstruction(instructions, instructionCounter+1)%16))
		rb := min(12, int(getInstruction(instructions, instructionCounter+1)/16))
		rd := min(12, int(getInstruction(instructions, instructionCounter+2)))
		switch instruction {
		case 190: // add_32
			nextRegisters[rd] = signExtendImmediate(4, uint64(registers[ra]+registers[rb]))
		case 191: // sub_32
			nextRegisters[rd] = signExtendImmediate(4, uint64(registers[ra]-registers[rb]))
		case 192: // mul_32
			nextRegisters[rd] = signExtendImmediate(4, uint64(registers[ra]*registers[rb]))
		case 193: // div_u_32
			if uint32(registers[rb]) == 0 {
				nextRegisters[rd] = (1 << 64) - 1
			} else {
				nextRegisters[rd] = signExtendImmediate(4, uint64(uint32(registers[ra])/uint32(registers[rb])))
			}
		case 194: // div_s_32
			a := serializer.UnsignedToSigned(4, uint64(uint32(registers[ra])))
			b := serializer.UnsignedToSigned(4, uint64(uint32(registers[rb])))
			if b == 0 {
				nextRegisters[rd] = (1 << 64) - 1
			} else if a == -(1<<31) && b == -1 {
				nextRegisters[rd] = Register(a)
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, a/b))
			}
		case 195: // rem_u_32
			if uint32(registers[rb]) == 0 {
				nextRegisters[rd] = signExtendImmediate(4, uint64(uint32(registers[ra])))
			} else {
				nextRegisters[rd] = signExtendImmediate(4, uint64(uint32(registers[ra])%uint32(registers[rb])))
			}
		case 196: // rem_s_32
			a := serializer.UnsignedToSigned(4, uint64(uint32(registers[ra])))
			b := serializer.UnsignedToSigned(4, uint64(uint32(registers[rb])))
			if a == -(1<<31) && b == -1 {
				nextRegisters[rd] = 0
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, smod(a, b)))
			}
		case 197: // shlo_l_32
			nextRegisters[rd] = signExtendImmediate(4, uint64(uint32(registers[ra]*(1<<(registers[rb]%32)))))
		case 198: // shlo_r_32
			nextRegisters[rd] = signExtendImmediate(4, uint64(uint32(registers[ra])/(1<<(registers[rb]%32))))
		case 199: // shar_r_32
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(4, uint64(uint32(registers[ra])))/(1<<(registers[rb]%32))))
		case 200: // add_64
			nextRegisters[rd] = registers[ra] + registers[rb]
		case 201: // sub_64
			nextRegisters[rd] = registers[ra] - registers[rb] // TODO: change in GP
		case 202: // mul_64
			nextRegisters[rd] = registers[ra] * registers[rb]
		case 203: // div_u_64
			if registers[rb] == 0 {
				nextRegisters[rd] = (1 << 64) - 1
			} else {
				nextRegisters[rd] = registers[ra] / registers[rb]
			}
		case 204: // div_s_64
			if registers[rb] == 0 {
				nextRegisters[rd] = (1 << 64) - 1
			} else if serializer.UnsignedToSigned(8, uint64(registers[ra])) == -(1<<63) && serializer.UnsignedToSigned(8, uint64(registers[rb])) == -1 {
				nextRegisters[rd] = registers[ra]
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(8, uint64(registers[ra]))/serializer.UnsignedToSigned(8, uint64(registers[rb]))))
			}
		case 205: // rem_u_64
			if registers[rb] == 0 {
				nextRegisters[rd] = registers[ra]
			} else {
				nextRegisters[rd] = registers[ra] % registers[rb]
			}
		case 206: // rem_s_64
			if serializer.UnsignedToSigned(8, uint64(registers[ra])) == -(1<<63) && serializer.UnsignedToSigned(8, uint64(registers[rb])) == -1 {
				nextRegisters[rd] = 0
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, smod(serializer.UnsignedToSigned(8, uint64(registers[ra])), serializer.UnsignedToSigned(8, uint64(registers[rb])))))
			}
		case 207: // shlo_l_64
			nextRegisters[rd] = registers[ra] * (1 << (registers[rb] % 64))
		case 208: // shlo_r_64
			nextRegisters[rd] = registers[ra] / (1 << (registers[rb] % 64))
		case 209: // shar_r_64
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, serializer.UnsignedToSigned(8, uint64(registers[ra]))/(1<<(registers[rb]%64))))
		case 210: // and
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).And(serializer.UintToBitSequenceLE(8, uint64(registers[rb])))))
		case 211: // xor
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).Xor(serializer.UintToBitSequenceLE(8, uint64(registers[rb])))))
		case 212: // or
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).Or(serializer.UintToBitSequenceLE(8, uint64(registers[rb])))))
		case 213: // mul_upper_s_s
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, floorProductDiv2Pow64Signed(serializer.UnsignedToSigned(8, uint64(registers[ra])), serializer.UnsignedToSigned(8, uint64(registers[rb])))))
		case 214: // mul_upper_u_u
			hi, _ := bits.Mul64(uint64(registers[ra]), uint64(registers[rb]))
			nextRegisters[rd] = Register(hi)
		case 215: // mul_upper_s_u
			nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, mulDiv2Pow64(serializer.UnsignedToSigned(8, uint64(registers[ra])), uint64(registers[rb]))))
		case 216: // set_lt_u
			if registers[ra] < registers[rb] {
				nextRegisters[rd] = 1
			} else {
				nextRegisters[rd] = 0
			}
		case 217: // set_lt_s
			if serializer.UnsignedToSigned(8, uint64(registers[ra])) < serializer.UnsignedToSigned(8, uint64(registers[rb])) {
				nextRegisters[rd] = 1
			} else {
				nextRegisters[rd] = 0
			}
		case 218: // cmov_iz
			if registers[rb] == 0 {
				nextRegisters[rd] = registers[ra]
			} else {
				nextRegisters[rd] = registers[rd]
			}
		case 219: // cmov_nz
			if registers[rb] != 0 {
				nextRegisters[rd] = registers[ra]
			} else {
				nextRegisters[rd] = registers[rd]
			}
		case 220: // rot_l_64 TODO: these are wrong in the GP I think, fix in the GP.
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).Rotate(-int(registers[rb]))))
		case 221: // rot_l_32
			nextRegisters[rd] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(registers[ra])).Rotate(-int(registers[rb]))))
		case 222: // rot_r_64
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(8, uint64(registers[ra])).Rotate(int(registers[rb]))))
		case 223: // rot_r_32
			nextRegisters[rd] = signExtendImmediate(4, serializer.BitSequenceToUintLE(serializer.UintToBitSequenceLE(4, uint64(registers[ra])).Rotate(int(registers[rb]))))
		case 224: // and_inv
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceBE(8, uint64(registers[ra])).And(serializer.UintToBitSequenceBE(8, uint64(registers[rb])).Invert())))
		case 225: // or_inv
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceBE(8, uint64(registers[ra])).Or(serializer.UintToBitSequenceBE(8, uint64(registers[rb])).Invert())))
		case 226: // xnor
			nextRegisters[rd] = Register(serializer.BitSequenceToUintLE(serializer.UintToBitSequenceBE(8, uint64(registers[ra])).Xor(serializer.UintToBitSequenceBE(8, uint64(registers[rb]))).Invert()))
		case 227: // max TODO: needs signed to unsigned before setting next register? fix in GP
			l := serializer.UnsignedToSigned(8, uint64(registers[ra]))
			r := serializer.UnsignedToSigned(8, uint64(registers[rb]))
			if l > r {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, l))
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, r))
			}
		case 228: // max_u
			nextRegisters[rd] = max(registers[ra], registers[rb])
		case 229: // min TODO: needs signed to unsigned before setting next register? fix in GP
			l := serializer.UnsignedToSigned(8, uint64(registers[ra]))
			r := serializer.UnsignedToSigned(8, uint64(registers[rb]))
			if l < r {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, l))
			} else {
				nextRegisters[rd] = Register(serializer.SignedToUnsigned(8, r))
			}
		case 230: // min_u
			nextRegisters[rd] = min(registers[ra], registers[rb])
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

	return exitReason, nextInstructionCounter, nextGas, nextRegisters, nextRam
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
