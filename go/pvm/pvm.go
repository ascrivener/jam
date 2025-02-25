package pvm

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

func Ψ(programBlob []byte, instructionCounter Register, gas types.GasValue, registers [13]Register, ram *RAM) *State {
	instructions, opcodes, dynamicJumpTable, ok := deblob(programBlob)
	if !ok {
		return &State{
			InstructionCounter: instructionCounter,
			Gas:                types.SignedGasValue(gas),
			Registers:          registers,
			RAM:                ram,
			ExitReason:         NewSimpleExitReason(ExitPanic),
		}
	}
	// initialState
	state := &State{
		InstructionCounter: instructionCounter,
		Gas:                types.SignedGasValue(gas),
		Registers:          registers,
		RAM:                ram,
		ExitReason:         NewSimpleExitReason(ExitGo),
	}
	basicBlockBeginningOpcodes := basicBlockBeginningOpcodes(instructions, opcodes)
	singleStepContext := &SingleStepContext{
		State:                      state,
		Instructions:               instructions,
		Opcodes:                    opcodes,
		DynamicJumpTable:           dynamicJumpTable,
		BasicBlockBeginningOpcodes: basicBlockBeginningOpcodes,
		MemAccessExceptions:        make([]RamIndex, 0, 16),
	}
	for {
		SingleStep(singleStepContext)
		exitReason := singleStepContext.State.ExitReason
		if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitGo {
			// Continue executing if the exit reason is still "go".
			continue
		}
		// Otherwise, adjust for out-of-gas or panic/halt conditions.
		if singleStepContext.State.Gas < 0 {
			singleStepContext.State.ExitReason = NewSimpleExitReason(ExitOutOfGas)
		} else if exitReason.IsSimple() &&
			(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
			// Reset the instruction counter on panic/halt.
			singleStepContext.State.InstructionCounter = 0
		}
		return singleStepContext.State
	}
}

// deblob attempts to decompose p into three parts: c, k, and j.
// It returns ok==false if p does not follow the expected structure.
func deblob(p []byte) (c []byte, k bitsequence.BitSequence, j []Register, ok bool) {
	offset := 0

	// 1. Decode E(|j|): the encoded number of elements in j.
	L_j, n, ok := serializer.DecodeLength(p[offset:])
	if !ok {
		return nil, k, nil, false
	}
	offset += n

	// 2. Decode E1(z): a one-byte value indicating bytes per element in j.
	if offset >= len(p) {
		return nil, k, nil, false
	}
	z := p[offset]
	offset++

	// 3. Decode E(|c|): the encoded length of c (and hence k's underlying byte slice).
	L_c, n, ok := serializer.DecodeLength(p[offset:])
	if !ok {
		return nil, k, nil, false
	}
	offset += n

	// 4. Decode Ez(j): j is an array of L_j elements, each encoded in z bytes.
	totalJBytes := int(L_j) * int(z)
	if offset+totalJBytes > len(p) {
		return nil, k, nil, false
	}
	jArr := make([]Register, 0, L_j)
	for range int(L_j) {
		elem := serializer.DecodeLittleEndian(p[offset : offset+int(z)])
		jArr = append(jArr, Register(elem))
		offset += int(z)
	}

	// 5. The next L_c bytes are c.
	// 6. The following L_c/8 bytes are for k, so that number of bits in k = L_c
	if offset+int(L_c)+int(L_c)/8 != len(p) {
		return nil, k, nil, false
	}
	c = p[offset : offset+int(L_c)]
	kBuf := p[offset+int(L_c) : offset+int(L_c)+int(L_c)/8]

	// Construct k from kBuf
	k = *bitsequence.FromBytes(kBuf)

	return c, k, jArr, true
}

func basicBlockBeginningOpcodes(instructions []byte, opcodes bitsequence.BitSequence) bitsequence.BitSequence {
	basicBlockBeginningOpcodes := bitsequence.New()
	bits := make([]bool, len(instructions))
	basicBlockBeginningOpcodes.AppendBits(bits)
	basicBlockBeginningOpcodes.SetBitAt(0, true)
	for n, instruction := range instructions {
		if opcodes.BitAt(n) && terminationOpcodes[instruction] {
			basicBlockBeginningOpcodes.SetBitAt(n+1+skip(Register(n), opcodes), true)
		}
	}
	return *basicBlockBeginningOpcodes
}
