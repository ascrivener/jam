package pvm

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

type PVM struct {
	ProgramBlob []byte
	State       *State
}

func InitializePVM(programCodeFormat []byte, arguments Arguments, instructionCounter Register, gas types.SignedGasValue) *PVM {
	programBlob, registers, ram, ok := decodeProgramCodeFormat(programCodeFormat, arguments)
	if !ok {
		return nil
	}
	return &PVM{
		ProgramBlob: programBlob,
		State: &State{
			InstructionCounter: instructionCounter,
			Gas:                gas,
			Registers:          registers,
			RAM:                ram,
		},
	}
}

func decodeProgramCodeFormat(p []byte, arguments Arguments) (c []byte, r [13]Register, ram *RAM, ok bool) {
	offset := 0

	// 1. Decode E3(|o|): the encoded number of elements in o.
	if offset+3 > len(p) {
		return nil, r, nil, false
	}
	L_o := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 2. Decode E3(|w|): the encoded number of elements in w.
	if offset+3 > len(p) {
		return nil, r, nil, false
	}
	L_w := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 3. Decode E2(z): the encoded z
	if offset+2 > len(p) {
		return nil, r, nil, false
	}
	z := int(serializer.DecodeLittleEndian(p[offset : offset+2]))
	offset += 2

	// 4. Decode E3(s): encoded s
	if offset+3 > len(p) {
		return nil, r, nil, false
	}
	s := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 5. Decode o and w
	if offset+L_o > len(p) {
		return nil, r, nil, false
	}
	o := p[offset : offset+L_o]
	offset += L_o
	if offset+L_w > len(p) {
		return nil, r, nil, false
	}
	w := p[offset : offset+L_w]
	offset += int(L_w)

	// 6. Decode E4(|c|)
	if offset+4 > len(p) {
		return nil, r, nil, false
	}
	L_c := serializer.DecodeLittleEndian(p[offset : offset+4])
	offset += 4
	if offset+int(L_c) != len(p) {
		return nil, r, nil, false
	}
	c = p[offset : offset+int(L_c)]

	if 5*MajorZoneSize+TotalSizeNeededMajorZones(L_o)+TotalSizeNeededMajorZones(L_w+z*PageSize)+TotalSizeNeededMajorZones(int(s))+ArgumentsZoneSize > (1 << 32) {
		return nil, r, nil, false
	}

	r[0] = (1 << 32) - (1 << 16)
	r[1] = (1 << 32) - 2*MajorZoneSize - ArgumentsZoneSize
	r[7] = (1 << 32) - MajorZoneSize - ArgumentsZoneSize
	r[8] = Register(len(arguments))

	return c, r, NewRAM(o, w, arguments, z, s), true
}

func (pvm *PVM) Ψ() (*State, ExitReason) {
	instructions, opcodes, dynamicJumpTable, ok := deblob(pvm.ProgramBlob)
	if !ok {
		return pvm.State, NewSimpleExitReason(ExitPanic)
	}
	singleStepContext := &SingleStepContext{
		State:                      pvm.State,
		ExitReason:                 NewSimpleExitReason(ExitGo),
		Instructions:               instructions,
		Opcodes:                    opcodes,
		DynamicJumpTable:           dynamicJumpTable,
		BasicBlockBeginningOpcodes: basicBlockBeginningOpcodes(instructions, opcodes),
		MemAccessExceptions:        make([]RamIndex, 0, 16),
	}
	for {
		SingleStep(singleStepContext)
		exitReason := singleStepContext.ExitReason
		if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitGo {
			// Continue executing if the exit reason is still "go".
			continue
		}
		// Otherwise, adjust for out-of-gas or panic/halt conditions.
		if singleStepContext.State.Gas < 0 {
			singleStepContext.ExitReason = NewSimpleExitReason(ExitOutOfGas)
		} else if exitReason.IsSimple() &&
			(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
			// Reset the instruction counter on panic/halt.
			singleStepContext.State.InstructionCounter = 0
		}
		return singleStepContext.State, singleStepContext.ExitReason
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
