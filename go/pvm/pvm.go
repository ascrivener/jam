package pvm

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

type PVM[X any] struct {
	Instructions     []byte
	Opcodes          bitsequence.BitSequence
	dynamicJumpTable []Register
	State            *State
}

func NewPVM[X any](programBlob []byte, registers [13]Register, ram *ram.RAM, instructionCounter Register, gas types.GasValue) *PVM[X] {
	instructions, opcodes, dynamicJumpTable, ok := Deblob(programBlob)
	if !ok {
		return nil
	}
	return &PVM[X]{
		Instructions:     instructions,
		Opcodes:          opcodes,
		dynamicJumpTable: dynamicJumpTable,
		State: &State{
			InstructionCounter: instructionCounter,
			Gas:                types.SignedGasValue(gas),
			Registers:          registers,
			RAM:                ram,
		},
	}
}

func InitializePVM[X any](programCodeFormat []byte, arguments Arguments, instructionCounter Register, gas types.GasValue) *PVM[X] {
	programBlob, registers, ram, ok := decodeProgramCodeFormat(programCodeFormat, arguments)
	if !ok {
		return nil
	}
	return NewPVM[X](programBlob, registers, ram, instructionCounter, gas)
}

func decodeProgramCodeFormat(p []byte, arguments Arguments) (c []byte, regs [13]Register, r *ram.RAM, ok bool) {
	offset := 0

	// 1. Decode E3(|o|): the encoded number of elements in o.
	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	L_o := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 2. Decode E3(|w|): the encoded number of elements in w.
	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	L_w := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 3. Decode E2(z): the encoded z
	if offset+2 > len(p) {
		return nil, regs, nil, false
	}
	z := int(serializer.DecodeLittleEndian(p[offset : offset+2]))
	offset += 2

	// 4. Decode E3(s): encoded s
	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	s := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	// 5. Decode o and w
	if offset+L_o > len(p) {
		return nil, regs, nil, false
	}
	o := p[offset : offset+L_o]
	offset += L_o
	if offset+L_w > len(p) {
		return nil, regs, nil, false
	}
	w := p[offset : offset+L_w]
	offset += int(L_w)

	// 6. Decode E4(|c|)
	if offset+4 > len(p) {
		return nil, regs, nil, false
	}
	L_c := serializer.DecodeLittleEndian(p[offset : offset+4])
	offset += 4
	if offset+int(L_c) != len(p) {
		return nil, regs, nil, false
	}
	c = p[offset : offset+int(L_c)]

	if 5*ram.MajorZoneSize+ram.TotalSizeNeededMajorZones(L_o)+ram.TotalSizeNeededMajorZones(L_w+z*ram.PageSize)+ram.TotalSizeNeededMajorZones(int(s))+ram.ArgumentsZoneSize > ram.RamSize {
		return nil, regs, nil, false
	}

	regs[0] = ram.RamSize - ram.MajorZoneSize
	regs[1] = ram.RamSize - 2*ram.MajorZoneSize - ram.ArgumentsZoneSize
	regs[7] = ram.RamSize - ram.MajorZoneSize - ram.ArgumentsZoneSize
	regs[8] = Register(len(arguments))

	return c, regs, ram.NewRAM(o, w, arguments, z, s), true
}

// deblob attempts to decompose p into three parts: c, k, and j.
// It returns ok==false if p does not follow the expected structure.
func Deblob(p []byte) (c []byte, k bitsequence.BitSequence, j []Register, ok bool) {
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

func (pvm *PVM[X]) Ψ() ExitReason {
	singleStepContext := &SingleStepContext{
		State:                      pvm.State,
		ExitReason:                 NewSimpleExitReason(ExitGo),
		Instructions:               pvm.Instructions,
		Opcodes:                    pvm.Opcodes,
		DynamicJumpTable:           pvm.dynamicJumpTable,
		BasicBlockBeginningOpcodes: pvm.BasicBlockBeginningOpcodes(),
		MemAccessExceptions:        make([]ram.RamIndex, 0, 16),
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
		return singleStepContext.ExitReason
	}
}

func (pvm *PVM[X]) BasicBlockBeginningOpcodes() bitsequence.BitSequence {
	basicBlockBeginningOpcodes := bitsequence.New()
	bits := make([]bool, len(pvm.Instructions))
	basicBlockBeginningOpcodes.AppendBits(bits)
	basicBlockBeginningOpcodes.SetBitAt(0, true)
	for n, instruction := range pvm.Instructions {
		if pvm.Opcodes.BitAt(n) && terminationOpcodes[instruction] {
			basicBlockBeginningOpcodes.SetBitAt(n+1+skip(Register(n), pvm.Opcodes), true)
		}
	}
	return *basicBlockBeginningOpcodes
}

func (pvm *PVM[X]) ΨH(f HostFunction[X], x X) (ExitReason, X) {
	for {
		exitReason := pvm.Ψ()
		if exitReason.IsSimple() || exitReason.ComplexExitReason.Type != ExitHostCall {
			pvm.State.RAM.ClearRollbackLog()
			return exitReason, x
		}

		hostCall := exitReason.ComplexExitReason.Parameter
		stateBeforeHostCall := *pvm.State
		postHostCallExitReason, postHostCallX := f(HostFunctionIdentifier(hostCall), pvm.State, x)

		if postHostCallExitReason.IsComplex() && postHostCallExitReason.ComplexExitReason.Type == ExitPageFault {
			pvm.State.RAM.Rollback() // rollback changes
			// Reset pvm.State to the snapshot from before the host call.
			// Taking the address of stateBeforeHostCall will cause it to escape to the heap.
			pvm.State = &stateBeforeHostCall
			return postHostCallExitReason, x
		}

		pvm.State.RAM.ClearRollbackLog()

		if *postHostCallExitReason.SimpleExitReason == ExitGo {
			pvm.State.InstructionCounter = stateBeforeHostCall.InstructionCounter + Register(1+skip(stateBeforeHostCall.InstructionCounter, pvm.Opcodes))
			x = postHostCallX // Update `x` with new value and continue
			continue
		}

		return postHostCallExitReason, postHostCallX
	}
}

func ΨM[X any](programCodeFormat []byte, instructionCounter Register, gas types.GasValue, arguments Arguments, f HostFunction[X], x X) (types.SignedGasValue, ExecutionExitReason, X) {
	pvm := InitializePVM[X](programCodeFormat, arguments, instructionCounter, gas)
	if pvm == nil {
		return types.SignedGasValue(gas), NewExecutionExitReasonError(ExecutionErrorPanic), x
	}
	postHostCallExitReason, postHostCallX := pvm.ΨH(f, x)
	if postHostCallExitReason.IsSimple() {
		if *postHostCallExitReason.SimpleExitReason == ExitOutOfGas {
			return pvm.State.Gas, NewExecutionExitReasonError(ExecutionErrorOutOfGas), postHostCallX
		}
		if *postHostCallExitReason.SimpleExitReason == ExitHalt {
			start := pvm.State.Registers[7]
			end := start + pvm.State.Registers[8]
			if !pvm.State.RAM.RangeHas(ram.Inaccessible, uint64(start), uint64(end)) {
				blob := pvm.State.RAM.GetValueSlice(uint64(start), uint64(end))
				return pvm.State.Gas, NewExecutionExitReasonBlob(blob), postHostCallX
			} else {
				return pvm.State.Gas, NewExecutionExitReasonBlob([]byte{}), postHostCallX
			}
		}
	}
	return pvm.State.Gas, NewExecutionExitReasonError(ExecutionErrorPanic), postHostCallX
}
