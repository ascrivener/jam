package pvm

import (
	"fmt"
	"jam/pkg/bitsequence"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

type PVM struct {
	Instructions               []byte
	InstructionsLength         int // Cached length to avoid repeated len() calls
	Opcodes                    bitsequence.BitSequence
	BasicBlockBeginningOpcodes map[int]struct{} // Precomputed basic block beginning opcodes.
	SkipLengths                []int            // Precomputed skip lengths for all instruction positions.
	DynamicJumpTable           []types.Register
	InstructionCounter         types.Register
	State                      *State
}

func NewPVM(programBlob []byte, registers [13]types.Register, ram *ram.RAM, instructionCounter types.Register, gas types.GasValue) *PVM {
	instructions, opcodes, dynamicJumpTable, ok := Deblob(programBlob)
	if !ok {
		return nil
	}

	// Precompute skip lengths for all instruction positions
	skipLengths := make([]int, len(instructions))
	for i := range instructions {
		skipLengths[i] = skip(types.Register(i), opcodes)
	}

	basicBlockBeginningOpcodes := map[int]struct{}{0: {}} // Start with index 0 as it's always a basic block beginning
	for n, instruction := range instructions {
		if opcodes.BitAt(n) && terminationOpcodes[instruction] {
			basicBlockBeginningOpcodes[n+1+skipLengths[n]] = struct{}{}
		}
	}
	for basicBlockBeginningOpcode := range basicBlockBeginningOpcodes {
		if basicBlockBeginningOpcode >= len(instructions) || !opcodes.BitAt(basicBlockBeginningOpcode) || dispatchTable[instructions[basicBlockBeginningOpcode]] == nil {
			delete(basicBlockBeginningOpcodes, basicBlockBeginningOpcode)
		}
	}
	return &PVM{
		Instructions:               instructions,
		InstructionsLength:         len(instructions),
		Opcodes:                    opcodes,
		BasicBlockBeginningOpcodes: basicBlockBeginningOpcodes,
		SkipLengths:                skipLengths,
		DynamicJumpTable:           dynamicJumpTable,
		InstructionCounter:         instructionCounter,
		State: &State{
			Gas:       types.SignedGasValue(gas),
			Registers: registers,
			RAM:       ram,
		},
	}
}

func InitializePVM(programCodeFormat []byte, arguments ram.Arguments, instructionCounter types.Register, gas types.GasValue) *PVM {
	programBlob, registers, ram, ok := decodeProgramCodeFormat(programCodeFormat, arguments)
	if !ok {
		return nil
	}
	return NewPVM(programBlob, registers, ram, instructionCounter, gas)
}

func decodeProgramCodeFormat(p []byte, arguments ram.Arguments) (c []byte, regs [13]types.Register, r *ram.RAM, ok bool) {
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
	regs[8] = types.Register(len(arguments))

	return c, regs, ram.NewRAM(o, w, arguments, z, s), true
}

// deblob attempts to decompose p into three parts: c, k, and j.
// It returns ok==false if p does not follow the expected structure.
func Deblob(p []byte) (c []byte, k bitsequence.BitSequence, j []types.Register, ok bool) {
	offset := 0

	// 1. Decode E(|j|): the encoded number of elements in j.
	L_j, n, ok := serializer.DecodeGeneralNatural(p[offset:])
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
	L_c, n, ok := serializer.DecodeGeneralNatural(p[offset:])
	if !ok {
		return nil, k, nil, false
	}
	offset += n

	// 4. Decode Ez(j): j is an array of L_j elements, each encoded in z bytes.
	totalJBytes := int(L_j) * int(z)
	if offset+totalJBytes > len(p) {
		return nil, k, nil, false
	}
	jArr := make([]types.Register, 0, L_j)
	for range int(L_j) {
		elem := serializer.DecodeLittleEndian(p[offset : offset+int(z)])
		jArr = append(jArr, types.Register(elem))
		offset += int(z)
	}

	c = p[offset : offset+int(L_c)]
	offset += int(L_c)
	// Construct k from kBuf using LSB-first ordering with exact bit length matching L_c
	bitSeq, err := bitsequence.FromBytesLSBWithLength(p[offset:], int(L_c))
	if err != nil {
		return nil, k, nil, false
	}
	k = *bitSeq

	return c, k, jArr, true
}

func (pvm *PVM) Run() ExitReason {
	for {
		exitReason := pvm.SingleStep()
		if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitGo {
			// Continue executing if the exit reason is still "go".
			continue
		}
		// Otherwise, adjust for out-of-gas or panic/halt conditions.
		if pvm.State.Gas < 0 {
			exitReason = ExitReasonOutOfGas
		} else if exitReason.IsSimple() &&
			(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
			// Reset the instruction counter on panic/halt.
			pvm.InstructionCounter = 0
		}
		return exitReason
	}
}

func RunHost[X any](pvm *PVM, f HostFunction[X], x *X) (ExitReason, error) {
	for {
		exitReason := pvm.Run()
		if exitReason.IsSimple() || exitReason.ComplexExitReason.Type != ExitHostCall {
			return exitReason, nil
		}

		hostCall := exitReason.ComplexExitReason.Parameter
		postHostCallExitReason, err := f(HostFunctionIdentifier(hostCall), &HostFunctionContext[X]{State: pvm.State, Argument: x})
		if err != nil {
			return ExitReason{}, err
		}

		if postHostCallExitReason.IsComplex() && postHostCallExitReason.ComplexExitReason.Type == ExitPageFault {
			return ExitReason{}, fmt.Errorf("host call returning fault unhandled")
		}

		if *postHostCallExitReason.SimpleExitReason == ExitGo {
			continue
		}

		return postHostCallExitReason, nil
	}
}

func RunWithArgs[X any](programCodeFormat []byte, instructionCounter types.Register, gas types.GasValue, arguments ram.Arguments, f HostFunction[X], x *X) (types.ExecutionExitReason, types.GasValue, error) {
	pvm := InitializePVM(programCodeFormat, arguments, instructionCounter, gas)
	if pvm == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorPanic), 0, nil
	}
	postHostCallExitReason, err := RunHost(pvm, f, x)
	if err != nil {
		return types.ExecutionExitReason{}, 0, err
	}
	gasUsed := gas - types.GasValue(max(pvm.State.Gas, 0))
	if postHostCallExitReason.IsSimple() {
		if *postHostCallExitReason.SimpleExitReason == ExitOutOfGas {
			return types.NewExecutionExitReasonError(types.ExecutionErrorOutOfGas), gasUsed, nil
		}
		if *postHostCallExitReason.SimpleExitReason == ExitHalt {
			start := pvm.State.Registers[7]
			if !pvm.State.RAM.RangeHas(ram.Inaccessible, uint64(start), uint64(pvm.State.Registers[8]), ram.NoWrap) {
				blob := pvm.State.RAM.InspectRange(uint64(start), 8, ram.NoWrap, false)
				return types.NewExecutionExitReasonBlob(blob), gasUsed, nil
			} else {
				return types.NewExecutionExitReasonBlob([]byte{}), gasUsed, nil
			}
		}
	}
	return types.NewExecutionExitReasonError(types.ExecutionErrorPanic), gasUsed, nil
}
