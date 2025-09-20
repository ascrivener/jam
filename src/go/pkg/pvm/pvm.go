package pvm

import (
	"fmt"
	"jam/pkg/bitsequence"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

type ParsedInstruction struct {
	PC                    types.Register
	NextPC                types.Register
	Opcode                byte
	SkipLength            int
	Handler               InstructionHandler
	IsBeginningBasicBlock bool
	Ra, Rb, Rd            int
	Vx, Vy                types.Register
}

type PVM struct {
	Instructions       []byte
	InstructionsLength int
	InstructionCounter types.Register
	DynamicJumpTable   []types.Register
	State              *State
	InstructionSlice   []*ParsedInstruction // For direct instruction lookup
}

func NewPVM(programBlob []byte, registers [13]types.Register, ram *ram.RAM, instructionCounter types.Register, gas types.GasValue) *PVM {
	instructions, opcodes, dynamicJumpTable, ok := Deblob(programBlob)
	if !ok {
		return nil
	}

	instructionSlice := formParsedInstructions(instructions, opcodes)

	return &PVM{
		Instructions:       instructions,
		InstructionsLength: len(instructions),
		InstructionCounter: instructionCounter,
		DynamicJumpTable:   dynamicJumpTable,
		State: &State{
			Gas:       types.SignedGasValue(gas),
			Registers: registers,
			RAM:       ram,
		},
		InstructionSlice: instructionSlice,
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

func formParsedInstructions(instructions []byte, opcodes bitsequence.BitSequence) []*ParsedInstruction {
	// Create sparse slice sized to instruction length
	instructionSlice := make([]*ParsedInstruction, len(instructions))

	currentOpcode := instructions[0]
	currentOpcodePC := 0
	previousWasTerminating := false

	// Helper function to finish current instruction
	finishInstruction := func(nextPC int) {
		instructionInfo := dispatchTable[currentOpcode]
		isBeginning := (currentOpcodePC == 0 || previousWasTerminating) && instructionInfo != nil
		handler := dispatchTable[0].Handler
		operandExtractor := dispatchTable[0].ExtractOperands
		if instructionInfo != nil {
			handler = instructionInfo.Handler
			operandExtractor = instructionInfo.ExtractOperands
		}
		skipLength := nextPC - currentOpcodePC - 1

		ra, rb, rd, vx, vy := operandExtractor(instructions, currentOpcodePC, skipLength)

		instruction := &ParsedInstruction{
			PC:                    types.Register(currentOpcodePC),
			NextPC:                types.Register(nextPC),
			Opcode:                currentOpcode,
			SkipLength:            skipLength,
			Handler:               handler,
			IsBeginningBasicBlock: isBeginning,
			Ra:                    ra,
			Rb:                    rb,
			Rd:                    rd,
			Vx:                    vx,
			Vy:                    vy,
		}
		instructionSlice[currentOpcodePC] = instruction

		// Update for next iteration
		previousWasTerminating = terminationOpcodes[currentOpcode]
	}

	for n := 1; n < len(instructions); n++ {
		// If this is an opcode position
		if opcodes.BitAt(n) {
			// Finish the previous instruction
			finishInstruction(n)

			// Start new instruction
			currentOpcode = instructions[n]
			currentOpcodePC = n
		}
	}

	// Handle the final instruction
	finishInstruction(len(instructions))

	return instructionSlice
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

	defer pvm.State.RAM.ReturnToPool()

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
			start := uint64(pvm.State.Registers[7])
			len := uint64(pvm.State.Registers[8])
			if !pvm.State.RAM.RangeHas(ram.Inaccessible, start, len, ram.NoWrap) {
				blob := pvm.State.RAM.InspectRange(start, len, ram.NoWrap, false)
				return types.NewExecutionExitReasonBlob(blob), gasUsed, nil
			} else {
				return types.NewExecutionExitReasonBlob([]byte{}), gasUsed, nil
			}
		}
	}
	return types.NewExecutionExitReasonError(types.ExecutionErrorPanic), gasUsed, nil
}

func (pvm *PVM) Run() ExitReason {
	for {
		ic := pvm.InstructionCounter
		if int(ic) >= pvm.InstructionsLength || pvm.InstructionSlice[ic] == nil {
			ic = 0
		}
		instruction := pvm.InstructionSlice[ic]

		// Execute single instruction
		exitReason := pvm.executeInstruction(instruction)
		if exitReason == ExitReasonGo {
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

func (pvm *PVM) executeInstruction(instruction *ParsedInstruction) ExitReason {
	// Clear memory access exceptions for each instruction
	pvm.State.RAM.ClearMemoryAccessExceptions()

	exitReason, nextIC := instruction.Handler(pvm, instruction)

	// Consume gas
	pvm.State.Gas -= types.SignedGasValue(1)

	// Always update instruction counter and return what the handler gave us
	pvm.InstructionCounter = nextIC

	minRamIndex := pvm.State.RAM.GetMinMemoryAccessException()
	if minRamIndex != nil {
		if *minRamIndex < ram.MinValidRamIndex {
			return ExitReasonPanic
		} else {
			parameter := types.Register(ram.PageSize * (*minRamIndex / ram.PageSize))
			return NewComplexExitReason(ExitPageFault, parameter)
		}
	}
	return exitReason
}
