package pvm

import (
	"fmt"
	"jam/pkg/bitsequence"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

type ParsedInstruction struct {
	PC         types.Register
	NextPC     types.Register
	Opcode     byte
	SkipLength int
	Ra, Rb, Rd int
	Vx, Vy     types.Register
}

type BasicBlock struct {
	StartPC  types.Register
	StartIdx int
	EndIdx   int
}

type PVM struct {
	InstructionsLength int
	InstructionCounter types.Register
	DynamicJumpTable   []types.Register
	State              *State
	program            []byte
	opcodes            bitsequence.BitSequence
	blockCache         []*BasicBlock
	parsedInstructions []ParsedInstruction
}

func NewPVM(programBlob []byte, registers [13]types.Register, ram *ram.RAM, instructionCounter types.Register, gas types.GasValue) *PVM {
	instructions, opcodes, dynamicJumpTable, ok := Deblob(programBlob)
	if !ok {
		return nil
	}

	opcodeCount := opcodes.CountOnes()

	return &PVM{
		InstructionsLength: len(instructions),
		InstructionCounter: instructionCounter,
		DynamicJumpTable:   dynamicJumpTable,
		State: &State{
			Gas:       types.SignedGasValue(gas),
			Registers: registers,
			RAM:       ram,
		},
		program:            instructions,
		opcodes:            opcodes,
		blockCache:         make([]*BasicBlock, len(instructions)),
		parsedInstructions: make([]ParsedInstruction, 0, opcodeCount),
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

	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	L_o := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	L_w := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

	if offset+2 > len(p) {
		return nil, regs, nil, false
	}
	z := int(serializer.DecodeLittleEndian(p[offset : offset+2]))
	offset += 2

	if offset+3 > len(p) {
		return nil, regs, nil, false
	}
	s := int(serializer.DecodeLittleEndian(p[offset : offset+3]))
	offset += 3

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

func Deblob(p []byte) (c []byte, k bitsequence.BitSequence, j []types.Register, ok bool) {
	offset := 0

	L_j, n, ok := serializer.DecodeGeneralNatural(p[offset:])
	if !ok {
		return nil, k, nil, false
	}
	offset += n

	if offset >= len(p) {
		return nil, k, nil, false
	}
	z := p[offset]
	offset++

	L_c, n, ok := serializer.DecodeGeneralNatural(p[offset:])
	if !ok {
		return nil, k, nil, false
	}
	offset += n

	totalJBytes := int(L_j) * int(z)
	if offset+totalJBytes > len(p) {
		return nil, k, nil, false
	}
	jArr := make([]types.Register, L_j)
	for i := range int(L_j) {
		elem := serializer.DecodeLittleEndian(p[offset : offset+int(z)])
		jArr[i] = types.Register(elem)
		offset += int(z)
	}

	c = p[offset : offset+int(L_c)]
	offset += int(L_c)
	bitSeq, err := bitsequence.FromBytesLSBWithLength(p[offset:], int(L_c))
	if err != nil {
		return nil, k, nil, false
	}
	k = *bitSeq

	return c, k, jArr, true
}

func (pvm *PVM) getOrCreateBlock(pc types.Register) *BasicBlock {
	if int(pc) < len(pvm.blockCache) {
		if block := pvm.blockCache[pc]; block != nil {
			return block
		}
	}
	return pvm.parseBlockFrom(pc)
}

func (pvm *PVM) parseBlockFrom(startPC types.Register) *BasicBlock {
	programLen := len(pvm.program)
	if int(startPC) >= programLen {
		return nil
	}

	defaultExtractor := dispatchTable[0].ExtractOperands
	startIdx := len(pvm.parsedInstructions)
	pc := int(startPC)

	for {
		if !pvm.opcodes.BitAt(pc) {
			pc++
			if pc >= programLen {
				break
			}
			continue
		}

		opcode := pvm.program[pc]
		nextPC := pc + 1
		for nextPC < programLen && !pvm.opcodes.BitAt(nextPC) {
			nextPC++
		}

		operandExtractor := defaultExtractor
		if instructionInfo := dispatchTable[opcode]; instructionInfo != nil {
			operandExtractor = instructionInfo.ExtractOperands
		}

		skipLength := nextPC - pc - 1
		ra, rb, rd, vx, vy := operandExtractor(pvm.program, pc, skipLength)

		idx := len(pvm.parsedInstructions)
		pvm.parsedInstructions = pvm.parsedInstructions[:idx+1]
		pvm.parsedInstructions[idx] = ParsedInstruction{
			PC:         types.Register(pc),
			NextPC:     types.Register(nextPC),
			Opcode:     opcode,
			SkipLength: skipLength,
			Ra:         ra,
			Rb:         rb,
			Rd:         rd,
			Vx:         vx,
			Vy:         vy,
		}

		pc = nextPC
		if terminationOpcodes[opcode] || pc >= programLen {
			break
		}
	}

	endIdx := len(pvm.parsedInstructions)
	if startIdx == endIdx {
		return nil
	}

	block := &BasicBlock{
		StartPC:  startPC,
		StartIdx: startIdx,
		EndIdx:   endIdx,
	}

	for i := startIdx; i < endIdx; i++ {
		pvm.blockCache[pvm.parsedInstructions[i].PC] = block
	}

	return block
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
			start := uint64(pvm.State.Registers[7])
			len := uint64(pvm.State.Registers[8])
			if !pvm.State.RAM.RangeHas(ram.Inaccessible, start, len, ram.NoWrap) {
				blob := pvm.State.RAM.InspectRange(start, len, ram.NoWrap, false)
				blobCopy := make([]byte, len)
				copy(blobCopy, blob)
				return types.NewExecutionExitReasonBlob(blobCopy), gasUsed, nil
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
		if int(ic) >= pvm.InstructionsLength {
			ic = 0
		}

		block := pvm.getOrCreateBlock(ic)
		if block == nil {
			pvm.InstructionCounter = 0
			continue
		}

		var instrIdx int
		for i := block.StartIdx; i < block.EndIdx; i++ {
			if pvm.parsedInstructions[i].PC == ic {
				instrIdx = i
				break
			}
		}

		for i := instrIdx; i < block.EndIdx; i++ {
			instruction := pvm.parsedInstructions[i]

			exitReason := pvm.executeInstruction(instruction)
			if exitReason == ExitReasonGo {
				continue
			}
			if pvm.State.Gas < 0 {
				exitReason = ExitReasonOutOfGas
			} else if exitReason.IsSimple() &&
				(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
				pvm.InstructionCounter = 0
			}
			return exitReason
		}
	}
}

func (pvm *PVM) executeInstruction(instruction ParsedInstruction) ExitReason {
	pvm.State.RAM.ClearMemoryAccessExceptions()
	handler := dispatchTable[instruction.Opcode].Handler
	exitReason, nextIC := handler(pvm, instruction)
	pvm.State.Gas -= types.SignedGasValue(1)
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
