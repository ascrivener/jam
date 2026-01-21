package pvm

import (
	"crypto/sha256"
	"fmt"
	"jam/pkg/bitsequence"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"reflect"
	"sync"
)

type cachedProgram struct {
	instructions       []byte
	opcodes            bitsequence.BitSequence
	dynamicJumpTable   []types.Register
	parsedInstructions []*ParsedInstruction
}

var (
	programCache   = make(map[[32]byte]*cachedProgram)
	programCacheMu sync.RWMutex
)

// extractFaultAddress attempts to extract the faulting address from a runtime error
// The runtime.errorAddressString type has an unexported "addr" field we access via reflection
func extractFaultAddress(err error) uintptr {
	v := reflect.ValueOf(err)
	// Handle pointer types
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	// Look for "addr" field in the struct
	if v.Kind() == reflect.Struct {
		addrField := v.FieldByName("addr")
		if addrField.IsValid() && addrField.CanUint() {
			addr := uintptr(addrField.Uint())
			return addr
		}
	}
	return 0
}

type ParsedInstruction struct {
	PC          types.Register
	Opcode      byte
	SkipLength  int
	Ra, Rb, Rd  int
	Vx, Vy      types.Register
	BeginsBlock bool
}

// func runBlock[X any](block *BasicBlock, pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
// 	for idx := block.StartIdx; idx < block.EndIdx; idx++ {
// 		instruction := pvm.ParsedInstructions[idx]
// 		exitReason = pvm.executeInstruction(instruction)
// 		if exitReason == ExitReasonGo {
// 			continue
// 		}
// 		if pvm.State.Gas < 0 {
// 			exitReason = ExitReasonOutOfGas
// 		} else if exitReason.IsSimple() &&
// 			(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
// 			pvm.InstructionCounter = 0
// 		}

// 		// Handle host calls inline if host function provided
// 		if exitReason.IsComplex() && exitReason.ComplexExitReason.Type == ExitHostCall {
// 			if hostFunc != nil {
// 				hostCall := exitReason.ComplexExitReason.Parameter
// 				postHostCallExitReason, hostErr := hostFunc(
// 					HostFunctionIdentifier(hostCall),
// 					&HostFunctionContext[X]{State: pvm.State, Argument: hostArg},
// 				)

// 				if hostErr != nil {
// 					return ExitReason{}, hostErr
// 				}

// 				if postHostCallExitReason.IsComplex() &&
// 					postHostCallExitReason.ComplexExitReason.Type == ExitPageFault {
// 					return ExitReason{}, fmt.Errorf("host call returning fault unhandled")
// 				}

// 				if *postHostCallExitReason.SimpleExitReason == ExitGo {
// 					continue
// 				}

// 				return postHostCallExitReason, nil
// 			} else {
// 				// No host function, return to caller (Invoke case)
// 				return exitReason, nil
// 			}
// 		}

// 		return exitReason, nil
// 	}
// 	return ExitReasonGo, nil
// }

type PVM struct {
	InstructionCounter types.Register
	DynamicJumpTable   []types.Register
	State              *State
	program            []byte
	opcodes            bitsequence.BitSequence
	// ParsedInstructions          []ParsedInstruction
	PvmICToParsedInstruction []*ParsedInstruction
}

func NewPVM(programBlob []byte, registers [13]types.Register, ram *ram.RAM, instructionCounter types.Register, gas types.GasValue) *PVM {
	hash := sha256.Sum256(programBlob)

	programCacheMu.RLock()
	cached, ok := programCache[hash]
	programCacheMu.RUnlock()

	if ok {
		return &PVM{
			InstructionCounter: instructionCounter,
			DynamicJumpTable:   cached.dynamicJumpTable,
			State: &State{
				Gas:       types.SignedGasValue(gas),
				Registers: registers,
				RAM:       ram,
			},
			program:                  cached.instructions,
			opcodes:                  cached.opcodes,
			PvmICToParsedInstruction: cached.parsedInstructions,
		}
	}

	instructions, opcodes, dynamicJumpTable, deblobOk := Deblob(programBlob)
	if !deblobOk {
		return nil
	}

	if len(instructions) == 0 {
		return nil
	}

	parsedInstructions := make([]*ParsedInstruction, len(instructions))

	pc := 0
	previousPCIsTerminating := false
	for pc < len(instructions) {
		nextPC := pc + 1
		for nextPC < len(instructions) && !opcodes.BitAt(nextPC) && (nextPC-pc) <= 24 {
			nextPC++
		}

		opcode := instructions[0]
		operandExtractor := dispatchTable[0].ExtractOperands
		if instructionInfo := dispatchTable[instructions[pc]]; instructionInfo != nil && opcodes.BitAt(pc) {
			opcode = instructions[pc]
			operandExtractor = instructionInfo.ExtractOperands
		}

		skipLength := nextPC - pc - 1
		ra, rb, rd, vx, vy := operandExtractor(instructions, pc, skipLength)

		parsedInstruction := &ParsedInstruction{
			PC:         types.Register(pc),
			Opcode:     opcode,
			SkipLength: skipLength,
			Ra:         ra,
			Rb:         rb,
			Rd:         rd,
			Vx:         vx,
			Vy:         vy,
		}

		if previousPCIsTerminating {
			parsedInstruction.BeginsBlock = true
			previousPCIsTerminating = false
		}

		if nextPC < len(instructions) && dispatchTable[instructions[nextPC]] != nil && opcodes.BitAt(nextPC) {
			if terminationOpcodes[instructions[pc]] && opcodes.BitAt(pc) {
				previousPCIsTerminating = true
			} else if pc == 0 {
				parsedInstruction.BeginsBlock = true
			}
		}

		parsedInstructions[pc] = parsedInstruction

		pc = nextPC
	}

	// Cache the result
	programCacheMu.Lock()
	programCache[hash] = &cachedProgram{
		instructions:       instructions,
		opcodes:            opcodes,
		dynamicJumpTable:   dynamicJumpTable,
		parsedInstructions: parsedInstructions,
	}
	programCacheMu.Unlock()

	return &PVM{
		InstructionCounter: instructionCounter,
		DynamicJumpTable:   dynamicJumpTable,
		State: &State{
			Gas:       types.SignedGasValue(gas),
			Registers: registers,
			RAM:       ram,
		},
		program:                  instructions,
		opcodes:                  opcodes,
		PvmICToParsedInstruction: parsedInstructions,
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

// func (pvm *PVM) getOrCreateBlock() *BasicBlock {
// 	pc := pvm.InstructionCounter
// 	if block, ok := pvm.blockCache[pc]; ok {
// 		return block
// 	}
// 	return pvm.parseInstructionsFrom(pc)
// }

// func (pvm *PVM) parseInstructionsFrom(startPC types.Register) *BasicBlock {

// 	programLen := len(pvm.program)

// 	defaultExtractor := dispatchTable[0].ExtractOperands
// 	pc := int(startPC)
// 	startIdx := len(pvm.ParsedInstructions)

// 	for {
// 		nextPC := pc + 1
// 		for nextPC < programLen && !pvm.opcodes.BitAt(nextPC) && (nextPC-pc) <= 24 {
// 			nextPC++
// 		}

// 		opcode := byte(0) // trap instruction
// 		if pc < programLen {
// 			opcode = pvm.program[pc]
// 		}

// 		operandExtractor := defaultExtractor
// 		if instructionInfo := dispatchTable[opcode]; instructionInfo != nil {
// 			operandExtractor = instructionInfo.ExtractOperands
// 		}

// 		skipLength := nextPC - pc - 1
// 		ra, rb, rd, vx, vy := operandExtractor(pvm.program, pc, skipLength)

// 		pvm.ParsedInstructions = append(pvm.ParsedInstructions, ParsedInstruction{
// 			PC:         types.Register(pc),
// 			Opcode:     opcode,
// 			SkipLength: skipLength,
// 			Ra:         ra,
// 			Rb:         rb,
// 			Rd:         rd,
// 			Vx:         vx,
// 			Vy:         vy,
// 		})

// 		if terminationOpcodes[opcode] || pc >= programLen {
// 			break
// 		}
// 		pc = nextPC
// 	}

// 	endIdx := len(pvm.ParsedInstructions)

// 	if endIdx == startIdx {
// 		return nil
// 	}

// 	block := &BasicBlock{
// 		StartIdx: types.Register(startIdx),
// 		EndIdx:   types.Register(endIdx),
// 		// CompiledCode: pvm.compileBlock(instructions),
// 	}

// 	pvm.blockCache[startPC] = block

// 	return block
// }

func RunWithArgs[X any](programCodeFormat []byte, instructionCounter types.Register, gas types.GasValue, arguments ram.Arguments, f HostFunction[X], x *X) (types.ExecutionExitReason, types.GasValue, error) {
	pvm := InitializePVM(programCodeFormat, arguments, instructionCounter, gas)
	if pvm == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorPanic), 0, nil
	}

	postRunExitReason, err := Run(pvm, f, x)
	if err != nil {
		return types.ExecutionExitReason{}, 0, err
	}
	gasUsed := gas - types.GasValue(max(pvm.State.Gas, 0))
	if postRunExitReason.IsSimple() {
		if *postRunExitReason.SimpleExitReason == ExitOutOfGas {
			return types.NewExecutionExitReasonError(types.ExecutionErrorOutOfGas), gasUsed, nil
		}
		if *postRunExitReason.SimpleExitReason == ExitHalt {
			start := uint64(pvm.State.Registers[7])
			len := uint64(pvm.State.Registers[8])
			if !pvm.State.RAM.RangeHasInaccessible(start, len, ram.NoWrap) {
				blob := pvm.State.RAM.InspectRange(start, len, ram.NoWrap)
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

func Run[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Memory fault likely occurred - try to extract faulting address
			if e, ok := r.(error); ok {
				addr := extractFaultAddress(e)
				if addr != 0 {
					ramIdx := pvm.State.RAM.AddressToIndex(addr)
					if ramIdx != nil {
						if *ramIdx < ram.MinValidRamIndex {
							exitReason = ExitReasonPanic
						} else {
							parameter := types.Register(ram.PageSize * (*ramIdx / ram.PageSize))
							exitReason = NewComplexExitReason(ExitPageFault, parameter)
						}
						pvm.InstructionCounter = 0
						return
					}
				}
			}
			// Can't determine the address - this is unexpected, return error
			err = fmt.Errorf("unexpected panic in PVM execution: %v", r)
			exitReason = ExitReason{}
		}
	}()

	for {
		instruction := pvm.PvmICToParsedInstruction[pvm.InstructionCounter]
		exitReason = pvm.executeInstruction(instruction)
		if exitReason == ExitReasonGo {
			continue
		}
		if pvm.State.Gas < 0 {
			exitReason = ExitReasonOutOfGas
		} else if exitReason.IsSimple() &&
			(*exitReason.SimpleExitReason == ExitPanic || *exitReason.SimpleExitReason == ExitHalt) {
			pvm.InstructionCounter = 0
		}

		// Handle host calls inline if host function provided
		if exitReason.IsComplex() && exitReason.ComplexExitReason.Type == ExitHostCall {
			if hostFunc != nil {
				hostCall := exitReason.ComplexExitReason.Parameter
				postHostCallExitReason, hostErr := hostFunc(
					HostFunctionIdentifier(hostCall),
					&HostFunctionContext[X]{State: pvm.State, Argument: hostArg},
				)

				if hostErr != nil {
					return ExitReason{}, hostErr
				}

				if postHostCallExitReason.IsComplex() &&
					postHostCallExitReason.ComplexExitReason.Type == ExitPageFault {
					return ExitReason{}, fmt.Errorf("host call returning fault unhandled")
				}

				if *postHostCallExitReason.SimpleExitReason == ExitGo {
					continue
				}

				return postHostCallExitReason, nil
			} else {
				// No host function, return to caller (Invoke case)
				return exitReason, nil
			}
		}

		return exitReason, nil
	}
}

func (pvm *PVM) executeInstruction(instruction *ParsedInstruction) ExitReason {
	pvm.State.Gas--
	if instruction == nil {
		return ExitReasonPanic
	}
	handler := dispatchTable[instruction.Opcode].Handler
	exitReason, nextIC := handler(pvm, *instruction)
	pvm.InstructionCounter = nextIC
	return exitReason
}
