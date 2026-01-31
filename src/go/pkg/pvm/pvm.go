package pvm

import (
	"crypto/sha256"
	"fmt"
	"jam/pkg/bitsequence"
	"jam/pkg/pvm/jit"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"sync"
)

type cachedProgram struct {
	dynamicJumpTable   []types.Register
	parsedInstructions []*ParsedInstruction
	jitContext         *jit.ProgramContext
}

var (
	programCache   = make(map[[32]byte]*cachedProgram)
	programCacheMu sync.RWMutex
)

type ParsedInstruction struct {
	PC          types.Register
	Opcode      byte
	SkipLength  int
	Ra, Rb, Rd  int
	Vx, Vy      types.Register
	BeginsBlock bool
}

type PVM struct {
	InstructionCounter       types.Register
	DynamicJumpTable         []types.Register
	State                    *State
	PvmICToParsedInstruction []*ParsedInstruction
	JITContext               *jit.ProgramContext
}

func NewPVM(programBlob []byte, registers [13]types.Register, ram *RAM, instructionCounter types.Register, gas types.GasValue) (*PVM, error) {
	hash := sha256.Sum256(programBlob)

	programCacheMu.RLock()
	cached, ok := programCache[hash]
	programCacheMu.RUnlock()

	if ok {
		pvm := &PVM{
			InstructionCounter: instructionCounter,
			DynamicJumpTable:   cached.dynamicJumpTable,
			State: &State{
				Gas:       types.SignedGasValue(gas),
				Registers: registers,
				RAM:       ram,
			},
			PvmICToParsedInstruction: cached.parsedInstructions,
			JITContext:               cached.jitContext, // Reuse cached JIT context for trampolines
		}
		return pvm, nil
	}

	instructions, opcodes, dynamicJumpTable, deblobOk := Deblob(programBlob)
	if !deblobOk {
		return nil, nil
	}

	if len(instructions) == 0 {
		return nil, nil
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

	pvm := &PVM{
		InstructionCounter: instructionCounter,
		DynamicJumpTable:   dynamicJumpTable,
		State: &State{
			Gas:       types.SignedGasValue(gas),
			Registers: registers,
			RAM:       ram,
		},
		PvmICToParsedInstruction: parsedInstructions,
	}

	// Compile for JIT execution only if in JIT mode
	var jitContext *jit.ProgramContext
	if GetExecutionMode() == ModeJIT {
		var err error
		jitContext, err = pvm.CompileForJIT()
		if err != nil {
			return nil, err
		}
	}

	// Cache the result including JIT blocks and context
	programCacheMu.Lock()
	programCache[hash] = &cachedProgram{
		dynamicJumpTable:   dynamicJumpTable,
		parsedInstructions: parsedInstructions,
		jitContext:         jitContext,
	}
	programCacheMu.Unlock()

	return pvm, nil
}

func InitializePVM(programCodeFormat []byte, arguments Arguments, instructionCounter types.Register, gas types.GasValue) (*PVM, error) {
	programBlob, registers, ram, ok := decodeProgramCodeFormat(programCodeFormat, arguments)
	if !ok {
		return nil, nil
	}
	return NewPVM(programBlob, registers, ram, instructionCounter, gas)
}

func decodeProgramCodeFormat(p []byte, arguments Arguments) (c []byte, regs [13]types.Register, r *RAM, ok bool) {
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

	if 5*MajorZoneSize+TotalSizeNeededMajorZones(L_o)+TotalSizeNeededMajorZones(L_w+z*PageSize)+TotalSizeNeededMajorZones(int(s))+ArgumentsZoneSize > RamSize {
		return nil, regs, nil, false
	}

	regs[0] = RamSize - MajorZoneSize
	regs[1] = RamSize - 2*MajorZoneSize - ArgumentsZoneSize
	regs[7] = RamSize - MajorZoneSize - ArgumentsZoneSize
	regs[8] = types.Register(len(arguments))

	return c, regs, NewRAM(o, w, arguments, z, s, GetExecutionMode() == ModeJIT), true
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

func RunWithArgs[X any](programCodeFormat []byte, instructionCounter types.Register, gas types.GasValue, arguments Arguments, f HostFunction[X], x *X) (types.ExecutionExitReason, types.GasValue, error) {
	pvm, err := InitializePVM(programCodeFormat, arguments, instructionCounter, gas)
	if err != nil {
		return types.ExecutionExitReason{}, 0, err
	}
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
			blob := pvm.State.RAM.InspectRangeSafe(start, len)
			if blob != nil {
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
	// Use JIT execution if available
	if GetExecutionMode() == ModeJIT {
		return RunJIT(pvm, hostFunc, hostArg)
	}
	return runInterpreter(pvm, hostFunc, hostArg)
}

func runInterpreter[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	for {
		exitReason = pvm.executeInstruction()
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

func (pvm *PVM) executeInstruction() ExitReason {
	instruction := pvm.PvmICToParsedInstruction[pvm.InstructionCounter]
	pvm.State.Gas--
	if instruction == nil {
		return ExitReasonPanic
	}
	handler := dispatchTable[instruction.Opcode].Handler
	exitReason, nextIC := handler(pvm, *instruction)
	pvm.InstructionCounter = nextIC
	return exitReason
}
