package pvm

import (
	"jam/pkg/pvm/jit"
	"jam/pkg/types"
	"os"
	"runtime"
	"unsafe"
)

// ExecutionMode determines how the PVM executes code
type ExecutionMode int

const (
	ModeInterpreter ExecutionMode = iota // Safe, debuggable
	ModeJIT                              // Fast, production
)

// GetExecutionMode returns the current execution mode based on environment
func GetExecutionMode() ExecutionMode {
	if os.Getenv("PVM_MODE") == "interpreter" {
		return ModeInterpreter
	}
	return ModeJIT
}

// convertParsedInstructions converts PVM ParsedInstructions to JIT ParsedInstructions
func convertParsedInstructions(pvmInstructions []*ParsedInstruction) []*jit.ParsedInstruction {
	result := make([]*jit.ParsedInstruction, len(pvmInstructions))
	for i, instr := range pvmInstructions {
		if instr != nil {
			result[i] = &jit.ParsedInstruction{
				PC:          instr.PC,
				Opcode:      instr.Opcode,
				SkipLength:  instr.SkipLength,
				Ra:          instr.Ra,
				Rb:          instr.Rb,
				Rd:          instr.Rd,
				Vx:          instr.Vx,
				Vy:          instr.Vy,
				BeginsBlock: instr.BeginsBlock,
			}
		}
	}
	return result
}

// CompileForJIT compiles the PVM's program for JIT execution
// Returns the ProgramContext that must be kept alive as long as the compiled code is used
func (pvm *PVM) CompileForJIT() (*jit.ProgramContext, error) {
	jitInstructions := convertParsedInstructions(pvm.PvmICToParsedInstruction)
	ctx, err := jit.CompileProgram(jitInstructions)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, nil
	}
	pvm.JITContext = ctx
	return ctx, nil
}

// RunJIT executes the PVM using JIT-compiled code where available
func RunJIT[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	ctx := pvm.JITContext

	// Pin goroutine to OS thread so we can set up thread-local signal handler once
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Now safe to activate once - goroutine won't migrate to another thread
	ctx.Activate()

	for {
		// Try to get compiled block for current PC (supports mid-block entry via trampolines)
		entryPoint := ctx.GetBlockEntryPoint(pvm.InstructionCounter)

		if entryPoint != 0 {
			// Execute JIT-compiled block
			statePtr := unsafe.Pointer(pvm.State)
			exitEncoded, nextPC := jit.ExecuteBlockPtr(entryPoint, statePtr)

			pvm.InstructionCounter = types.Register(nextPC)

			// Decode exit reason
			if exitEncoded&0x8000000000000000 != 0 {
				// Complex exit (host call or page fault)
				exitType := (exitEncoded >> 56) & 0x7F
				param := types.Register(exitEncoded & 0x00FFFFFFFFFFFFFF)

				if exitType == 0 { // Host call
					if hostFunc != nil {
						postHostCallExitReason, hostErr := hostFunc(
							HostFunctionIdentifier(param),
							&HostFunctionContext[X]{State: pvm.State, Argument: hostArg},
						)
						if hostErr != nil {
							return ExitReason{}, hostErr
						}
						if *postHostCallExitReason.SimpleExitReason == ExitGo {
							continue
						}
						return postHostCallExitReason, nil
					}
					return NewComplexExitReason(ExitHostCall, param), nil
				} else if exitType == 1 { // DynamicJump (jump_ind)
					// Call djump to validate and resolve the dynamic jump
					a := uint32(param)
					djumpResult, target := djump(pvm, a)
					if djumpResult == ExitReasonHalt {
						pvm.InstructionCounter = 0
						return ExitReasonHalt, nil
					}
					if djumpResult == ExitReasonPanic {
						pvm.InstructionCounter = 0
						return ExitReasonPanic, nil
					}
					// djumpResult == ExitReasonGo, continue with target PC
					pvm.InstructionCounter = target
					continue
				} else { // Page fault
					return NewComplexExitReason(ExitPageFault, param), nil
				}
			}

			// Simple exit
			switch exitEncoded {
			case 0: // Go
				continue
			case 1: // Halt
				pvm.InstructionCounter = 0
				return ExitReasonHalt, nil
			case 2: // Panic
				pvm.InstructionCounter = 0
				return ExitReasonPanic, nil
			case 3: // OutOfGas
				return ExitReasonOutOfGas, nil
			}
		} else {
			// No compiled block - execute one instruction via interpreter
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
					if *postHostCallExitReason.SimpleExitReason == ExitGo {
						continue
					}
					return postHostCallExitReason, nil
				}
				return exitReason, nil
			}

			return exitReason, nil
		}
	}
}
