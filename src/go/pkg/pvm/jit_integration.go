package pvm

import (
	"jam/pkg/pvm/jit"
	"jam/pkg/ram"
	"jam/pkg/types"
	"os"
	"unsafe"
)

// ExecutionMode determines how the PVM executes code
type ExecutionMode int

const (
	ModeInterpreter ExecutionMode = iota // Safe, debuggable
	ModeJIT                              // Fast, production
)

// Global JIT runtime (shared across PVM instances)
var (
	globalJITRuntime *jit.Runtime
	jitInitialized   bool
)

// initJIT initializes the global JIT runtime
func initJIT() error {
	if jitInitialized {
		return nil
	}

	// Check environment variable for JIT disable
	if os.Getenv("PVM_MODE") == "interpreter" {
		jitInitialized = true
		return nil
	}

	rt, err := jit.NewRuntime()
	if err != nil {
		return err
	}
	globalJITRuntime = rt
	jitInitialized = true
	return nil
}

// GetExecutionMode returns the current execution mode based on environment
func GetExecutionMode() ExecutionMode {
	if os.Getenv("PVM_MODE") == "interpreter" {
		return ModeInterpreter
	}
	return ModeJIT
}

// SetJITEnabled enables or disables JIT at runtime
func SetJITEnabled(enabled bool) {
	if globalJITRuntime != nil {
		globalJITRuntime.SetEnabled(enabled)
	}
}

// JITStats returns JIT compilation statistics
func JITStats() jit.Stats {
	if globalJITRuntime == nil {
		return jit.Stats{}
	}
	return globalJITRuntime.Stats()
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
func (pvm *PVM) CompileForJIT() error {
	if err := initJIT(); err != nil {
		return err
	}

	if globalJITRuntime == nil || !globalJITRuntime.Enabled() {
		return nil
	}

	jitInstructions := convertParsedInstructions(pvm.PvmICToParsedInstruction)
	return globalJITRuntime.CompileProgram(jitInstructions, pvm.DynamicJumpTable)
}

// RunJIT executes the PVM using JIT-compiled code where available
func RunJIT[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X) (exitReason ExitReason, err error) {
	defer func() {
		if r := recover(); r != nil {
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
			err = nil
			exitReason = ExitReasonPanic
		}
	}()

	// Fall back to interpreter if JIT not available
	if globalJITRuntime == nil || !globalJITRuntime.Enabled() {
		return Run(pvm, hostFunc, hostArg)
	}

	for {
		// Try to get compiled block for current PC
		block := globalJITRuntime.GetBlock(pvm.InstructionCounter)

		if block != nil {
			// Execute JIT-compiled block
			statePtr := unsafe.Pointer(pvm.State)
			exitEncoded, nextPC := globalJITRuntime.ExecuteBlock(block, statePtr)

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

// RunWithMode runs the PVM with the specified execution mode
func RunWithMode[X any](pvm *PVM, hostFunc HostFunction[X], hostArg *X, mode ExecutionMode) (ExitReason, error) {
	if mode == ModeJIT {
		return RunJIT(pvm, hostFunc, hostArg)
	}
	return Run(pvm, hostFunc, hostArg)
}
