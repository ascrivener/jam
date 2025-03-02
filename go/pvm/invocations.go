package pvm

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	wp "github.com/ascrivener/jam/workpackage"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

func IsAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) ExecutionExitReason {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[struct{}]) ExitReason {
		ctx.State.Gas = ctx.State.Gas - types.SignedGasValue(GasUsage)
		if n == GasID {
			return Gas(ctx.State, struct{}{})
		}
		ctx.State.Registers[7] = Register(HostCallWhat)
		return NewSimpleExitReason(ExitGo)
	}
	args := serializer.Serialize(struct {
		WorkPackage wp.WorkPackage
		Core        types.CoreIndex
	}{
		WorkPackage: workpackage,
		Core:        core,
	})
	exitReason := ΨM(workpackage.AuthorizationCode(), 0, types.GasValue(IsAuthorizedGasAllocation), args, hf, &struct{}{})
	return exitReason
}

type IntegratedPVM struct {
	ProgramCode        []byte
	RAM                *ram.RAM
	InstructionCounter Register
}

type IntegratedPVMsAndExportSequence struct {
	IntegratedPVMs map[int]IntegratedPVM
	ExportSequence [][]byte
}

type HostFunctionContext[T any] struct {
	State    *State
	Argument *T
}

func Refine(workItemIndex int, workPackage wp.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, exportSegmentOffset int, serviceAccounts state.ServiceAccounts) (ExecutionExitReason, [][]byte) {
	// TODO: implement
	workItem := workPackage.WorkItems[workItemIndex] // w
	var hf HostFunction[IntegratedPVMsAndExportSequence] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		ctx.State.Gas = ctx.State.Gas - types.SignedGasValue(GasUsage)
		switch n {
		case HistoricalLookupID:
			return HistoricalLookup(ctx, workItem.ServiceIdentifier, serviceAccounts, workPackage.RefinementContext.Timeslot)
		case FetchID:
			return Fetch(ctx, workItemIndex, workPackage, authorizerOutput, importSegments)
		case ExportID:
			return Export(ctx, exportSegmentOffset)
		case GasID:
			return Gas(ctx.State, struct{}{})
		case MachineID:
			return Machine(ctx)
		case PeekID:
			return Peek(ctx)
		case ZeroID:
			return Zero(ctx)
		case PokeID:
			return Poke(ctx)
		case VoidID:
			return Void(ctx)
		case InvokeID:
			return Invoke(ctx)
		case ExpungeID:
			return Expunge(ctx)
		default:
			ctx.State.Registers[7] = Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo)
		}
	}
	serviceAccount, ok := serviceAccounts[workItem.ServiceIdentifier]
	if !ok {
		return NewExecutionExitReasonError(ExecutionErrorBAD), [][]byte{}
	}
	preimage := historicallookup.HistoricalLookup(serviceAccount, workPackage.RefinementContext.Timeslot, workItem.CodeHash)
	if preimage == nil {
		return NewExecutionExitReasonError(ExecutionErrorBAD), [][]byte{}
	}
	if len(*preimage) > constants.ServiceCodeMaxSize {
		return NewExecutionExitReasonError(ExecutionErrorBIG), [][]byte{}
	}

	a := serializer.Serialize(struct {
		ServiceIndex                   types.ServiceIndex
		BlobHashesAndLengthsIntroduced []struct {
			BlobHash [32]byte
			Length   int
		}
		WorkPackageHash   [32]byte
		RefinementContext workreport.RefinementContext
		Authorizer        [32]byte
	}{workItem.ServiceIdentifier, workItem.BlobHashesAndLengthsIntroduced, blake2b.Sum256(serializer.Serialize(workPackage)), workPackage.RefinementContext, workPackage.Authorizer()})
	integratedPVMsAndExportSequence := &IntegratedPVMsAndExportSequence{
		IntegratedPVMs: map[int]IntegratedPVM{},
		ExportSequence: [][]byte{},
	}
	r := ΨM(*preimage, 0, workItem.RefinementGasLimit, a, hf, integratedPVMsAndExportSequence)
	if r.IsError() && *r.ExecutionError == ExecutionErrorOutOfGas || *r.ExecutionError == ExecutionErrorPanic {
		return r, [][]byte{}
	}
	return r, integratedPVMsAndExportSequence.ExportSequence
}
