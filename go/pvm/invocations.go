package pvm

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workpackage"
	wp "github.com/ascrivener/jam/workpackage"
)

func isAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) ExecutionExitReason {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, state *State, _ struct{}) (ExitReason, struct{}) {
		if n == Gas {
			exitReason, _, _, _ := gas(types.GasValue(state.Gas), state.Registers, state.RAM)
			return exitReason, struct{}{}
		}
		state.Registers[7] = Register(HostCallWhat)
		state.Gas = state.Gas - types.SignedGasValue(GasUsage)
		return NewSimpleExitReason(ExitGo), struct{}{}
	}
	args := serializer.Serialize(struct {
		WorkPackage wp.WorkPackage
		Core        types.CoreIndex
	}{
		WorkPackage: workpackage,
		Core:        core,
	})
	_, exitReason, _ := ΨM(workpackage.AuthorizationCode(), 0, types.GasValue(IsAuthorizedGasAllocation), args, hf, struct{}{})
	return exitReason
}

type IntegratedPVM struct {
	ProgramCode        []byte
	Ram                *RAM
	InstructionCounter Register
}

type IntegratedPVMsAndExportSequence struct {
	IntegratedPVMs map[int]IntegratedPVM
	ExportSequence [][]byte
}

func refine(serviceAccounts state.ServiceAccounts, workItemIndex int, workPackage workpackage.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, exportSegmentOffset int) (ExecutionExitReason, [][]byte) {
	// TODO: implement
	var hf HostFunction[IntegratedPVMsAndExportSequence] = func(n HostFunctionIdentifier, state *State, m IntegratedPVMsAndExportSequence) (ExitReason, IntegratedPVMsAndExportSequence) {
		return NewSimpleExitReason(ExitGo), m
	}
	workItem := workPackage.WorkItems[workItemIndex] // w
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

	// a := serializer.Serialize([]any{workItem.ServiceIdentifier, workItem.})

}
