package pvm

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workpackage"
	wp "github.com/ascrivener/jam/workpackage"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

func IsAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) ExecutionExitReason {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, state *State, _ struct{}) (ExitReason, struct{}) {
		if n == GasID {
			exitReason, _, _, _ := Gas(types.GasValue(state.Gas), state.Registers, state.RAM)
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

func Refine(workItemIndex int, workPackage workpackage.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, exportSegmentOffset int) (ExecutionExitReason, [][]byte) {
	// TODO: implement
	var hf HostFunction[IntegratedPVMsAndExportSequence] = func(n HostFunctionIdentifier, state *State, m IntegratedPVMsAndExportSequence) (ExitReason, IntegratedPVMsAndExportSequence) {
		return NewSimpleExitReason(ExitGo), m
	}
	workItem := workPackage.WorkItems[workItemIndex] // w
	serviceAccounts := historicallookup.GetPosteriorServiceAccounts(workPackage.RefinementContext.LookupAnchorHeaderHash, workPackage.RefinementContext.Timeslot)
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
	_, r, integratedPVMsAndExportSequence := ΨM(*preimage, 0, workItem.RefinementGasLimit, a, hf, IntegratedPVMsAndExportSequence{
		IntegratedPVMs: map[int]IntegratedPVM{},
		ExportSequence: [][]byte{},
	})
	if r.IsError() && *r.ExecutionError == ExecutionErrorOutOfGas || *r.ExecutionError == ExecutionErrorPanic {
		return r, [][]byte{}
	}
	return r, integratedPVMsAndExportSequence.ExportSequence
}
