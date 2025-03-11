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
	exitReason, _ := ΨM(workpackage.AuthorizationCode(), 0, types.GasValue(IsAuthorizedGasAllocation), args, hf, &struct{}{})
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

type RefineHostFunction = HostFunction[IntegratedPVMsAndExportSequence]

func Refine(workItemIndex int, workPackage wp.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, exportSegmentOffset int, serviceAccounts state.ServiceAccounts) (ExecutionExitReason, [][]byte) {
	// TODO: implement
	workItem := workPackage.WorkItems[workItemIndex] // w
	var hf RefineHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
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
	r, _ := ΨM(*preimage, 0, workItem.RefinementGasLimit, a, hf, integratedPVMsAndExportSequence)
	if r.IsError() && *r.ExecutionError == ExecutionErrorOutOfGas || *r.ExecutionError == ExecutionErrorPanic {
		return r, [][]byte{}
	}
	return r, integratedPVMsAndExportSequence.ExportSequence
}

type AccumulationStateComponents struct { // U
	ServiceAccounts          state.ServiceAccounts                                         // d
	UpcomingValidatorKeysets [constants.NumValidators]types.ValidatorKeyset                // i
	AuthorizersQueue         [constants.NumCores][constants.AuthorizerQueueLength][32]byte // q
	PrivilegedServices       state.PrivilegedServices                                      // x
}

type DefferredTransfer struct { // T
	SenderServiceIndex   types.ServiceIndex     // s
	ReceiverServiceIndex types.ServiceIndex     // d
	BalanceTransfer      types.Balance          // a
	Memo                 [TransferMemoSize]byte // m
	GasLimit             types.GasValue         // g
}

type OperandTuple struct { // O
	ExecutionExitReason ExecutionExitReason // o
	PayloadHash         [32]byte            // l
	WorkPackageHash     [32]byte            // k
	WorkReportOutput    []byte              // a
}

type AccumulationResultContext struct { // X
	AccumulatingServiceIndex types.ServiceIndex          // s
	StateComponents          AccumulationStateComponents // u
	DerivedServiceIndex      types.ServiceIndex          // i
	DefferredTransfers       []DefferredTransfer         // t
	PreimageResult           *[32]byte                   // y
}

func AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents *AccumulationStateComponents, serviceIndex types.ServiceIndex, timeslot types.Timeslot, posteriorEntropyAccumulator [4][32]byte) *AccumulationResultContext {
	hash := blake2b.Sum256(serializer.Serialize(struct {
		ServiceIndex types.ServiceIndex
		Entropy      [32]byte
		Timeslot     types.Timeslot
	}{
		ServiceIndex: serviceIndex,
		Entropy:      posteriorEntropyAccumulator[0],
		Timeslot:     timeslot,
	}))
	derivedServiceIndex := check(types.ServiceIndex(serializer.DecodeLittleEndian(hash[:])%((1<<32)-1<<9)+(1<<8)), accumulationStateComponents)
	return &AccumulationResultContext{
		AccumulatingServiceIndex: serviceIndex,
		StateComponents:          *accumulationStateComponents,
		DerivedServiceIndex:      derivedServiceIndex,
		DefferredTransfers:       []DefferredTransfer{},
		PreimageResult:           nil,
	}
}

type AccumulateInvocationContext struct {
	AccumulationResultContext            AccumulationResultContext // x
	ExceptionalAccumulationResultContext AccumulationResultContext // y
}

// s
func (ctx AccumulateInvocationContext) AccumulatingServiceAccount() *state.ServiceAccount {
	s := ctx.AccumulationResultContext.StateComponents.ServiceAccounts[ctx.AccumulationResultContext.AccumulatingServiceIndex]
	return &s
}

// G
func (ctx *AccumulateInvocationContext) SetAccumulatingServiceAccount(serviceAccount *state.ServiceAccount) {
	ctx.AccumulationResultContext.StateComponents.ServiceAccounts[ctx.AccumulationResultContext.AccumulatingServiceIndex] = *serviceAccount
}

type AccumulateHostFunction = HostFunction[AccumulateInvocationContext]

func Accumulate(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, serviceIndex types.ServiceIndex, gas types.GasValue, operandTuples []OperandTuple, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DefferredTransfer, *[32]byte, types.SignedGasValue) {
	var hf AccumulateHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Remember to use g = 10 + w9 for transfer
		ctx.State.Gas = ctx.State.Gas - types.SignedGasValue(GasUsage)
		switch n {
		case ReadID:
			return Read(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulatingServiceAccount(), ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex, ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts)
		case WriteID:
			return Write(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulatingServiceAccount(), ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex)
		case LookupID:
			return Lookup(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulatingServiceAccount(), ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex, ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts)
		case GasID:
			return Gas(ctx.State, struct{}{})
		case InfoID:
			return Info(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{}}, ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex, ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts)
		case BlessID:
			return Bless(ctx)
		case AssignID:
			return Assign(ctx)
		case DesignateID:
			return Designate(ctx)
		case CheckpointID:
			return Checkpoint(ctx)
		case NewID:
			return New(ctx)
		case UpgradeID:
			return Upgrade(ctx)
		case TransferID:
			ctx.State.Gas = ctx.State.Gas - types.SignedGasValue(ctx.State.Registers[9])
			return Transfer(ctx)
		case EjectID:
			return Eject(ctx, timeslot)
		case QueryID:
			return Query(ctx)
		case SolicitID:
			return Solicit(ctx, timeslot)
		case ForgetID:
			return Forget(ctx, timeslot)
		case YieldID:
			return Yield(ctx)
		default:
			ctx.State.Registers[7] = Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo)
		}
	}
	normalContext := AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents, serviceIndex, timeslot, posteriorEntropyAccumulator)
	if accumulatingServiceAccount, ok := accumulationStateComponents.ServiceAccounts[serviceIndex]; ok {
		// Create two separate context objects
		exceptionalContext := AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents, serviceIndex, timeslot, posteriorEntropyAccumulator)
		ctx := AccumulateInvocationContext{
			AccumulationResultContext:            *normalContext,
			ExceptionalAccumulationResultContext: *exceptionalContext,
		}
		executionExitReason, gas := ΨM(accumulatingServiceAccount.CodeHash[:], 5, gas, serializer.Serialize(struct {
			Timeslot      types.Timeslot
			ServiceIndex  types.ServiceIndex
			OperandTuples []OperandTuple
		}{
			Timeslot:      timeslot,
			ServiceIndex:  serviceIndex,
			OperandTuples: operandTuples,
		}), hf, &ctx)
		if executionExitReason.IsError() {
			return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DefferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gas
		}
		blob := *executionExitReason.Blob
		if len(blob) == 32 {
			var preimageResult [32]byte
			copy(preimageResult[:], blob)
			return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DefferredTransfers, &preimageResult, gas
		}
		return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DefferredTransfers, ctx.AccumulationResultContext.PreimageResult, gas
	} else {
		return normalContext.StateComponents, []DefferredTransfer{}, nil, 0
	}
}
