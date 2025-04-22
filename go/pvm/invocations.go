package pvm

import (
	"maps"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	wp "github.com/ascrivener/jam/workpackage"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

func IsAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) types.ExecutionExitReason {
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

func Refine(workItemIndex int, workPackage wp.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, exportSegmentOffset int, serviceAccounts serviceaccount.ServiceAccounts) (types.ExecutionExitReason, [][]byte) {
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
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}
	}
	preimage := historicallookup.HistoricalLookup(serviceAccount, workPackage.RefinementContext.Timeslot, workItem.CodeHash)
	if preimage == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}
	}
	if len(*preimage) > constants.ServiceCodeMaxSize {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBIG), [][]byte{}
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
	if r.IsError() && *r.ExecutionError == types.ExecutionErrorOutOfGas || *r.ExecutionError == types.ExecutionErrorPanic {
		return r, [][]byte{}
	}
	return r, integratedPVMsAndExportSequence.ExportSequence
}

// U
type AccumulationStateComponents struct {
	ServiceAccounts          serviceaccount.ServiceAccounts                                // d
	UpcomingValidatorKeysets [constants.NumValidators]types.ValidatorKeyset                // i
	AuthorizersQueue         [constants.NumCores][constants.AuthorizerQueueLength][32]byte // q
	PrivilegedServices       types.PrivilegedServices                                      // x
}

func (u AccumulationStateComponents) DeepCopy() AccumulationStateComponents {
	// Create a new struct to hold the copied data
	copy := AccumulationStateComponents{
		UpcomingValidatorKeysets: u.UpcomingValidatorKeysets,
		AuthorizersQueue:         u.AuthorizersQueue,
		PrivilegedServices:       u.PrivilegedServices, // Copy the struct
	}

	// Deep copy ServiceAccounts
	copy.ServiceAccounts = make(serviceaccount.ServiceAccounts, len(u.ServiceAccounts))
	for idx, account := range u.ServiceAccounts {
		if account != nil {
			accountCopy := *account
			copy.ServiceAccounts[idx] = &accountCopy
		}
	}

	// Deep copy the map inside PrivilegedServices if it exists
	if u.PrivilegedServices.AlwaysAccumulateServicesWithGas != nil {
		copy.PrivilegedServices.AlwaysAccumulateServicesWithGas = make(map[types.ServiceIndex]types.GasValue)
		maps.Copy(copy.PrivilegedServices.AlwaysAccumulateServicesWithGas, u.PrivilegedServices.AlwaysAccumulateServicesWithGas)
	}

	return copy
}

type DeferredTransfer struct { // T
	SenderServiceIndex   types.ServiceIndex     // s
	ReceiverServiceIndex types.ServiceIndex     // d
	BalanceTransfer      types.Balance          // a
	Memo                 [TransferMemoSize]byte // m
	GasLimit             types.GasValue         // g
}

// DeepCopy creates a deep copy of DeferredTransfer
func (t DeferredTransfer) DeepCopy() DeferredTransfer {
	// Create a new instance with all fields copied
	return DeferredTransfer{
		SenderServiceIndex:   t.SenderServiceIndex,
		ReceiverServiceIndex: t.ReceiverServiceIndex,
		BalanceTransfer:      t.BalanceTransfer,
		Memo:                 t.Memo,
		GasLimit:             t.GasLimit,
	}
}

func SelectDeferredTransfers(deferredTransfers []DeferredTransfer, serviceIndex types.ServiceIndex) []DeferredTransfer {
	selectedDeferredTransfers := make([]DeferredTransfer, 0)
	for _, deferredTransfer := range deferredTransfers {
		if deferredTransfer.ReceiverServiceIndex == serviceIndex {
			selectedDeferredTransfers = append(selectedDeferredTransfers, deferredTransfer)
		}
	}
	return selectedDeferredTransfers
}

type OperandTuple struct { // O
	WorkPackageHash       [32]byte                  // h
	SegmentRoot           [32]byte                  // e
	AuthorizerHash        [32]byte                  // a
	WorkReportOutput      []byte                    // o
	WorkResultPayloadHash [32]byte                  // y
	GasLimit              types.GasValue            // g
	ExecutionExitReason   types.ExecutionExitReason // d
}

type AccumulationResultContext struct { // X
	AccumulatingServiceIndex types.ServiceIndex          // s
	StateComponents          AccumulationStateComponents // u
	DerivedServiceIndex      types.ServiceIndex          // i
	DeferredTransfers        []DeferredTransfer          // t
	PreimageResult           *[32]byte                   // y
}

// DeepCopy creates a deep copy of AccumulationResultContext
func (x AccumulationResultContext) DeepCopy() *AccumulationResultContext {
	// Create a new instance with primitives copied
	copy := &AccumulationResultContext{
		AccumulatingServiceIndex: x.AccumulatingServiceIndex,
		StateComponents:          x.StateComponents.DeepCopy(),
		DerivedServiceIndex:      x.DerivedServiceIndex,
	}

	// Deep copy DeferredTransfers slice
	if x.DeferredTransfers != nil {
		copy.DeferredTransfers = make([]DeferredTransfer, len(x.DeferredTransfers))
		for i, transfer := range x.DeferredTransfers {
			copy.DeferredTransfers[i] = transfer.DeepCopy()
		}
	}

	// Deep copy PreimageResult if not nil
	if x.PreimageResult != nil {
		preimageResult := new([32]byte)
		*preimageResult = *x.PreimageResult
		copy.PreimageResult = preimageResult
	}

	return copy
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
		StateComponents:          accumulationStateComponents.DeepCopy(),
		DerivedServiceIndex:      derivedServiceIndex,
		DeferredTransfers:        []DeferredTransfer{},
		PreimageResult:           nil,
	}
}

type AccumulateInvocationContext struct {
	AccumulationResultContext            AccumulationResultContext // x
	ExceptionalAccumulationResultContext AccumulationResultContext // y
}

// s
func (ctx AccumulateInvocationContext) AccumulatingServiceAccount() *serviceaccount.ServiceAccount {
	s := ctx.AccumulationResultContext.StateComponents.ServiceAccounts[ctx.AccumulationResultContext.AccumulatingServiceIndex]
	return s
}

// G
func (ctx *AccumulateInvocationContext) SetAccumulatingServiceAccount(serviceAccount *serviceaccount.ServiceAccount) {
	ctx.AccumulationResultContext.StateComponents.ServiceAccounts[ctx.AccumulationResultContext.AccumulatingServiceIndex] = serviceAccount
}

type AccumulateHostFunction = HostFunction[AccumulateInvocationContext]

func Accumulate(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, serviceIndex types.ServiceIndex, gas types.GasValue, operandTuples []OperandTuple, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, *[32]byte, types.GasValue) {
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
	serviceAccount, ok := accumulationStateComponents.ServiceAccounts[serviceIndex]
	if !ok {
		return normalContext.StateComponents, []DeferredTransfer{}, nil, 0
	}
	_, code := serviceAccount.MetadataAndCode()
	if code == nil {
		return normalContext.StateComponents, []DeferredTransfer{}, nil, 0
	}
	// Create two separate context objects
	exceptionalContext := AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents, serviceIndex, timeslot, posteriorEntropyAccumulator)
	ctx := AccumulateInvocationContext{
		AccumulationResultContext:            *normalContext,
		ExceptionalAccumulationResultContext: *exceptionalContext,
	}
	executionExitReason, posteriorGas := ΨM(*code, 5, gas, serializer.Serialize(struct {
		Timeslot      types.Timeslot
		ServiceIndex  types.ServiceIndex
		OperandTuples []OperandTuple
	}{
		Timeslot:      timeslot,
		ServiceIndex:  serviceIndex,
		OperandTuples: operandTuples,
	}), hf, &ctx)
	gasUsed := gas - types.GasValue(max(0, posteriorGas))
	if executionExitReason.IsError() {
		return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed
	}
	blob := *executionExitReason.Blob
	if len(blob) == 32 {
		var preimageResult [32]byte
		copy(preimageResult[:], blob)
		return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, &preimageResult, gasUsed
	}
	return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, ctx.AccumulationResultContext.PreimageResult, gasUsed
}

func OnTransfer(serviceAccounts serviceaccount.ServiceAccounts, timeslot types.Timeslot, serviceIndex types.ServiceIndex, deferredTransfers []DeferredTransfer) (*serviceaccount.ServiceAccount, types.GasValue) {
	var hf HostFunction[serviceaccount.ServiceAccount] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[serviceaccount.ServiceAccount]) ExitReason {
		ctx.State.Gas = ctx.State.Gas - types.SignedGasValue(GasUsage)
		switch n {
		case LookupID:
			return Lookup(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument, serviceIndex, serviceAccounts)
		case ReadID:
			return Read(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument, serviceIndex, serviceAccounts)
		case WriteID:
			return Write(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument, serviceIndex)
		case GasID:
			return Gas(ctx.State, struct{}{})
		case InfoID:
			return Info(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, serviceIndex, serviceAccounts)
		default:
			ctx.State.Registers[7] = Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo)
		}
	}
	serviceAccount := serviceAccounts[serviceIndex]
	if len(deferredTransfers) == 0 {
		return serviceAccount, 0
	}
	DeferredTransferGasLimitTotal := types.GasValue(0)
	for _, deferredTransfer := range deferredTransfers {
		serviceAccount.Balance += deferredTransfer.BalanceTransfer
		DeferredTransferGasLimitTotal += deferredTransfer.GasLimit
	}
	_, code := serviceAccount.MetadataAndCode()
	if code == nil {
		return serviceAccount, 0
	}
	_, gas := ΨM(*code, 10, DeferredTransferGasLimitTotal, serializer.Serialize(struct {
		Timeslot          types.Timeslot
		ServiceIndex      types.ServiceIndex
		DeferredTransfers []DeferredTransfer
	}{
		Timeslot:          timeslot,
		ServiceIndex:      serviceIndex,
		DeferredTransfers: deferredTransfers,
	}), hf, serviceAccount)
	return serviceAccount, gas
}
