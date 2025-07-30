package pvm

import (
	"maps"

	"jam/pkg/constants"
	"jam/pkg/historicallookup"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/serviceaccount"
	"jam/pkg/types"
	"jam/pkg/workpackage"
	wp "jam/pkg/workpackage"

	"golang.org/x/crypto/blake2b"
)

func IsAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) (types.ExecutionExitReason, types.GasValue, error) {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		switch n {
		case GasID:
			return Gas(ctx, struct{}{})
		case FetchID:
			return Fetch(ctx, &workpackage, nil, nil, nil, nil, nil, nil, nil)
		default:
			ctx.State.Registers[7] = types.Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo), nil
		}
	}
	authorizationCode := workpackage.AuthorizationCode()
	if len(authorizationCode) == 0 {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), types.GasValue(0), nil
	}
	if len(authorizationCode) > int(constants.IsAuthorizedCodeMaxSizeOctets) {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBIG), types.GasValue(0), nil
	}
	return ΨM(authorizationCode, 0, types.GasValue(constants.IsAuthorizedGasAllocation), serializer.Serialize(core), hf, &struct{}{})
}

type IntegratedPVM struct {
	ProgramCode        []byte
	RAM                *ram.RAM
	InstructionCounter types.Register
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

// TODO: needs work. for m2
func Refine(workItemIndex int, workPackage wp.WorkPackage, authorizerOutput []byte, importSegments [][][constants.SegmentSize]byte, exportSegmentOffset int, serviceAccounts serviceaccount.ServiceAccounts) (types.ExecutionExitReason, [][]byte, error) {
	// TODO: implement
	workItem := workPackage.WorkItems[workItemIndex] // w
	var hf RefineHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		switch n {
		case HistoricalLookupID:
			return HistoricalLookup(ctx, workItem.ServiceIdentifier, serviceAccounts, workPackage.RefinementContext.Timeslot)
		case FetchID:
			panic("not implemented")
			// TODO: Figure out how to compute the blobs introduced for a work item
			return Fetch(ctx, &workPackage, &[32]byte{}, &authorizerOutput, &workItemIndex, &importSegments, nil, nil, nil)
		case ExportID:
			return Export(ctx, exportSegmentOffset)
		case GasID:
			return Gas(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{}}, struct{}{})
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
			ctx.State.Registers[7] = types.Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo), nil
		}
	}
	serviceAccount, ok := serviceAccounts[workItem.ServiceIdentifier]
	if !ok {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}, nil
	}
	preimage, err := historicallookup.HistoricalLookup(serviceAccount, workPackage.RefinementContext.Timeslot, workItem.CodeHash)
	if err != nil {
		return types.ExecutionExitReason{}, [][]byte{}, err
	}
	if preimage == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}, nil
	}
	if len(*preimage) > int(constants.ServiceCodeMaxSize) {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBIG), [][]byte{}, nil
	}

	a := serializer.Serialize(struct {
		ServiceIndex                   types.ServiceIndex
		BlobHashesAndLengthsIntroduced []wp.BlobHashAndLengthIntroduced
		WorkPackageHash                [32]byte
		RefinementContext              workpackage.RefinementContext
		Authorizer                     [32]byte
	}{workItem.ServiceIdentifier, workItem.BlobHashesAndLengthsIntroduced, blake2b.Sum256(serializer.Serialize(workPackage)), workPackage.RefinementContext, workPackage.Authorizer()})
	integratedPVMsAndExportSequence := &IntegratedPVMsAndExportSequence{
		IntegratedPVMs: map[int]IntegratedPVM{},
		ExportSequence: [][]byte{},
	}
	r, _, err := ΨM(*preimage, 0, workItem.RefinementGasLimit, a, hf, integratedPVMsAndExportSequence)
	if err != nil {
		return r, [][]byte{}, err
	}
	if r.IsError() && *r.ExecutionError == types.ExecutionErrorOutOfGas || *r.ExecutionError == types.ExecutionErrorPanic {
		return r, [][]byte{}, nil
	}
	return r, integratedPVMsAndExportSequence.ExportSequence, nil
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
	SenderServiceIndex   types.ServiceIndex               // s
	ReceiverServiceIndex types.ServiceIndex               // d
	BalanceTransfer      types.Balance                    // a
	Memo                 [constants.TransferMemoSize]byte // m
	GasLimit             types.GasValue                   // g
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
	WorkResultPayloadHash [32]byte                  // y
	GasLimit              types.GenericGasValue     // g
	ExecutionExitReason   types.ExecutionExitReason // d
	WorkReportOutput      []byte                    // o
}

type PreimageProvisions map[struct {
	ServiceIndex types.ServiceIndex
	BlobString   string
}]struct{}

type AccumulationResultContext struct { // X
	AccumulatingServiceIndex types.ServiceIndex          // s
	StateComponents          AccumulationStateComponents // u
	DerivedServiceIndex      types.ServiceIndex          // i
	DeferredTransfers        []DeferredTransfer          // t
	PreimageResult           *[32]byte                   // y
	PreimageProvisions       PreimageProvisions          // p
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
	derivedServiceIndex := check(types.ServiceIndex((1<<8)+serializer.DecodeLittleEndian(hash[:4])%(1<<32-1<<9)), accumulationStateComponents)
	return &AccumulationResultContext{
		AccumulatingServiceIndex: serviceIndex,
		StateComponents:          accumulationStateComponents.DeepCopy(),
		DerivedServiceIndex:      derivedServiceIndex,
		DeferredTransfers:        []DeferredTransfer{},
		PreimageResult:           nil,
		PreimageProvisions:       PreimageProvisions{},
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

func Accumulate(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, serviceIndex types.ServiceIndex, gas types.GasValue, operandTuples []OperandTuple, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, *[32]byte, types.GasValue, PreimageProvisions, error) {
	var hf AccumulateHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
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
			return Gas(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		case FetchID:
			return Fetch(ctx, nil, &posteriorEntropyAccumulator[0], nil, nil, nil, nil, &operandTuples, nil)
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
		case ProvideID:
			return Provide(ctx, serviceIndex)
		default:
			ctx.State.Registers[7] = types.Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo), nil
		}
	}
	normalContext := AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents, serviceIndex, timeslot, posteriorEntropyAccumulator)
	serviceAccount, ok := accumulationStateComponents.ServiceAccounts[serviceIndex]
	if !ok {
		return normalContext.StateComponents, []DeferredTransfer{}, nil, 0, PreimageProvisions{}, nil
	}
	_, code, err := serviceAccount.MetadataAndCode()
	if err != nil {
		return normalContext.StateComponents, []DeferredTransfer{}, nil, 0, PreimageProvisions{}, err
	}
	if code == nil || len(*code) > int(constants.ServiceCodeMaxSize) {
		return normalContext.StateComponents, []DeferredTransfer{}, nil, 0, PreimageProvisions{}, nil
	}
	// Create two separate context objects
	exceptionalContext := AccumulationResultContextFromAccumulationStateComponents(accumulationStateComponents, serviceIndex, timeslot, posteriorEntropyAccumulator)
	ctx := AccumulateInvocationContext{
		AccumulationResultContext:            *normalContext,
		ExceptionalAccumulationResultContext: *exceptionalContext,
	}
	serializedArguments := serializer.Serialize(struct {
		Timeslot         types.GenericNum
		ServiceIndex     types.GenericNum
		OperandTuplesLen types.GenericNum
	}{
		Timeslot:         types.GenericNum(timeslot),
		ServiceIndex:     types.GenericNum(serviceIndex),
		OperandTuplesLen: types.GenericNum(len(operandTuples)),
	})
	executionExitReason, gasUsed, err := ΨM(*code, 5, gas, serializedArguments, hf, &ctx)
	if err != nil {
		return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, err
	}
	if executionExitReason.IsError() {
		return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, nil
	}
	blob := *executionExitReason.Blob
	if len(blob) == 32 {
		var preimageResult [32]byte
		copy(preimageResult[:], blob)
		return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, &preimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, nil
	}
	return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, ctx.AccumulationResultContext.PreimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, nil
}

func OnTransfer(serviceAccounts serviceaccount.ServiceAccounts, timeslot types.Timeslot, serviceIndex types.ServiceIndex, posteriorEntropyAccumulator [4][32]byte, deferredTransfers []DeferredTransfer) (*serviceaccount.ServiceAccount, types.GasValue, error) {
	var hf HostFunction[serviceaccount.ServiceAccount] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[serviceaccount.ServiceAccount]) (ExitReason, error) {
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
			return Gas(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		case FetchID:
			return Fetch(ctx, nil, &posteriorEntropyAccumulator[0], nil, nil, nil, nil, nil, &deferredTransfers)
		case InfoID:
			return Info(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, serviceIndex, serviceAccounts)
		default:
			ctx.State.Registers[7] = types.Register(HostCallWhat)
			return NewSimpleExitReason(ExitGo), nil
		}
	}
	serviceAccount := serviceAccounts[serviceIndex]
	if len(deferredTransfers) == 0 {
		return serviceAccount, 0, nil
	}
	DeferredTransferGasLimitTotal := types.GasValue(0)
	for _, deferredTransfer := range deferredTransfers {
		serviceAccount.Balance += deferredTransfer.BalanceTransfer
		DeferredTransferGasLimitTotal += deferredTransfer.GasLimit
	}
	_, code, err := serviceAccount.MetadataAndCode()
	if err != nil {
		return serviceAccount, 0, err
	}
	if code == nil || len(*code) > int(constants.ServiceCodeMaxSize) {
		return serviceAccount, 0, nil
	}
	_, gas, err := ΨM(*code, 10, DeferredTransferGasLimitTotal, serializer.Serialize(struct {
		Timeslot             types.GenericNum
		ServiceIndex         types.GenericNum
		DeferredTransfersLen types.GenericNum
	}{
		Timeslot:             types.GenericNum(timeslot),
		ServiceIndex:         types.GenericNum(serviceIndex),
		DeferredTransfersLen: types.GenericNum(len(deferredTransfers)),
	}), hf, serviceAccount)
	if err != nil {
		return serviceAccount, 0, err
	}
	return serviceAccount, gas, nil
}
