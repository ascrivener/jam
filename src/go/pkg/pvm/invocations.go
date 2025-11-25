package pvm

import (
	"fmt"
	"maps"

	"jam/pkg/constants"
	"jam/pkg/historicallookup"
	"jam/pkg/ram"
	"jam/pkg/serializer"
	"jam/pkg/serviceaccount"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/workpackage"
	wp "jam/pkg/workpackage"

	"golang.org/x/crypto/blake2b"
)

func IsAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) (types.ExecutionExitReason, types.GasValue, error) {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		switch n {
		case GasID:
			return Gas(ctx)
		case FetchID:
			return Fetch(ctx, &workpackage, nil, nil, nil, nil, nil, nil)
		case LogID:
			return Log(ctx)
		default:
			return Default(ctx)
		}
	}
	authorizationCode := workpackage.AuthorizationCode()
	if authorizationCode == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), types.GasValue(0), nil
	}
	if len(authorizationCode) > int(constants.IsAuthorizedCodeMaxSizeOctets) {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBIG), types.GasValue(0), nil
	}
	return RunWithArgs(authorizationCode, 0, types.GasValue(constants.IsAuthorizedGasAllocation), serializer.Serialize(core), hf, &struct{}{})
}

type IntegratedPVM struct {
	ProgramCode        []byte
	RAM                *ram.RAM
	InstructionCounter types.Register
}

type IntegratedPVMsAndExportSequence struct {
	IntegratedPVMs map[uint64]IntegratedPVM
	ExportSequence [][]byte
}

type HostFunctionContext[T any] struct {
	State    *State
	Argument *T
}

type RefineHostFunction = HostFunction[IntegratedPVMsAndExportSequence]

// TODO: needs work. for m2
func Refine(tx *staterepository.TrackedTx, workItemIndex int, workPackage wp.WorkPackage, authorizerOutput []byte, importSegments [][][constants.SegmentSize]byte, exportSegmentOffset int, serviceAccounts serviceaccount.ServiceAccounts) (types.ExecutionExitReason, [][]byte, error) {
	// TODO: implement
	workItem := workPackage.WorkItems[workItemIndex] // w
	var hf RefineHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		switch n {
		case HistoricalLookupID:
			return HistoricalLookup(ctx, tx, workItem.ServiceIdentifier, serviceAccounts, workPackage.RefinementContext.Timeslot)
		case FetchID:
			panic("not implemented")
			// TODO: Figure out how to compute the blobs introduced for a work item
			return Fetch(ctx, &workPackage, &[32]byte{}, &authorizerOutput, &workItemIndex, &importSegments, nil, nil)
		case ExportID:
			return Export(ctx, exportSegmentOffset)
		case GasID:
			return Gas(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{}})
		case MachineID:
			return Machine(ctx)
		case PeekID:
			return Peek(ctx)
		case PagesID:
			return Pages(ctx)
		case PokeID:
			return Poke(ctx)
		case InvokeID:
			return Invoke(ctx)
		case ExpungeID:
			return Expunge(ctx)
		case LogID:
			return Log(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		default:
			return Default(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		}
	}
	serviceAccount, ok := serviceAccounts[workItem.ServiceIdentifier]
	if !ok {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}, nil
	}
	preimage, err := historicallookup.HistoricalLookup(nil, serviceAccount, workPackage.RefinementContext.Timeslot, workItem.CodeHash)
	if err != nil {
		return types.ExecutionExitReason{}, [][]byte{}, err
	}
	if preimage == nil {
		return types.NewExecutionExitReasonError(types.ExecutionErrorBAD), [][]byte{}, nil
	}
	if len(preimage) > int(constants.ServiceCodeMaxSize) {
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
		IntegratedPVMs: map[uint64]IntegratedPVM{},
		ExportSequence: [][]byte{},
	}
	r, _, err := RunWithArgs(preimage, 0, workItem.RefinementGasLimit, a, hf, integratedPVMsAndExportSequence)
	if err != nil {
		return r, [][]byte{}, err
	}
	if r.IsError() && *r.ExecutionError == types.ExecutionErrorOutOfGas || *r.ExecutionError == types.ExecutionErrorPanic {
		return r, [][]byte{}, nil
	}
	return r, integratedPVMsAndExportSequence.ExportSequence, nil
}

type PreimageProvisions map[struct {
	ServiceIndex types.ServiceIndex // s
	BlobString   string             // i
}]struct{}

type AccumulationResultContext struct { // X
	AccumulatingServiceAccount *serviceaccount.ServiceAccount // s
	StateComponents            *AccumulationStateComponents   // e
	DerivedServiceIndex        types.ServiceIndex             // i
	DeferredTransfers          []types.DeferredTransfer       // t
	PreimageResult             *[32]byte                      // y
	PreimageProvisions         PreimageProvisions             // p
	Tx                         *staterepository.TrackedTx
}

func (ctx *AccumulationResultContext) DeepCopy() *AccumulationResultContext {
	// Create an exact copy of the transaction (sibling with same state)
	exceptionalTx := ctx.Tx.DeepCopy()

	contextCheckpoint := &AccumulationResultContext{
		StateComponents:     ctx.StateComponents.DeepCopy(),
		DerivedServiceIndex: ctx.DerivedServiceIndex,
		Tx:                  exceptionalTx,
	}

	serviceAccountCopy := *ctx.AccumulatingServiceAccount
	contextCheckpoint.AccumulatingServiceAccount = &serviceAccountCopy

	// Deep copy PreimageProvisions
	if ctx.PreimageProvisions != nil {
		contextCheckpoint.PreimageProvisions = make(PreimageProvisions)
		for k, v := range ctx.PreimageProvisions {
			contextCheckpoint.PreimageProvisions[k] = v
		}
	}

	// Deep copy types.DeferredTransfers slice
	if ctx.DeferredTransfers != nil {
		contextCheckpoint.DeferredTransfers = make([]types.DeferredTransfer, len(ctx.DeferredTransfers))
		for i, transfer := range ctx.DeferredTransfers {
			contextCheckpoint.DeferredTransfers[i] = transfer.DeepCopy()
		}
	}

	// Deep copy PreimageResult if not nil
	if ctx.PreimageResult != nil {
		preimageResult := new([32]byte)
		*preimageResult = *ctx.PreimageResult
		contextCheckpoint.PreimageResult = preimageResult
	}

	return contextCheckpoint
}

func AccumulationResultContextFromAccumulationStateComponents(tx *staterepository.TrackedTx, stateComponents *AccumulationStateComponents, serviceAccount *serviceaccount.ServiceAccount, timeslot types.Timeslot, posteriorEntropyAccumulator [4][32]byte) *AccumulationResultContext {
	hash := blake2b.Sum256(serializer.Serialize(struct {
		ServiceIndex types.GenericNum
		Entropy      [32]byte
		Timeslot     types.GenericNum
	}{
		ServiceIndex: types.GenericNum(serviceAccount.ServiceIndex),
		Entropy:      posteriorEntropyAccumulator[0],
		Timeslot:     types.GenericNum(timeslot),
	}))
	derivedServiceIndex, err := check(tx, types.ServiceIndex(constants.MinPublicServiceIndex+serializer.DecodeLittleEndian(hash[:4])%(1<<32-constants.MinPublicServiceIndex-1<<8)))
	if err != nil {
		return nil
	}
	// Create a copy of the service account to ensure independence between contexts
	serviceAccountCopy := *serviceAccount
	return &AccumulationResultContext{
		AccumulatingServiceAccount: &serviceAccountCopy,
		StateComponents:            stateComponents.DeepCopy(),
		DerivedServiceIndex:        derivedServiceIndex,
		DeferredTransfers:          []types.DeferredTransfer{},
		PreimageResult:             nil,
		PreimageProvisions:         PreimageProvisions{},
		Tx:                         tx.DeepCopy(),
	}
}

// U
type AccumulationStateComponents struct {
	UpcomingValidatorKeysets [constants.NumValidators]types.ValidatorKeyset                // i
	AuthorizersQueue         [constants.NumCores][constants.AuthorizerQueueLength][32]byte // q
	PrivilegedServices       types.PrivilegedServices                                      // x
}

func (u *AccumulationStateComponents) DeepCopy() *AccumulationStateComponents {
	// Create a new struct to hold the copied data
	copy := &AccumulationStateComponents{
		UpcomingValidatorKeysets: u.UpcomingValidatorKeysets,
		AuthorizersQueue:         u.AuthorizersQueue,
		PrivilegedServices:       u.PrivilegedServices, // Copy the struct
	}

	// Deep copy the map inside PrivilegedServices if it exists
	if u.PrivilegedServices.AlwaysAccumulateServicesWithGas != nil {
		copy.PrivilegedServices.AlwaysAccumulateServicesWithGas = make(map[types.ServiceIndex]types.GasValue)
		maps.Copy(copy.PrivilegedServices.AlwaysAccumulateServicesWithGas, u.PrivilegedServices.AlwaysAccumulateServicesWithGas)
	}

	return copy
}

type AccumulateInvocationContext struct {
	AccumulationResultContext            AccumulationResultContext // x
	ExceptionalAccumulationResultContext AccumulationResultContext // y
}

type AccumulateHostFunction = HostFunction[AccumulateInvocationContext]

func Accumulate(tx *staterepository.TrackedTx, accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, serviceIndex types.ServiceIndex, gas types.GasValue, accumulationInputs []types.AccumulationInput, posteriorEntropyAccumulator [4][32]byte) (*AccumulationStateComponents, []types.DeferredTransfer, *[32]byte, types.GasValue, PreimageProvisions, error) {
	var hf AccumulateHostFunction = func(n HostFunctionIdentifier, ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		switch n {
		case ReadID:
			return Read(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulationResultContext.Tx, ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount, ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex)
		case WriteID:
			return Write(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulationResultContext.Tx, ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount)
		case LookupID:
			return Lookup(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			}, ctx.Argument.AccumulationResultContext.Tx, ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount)
		case GasID:
			return Gas(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		case FetchID:
			return Fetch(ctx, nil, &posteriorEntropyAccumulator[0], nil, nil, nil, nil, &accumulationInputs)
		case InfoID:
			return Info(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{}}, ctx.Argument.AccumulationResultContext.Tx, ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount)
		case BlessID:
			return Bless(ctx)
		case AssignID:
			return Assign(ctx)
		case DesignateID:
			return Designate(ctx)
		case CheckpointID:
			return Checkpoint(ctx)
		case NewID:
			return New(ctx, ctx.Argument.AccumulationResultContext.Tx, timeslot)
		case UpgradeID:
			return Upgrade(ctx)
		case TransferID:
			return Transfer(ctx)
		case EjectID:
			return Eject(ctx, ctx.Argument.AccumulationResultContext.Tx, timeslot)
		case QueryID:
			return Query(ctx, ctx.Argument.AccumulationResultContext.Tx)
		case SolicitID:
			return Solicit(ctx, ctx.Argument.AccumulationResultContext.Tx, timeslot)
		case ForgetID:
			return Forget(ctx, ctx.Argument.AccumulationResultContext.Tx, timeslot)
		case YieldID:
			return Yield(ctx)
		case ProvideID:
			return Provide(ctx, ctx.Argument.AccumulationResultContext.Tx)
		case LogID:
			return Log(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		default:
			return Default(&HostFunctionContext[struct{}]{
				State:    ctx.State,
				Argument: &struct{}{},
			})
		}
	}
	serviceAccount, exists, err := serviceaccount.GetServiceAccount(tx, serviceIndex)
	if err != nil {
		return &AccumulationStateComponents{}, []types.DeferredTransfer{}, nil, 0, PreimageProvisions{}, err
	}
	if !exists {
		return accumulationStateComponents, []types.DeferredTransfer{}, nil, 0, PreimageProvisions{}, nil
	}
	// Transfer the balances to the service account
	for _, accumulationInput := range accumulationInputs {
		if accumulationInput.IsDeferredTransfer() {
			serviceAccount.Balance += types.Balance(accumulationInput.DeferredTransfer.BalanceTransfer)
		}
	}
	_, code, err := serviceAccount.MetadataAndCode(tx)
	if err != nil {
		return &AccumulationStateComponents{}, []types.DeferredTransfer{}, nil, 0, PreimageProvisions{}, err
	}
	if code == nil || len(*code) > int(constants.ServiceCodeMaxSize) {
		serviceaccount.SetServiceAccount(tx, serviceAccount)
		return accumulationStateComponents, []types.DeferredTransfer{}, nil, 0, PreimageProvisions{}, nil
	}
	// Create two separate context objects with independent child transactions
	normalContext := AccumulationResultContextFromAccumulationStateComponents(tx, accumulationStateComponents, serviceAccount, timeslot, posteriorEntropyAccumulator)
	exceptionalContext := normalContext.DeepCopy()
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
		OperandTuplesLen: types.GenericNum(len(accumulationInputs)),
	})
	executionExitReason, gasUsed, err := RunWithArgs(*code, 5, gas, serializedArguments, hf, &ctx)
	if err != nil {
		return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed, ctx.ExceptionalAccumulationResultContext.PreimageProvisions, err
	}
	if executionExitReason.IsError() {
		if err := tx.ReplaceMemoryWith(ctx.ExceptionalAccumulationResultContext.Tx); err != nil {
			return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed, ctx.ExceptionalAccumulationResultContext.PreimageProvisions, err
		}
		serviceaccount.SetServiceAccount(tx, ctx.ExceptionalAccumulationResultContext.AccumulatingServiceAccount)
		return ctx.ExceptionalAccumulationResultContext.StateComponents, ctx.ExceptionalAccumulationResultContext.DeferredTransfers, ctx.ExceptionalAccumulationResultContext.PreimageResult, gasUsed, ctx.ExceptionalAccumulationResultContext.PreimageProvisions, nil
	}

	// Success - apply changes to outer batch (merges changes into parent transaction)
	if err := tx.ReplaceMemoryWith(ctx.AccumulationResultContext.Tx); err != nil {
		return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, ctx.AccumulationResultContext.PreimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, fmt.Errorf("failed to apply nested batch: %w", err)
	}

	serviceaccount.SetServiceAccount(tx, ctx.AccumulationResultContext.AccumulatingServiceAccount)

	blob := *executionExitReason.Blob
	if len(blob) == 32 {
		var preimageResult [32]byte
		copy(preimageResult[:], blob)
		return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, &preimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, nil
	}
	return ctx.AccumulationResultContext.StateComponents, ctx.AccumulationResultContext.DeferredTransfers, ctx.AccumulationResultContext.PreimageResult, gasUsed, ctx.AccumulationResultContext.PreimageProvisions, nil
}
