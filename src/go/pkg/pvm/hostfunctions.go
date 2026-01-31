package pvm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/historicallookup"
	"jam/pkg/serializer"
	"jam/pkg/serviceaccount"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/util"
	wp "jam/pkg/workpackage"

	"golang.org/x/crypto/blake2b"
)

type HostFunctionIdentifier int

const (
	GasID HostFunctionIdentifier = iota
	FetchID
	LookupID
	ReadID
	WriteID
	InfoID
	HistoricalLookupID
	ExportID
	MachineID
	PeekID
	PokeID
	PagesID
	InvokeID
	ExpungeID
	BlessID
	AssignID
	DesignateID
	CheckpointID
	NewID
	UpgradeID
	TransferID
	EjectID
	QueryID
	SolicitID
	ForgetID
	YieldID
	ProvideID
)

func (h HostFunctionIdentifier) String() string {
	switch h {
	case GasID:
		return "Gas"
	case FetchID:
		return "Fetch"
	case LookupID:
		return "Lookup"
	case ReadID:
		return "Read"
	case WriteID:
		return "Write"
	case InfoID:
		return "Info"
	case HistoricalLookupID:
		return "HistoricalLookup"
	case ExportID:
		return "Export"
	case MachineID:
		return "Machine"
	case PeekID:
		return "Peek"
	case PokeID:
		return "Poke"
	case PagesID:
		return "Pages"
	case InvokeID:
		return "Invoke"
	case ExpungeID:
		return "Expunge"
	case BlessID:
		return "Bless"
	case AssignID:
		return "Assign"
	case DesignateID:
		return "Designate"
	case CheckpointID:
		return "Checkpoint"
	case NewID:
		return "New"
	case UpgradeID:
		return "Upgrade"
	case TransferID:
		return "Transfer"
	case EjectID:
		return "Eject"
	case QueryID:
		return "Query"
	case SolicitID:
		return "Solicit"
	case ForgetID:
		return "Forget"
	case YieldID:
		return "Yield"
	case ProvideID:
		return "Provide"
	default:
		return fmt.Sprintf("Unknown(%d)", h)
	}
}

type ExitReasonType uint64

const maxUint64 = ^uint64(0)

const (
	// OK indicates general success.
	HostCallOK   ExitReasonType = 0
	HostCallNone ExitReasonType = ExitReasonType(maxUint64 - 0) // 2^64 - 1: The item does not exist.
	HostCallWhat ExitReasonType = ExitReasonType(maxUint64 - 1) // 2^64 - 2: Name unknown.
	HostCallOOB  ExitReasonType = ExitReasonType(maxUint64 - 2) // 2^64 - 3: Memory index not accessible.
	HostCallWho  ExitReasonType = ExitReasonType(maxUint64 - 3) // 2^64 - 4: Index unknown.
	HostCallFull ExitReasonType = ExitReasonType(maxUint64 - 4) // 2^64 - 5: Storage full.
	HostCallCore ExitReasonType = ExitReasonType(maxUint64 - 5) // 2^64 - 6: Core index unknown.
	HostCallCash ExitReasonType = ExitReasonType(maxUint64 - 6) // 2^64 - 7: Insufficient funds.
	HostCallLow  ExitReasonType = ExitReasonType(maxUint64 - 7) // 2^64 - 8: Gas limit too low.
	HostCallHuh  ExitReasonType = ExitReasonType(maxUint64 - 8) // 2^64 - 9: Already solicited or cannot be forgotten.
)

func IsValidHostCallError(code ExitReasonType) bool {
	const reservedThreshold = ^uint64(0) - 12 // 2^64 - 13
	return code != 0 && uint64(code) < reservedThreshold
}

// InnerInvocationResult represents the result of an inner PVM invocation.
type InnerInvocationResult int

const (
	InnerHalt  InnerInvocationResult = 0 // The invocation completed and halted normally.
	InnerPanic InnerInvocationResult = 1 // The invocation completed with a panic.
	InnerFault InnerInvocationResult = 2 // The invocation completed with a page fault.
	InnerHost  InnerInvocationResult = 3 // The invocation completed with a host-call fault.
	InnerOOG   InnerInvocationResult = 4 // The invocation completed by running out of gas.
)

type HostFunction[T any] func(HostFunctionIdentifier, *HostFunctionContext[T]) (ExitReason, error)

const GasUsage types.GasValue = 10

func Gas(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		ctx.State.Registers[7] = types.Register(ctx.State.Gas)
		return ExitReasonGo, nil
	})
}

func Default(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		ctx.State.Registers[7] = types.Register(HostCallWhat)
		return ExitReasonGo, nil
	})
}

// VerifyAndReturnStateForAccessor implements the state lookup host function
// as specified in the graypaper. It verifies access, computes a key hash,
// and returns data from state if available.
func Read(ctx *HostFunctionContext[struct{}], tx *staterepository.TrackedTx, serviceAccount *serviceaccount.ServiceAccount, serviceIndex types.ServiceIndex) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {

		// Determine s* based on reg7
		var sStar types.Register
		if ctx.State.Registers[7] == types.Register(^uint64(0)) { // 2^64 - 1
			sStar = types.Register(serviceIndex)
		} else {
			sStar = ctx.State.Registers[7]
		}

		// Determine 'a' based on s*
		var a *serviceaccount.ServiceAccount
		if sStar == types.Register(serviceIndex) {
			// a = s
			a = serviceAccount
		} else if sStar <= types.Register(^uint32(0)) {
			// Check if sStar can fit in uint32 range
			serviceAcc, ok, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(sStar))
			if err != nil {
				return ExitReason{}, err
			}
			if ok {
				a = serviceAcc
			}
		}

		ko := ctx.State.Registers[8] // Key offset
		kz := ctx.State.Registers[9] // Key length
		o := ctx.State.Registers[10] // Output offset

		keyBytes := ctx.State.RAM.InspectRangeSafe(uint64(ko), uint64(kz))
		if keyBytes == nil {
			return ExitReasonPanic, nil
		}

		// Determine 'v'
		var preImage []byte

		if a != nil {
			// Look up in state if available
			val, ok, err := a.GetServiceStorageItem(tx, keyBytes)
			if err != nil {
				return ExitReason{}, err
			}
			if ok {
				preImage = []byte(val)
			}
		}

		f := min(ctx.State.Registers[11], types.Register(len(preImage)))
		l := min(ctx.State.Registers[12], types.Register(len(preImage))-f)

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(len(preImage))
			if ok := ctx.State.RAM.MutateRangeSafe(uint64(o), uint64(l), func(dest []byte) {
				copy(dest, preImage[int(f):int(f+l)])
			}); !ok {
				return ExitReasonPanic, nil
			}
		}

		return ExitReasonGo, nil
	})
}

func Write(ctx *HostFunctionContext[struct{}], tx *staterepository.TrackedTx, serviceAccount *serviceaccount.ServiceAccount) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		ko := ctx.State.Registers[7]  // Key offset
		kz := ctx.State.Registers[8]  // Key length
		vo := ctx.State.Registers[9]  // Value offset
		vz := ctx.State.Registers[10] // Value length

		keyBytes := ctx.State.RAM.InspectRangeSafe(uint64(ko), uint64(kz))
		if keyBytes == nil {
			return ExitReasonPanic, nil
		}

		// Determine 'l' - length of previous value if it exists, NONE otherwise
		var l types.Register
		oldValue, ok, err := serviceAccount.GetServiceStorageItem(tx, keyBytes)
		if err != nil {
			return ExitReason{}, err
		}
		if ok {
			l = types.Register(len(oldValue))
		} else {
			l = types.Register(HostCallNone)
		}

		// Handle according to vz (value length)
		if vz == 0 {
			// If vz = 0, remove entry
			if err := serviceAccount.DeleteServiceStorageItem(tx, keyBytes); err != nil {
				return ExitReason{}, err
			}
		} else {
			// Write the value to the account storage
			valueBytes := ctx.State.RAM.InspectRangeSafe(uint64(vo), uint64(vz))
			if valueBytes == nil {
				return ExitReasonPanic, nil
			}
			// IMPORTANT: make sure to copy because valueBytes is an alias to page memory which is cleared later
			valueCopy := make([]byte, len(valueBytes))
			copy(valueCopy, valueBytes)
			if err := serviceAccount.SetServiceStorageItem(tx, keyBytes, valueCopy); err != nil {
				return ExitReason{}, err
			}
		}

		if serviceAccount.ThresholdBalanceNeeded() > serviceAccount.Balance {
			if !ok {
				if err := serviceAccount.DeleteServiceStorageItem(tx, keyBytes); err != nil {
					return ExitReason{}, err
				}
			} else {
				if err := serviceAccount.SetServiceStorageItem(tx, keyBytes, oldValue); err != nil {
					return ExitReason{}, err
				}
			}
			ctx.State.Registers[7] = types.Register(HostCallFull)
		} else {
			ctx.State.Registers[7] = l
		}

		return ExitReasonGo, nil
	})
}

// AccountInfo represents the structured account information for serialization
type AccountInfo struct {
	CodeHash                       [32]byte           // c
	Balance                        types.Balance      // b
	ThresholdBalanceNeeded         types.Balance      // t
	MinimumGasForAccumulate        types.GasValue     // g
	MinimumGasForOnTransfer        types.GasValue     // m
	TotalOctetsUsedInStorage       uint64             // o
	StorageItems                   uint32             // i
	GratisStorageOffset            types.Balance      // f
	CreatedTimeSlot                types.Timeslot     // r
	MostRecentAccumulationTimeslot types.Timeslot     // a
	ParentServiceIndex             types.ServiceIndex // p
}

func Info(ctx *HostFunctionContext[struct{}], tx *staterepository.TrackedTx, serviceAccount *serviceaccount.ServiceAccount) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		// Determine the target service account (t)
		var targetAccount *serviceaccount.ServiceAccount

		// If reg7 = 2^64 - 1, use service account parameter, otherwise lookup by index
		if ctx.State.Registers[7] == types.Register(^uint64(0)) {
			targetAccount = serviceAccount
		} else if ctx.State.Registers[7] <= types.Register(^uint32(0)) {
			// Check if reg7 can fit in uint32 range
			account, ok, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(ctx.State.Registers[7]))
			if err != nil {
				return ExitReason{}, err
			}
			if ok {
				targetAccount = account
			}
		}

		// Get output offset (o) from reg8
		outputOffset := ctx.State.Registers[8]

		var v []byte

		// If target account exists, encode its information
		if targetAccount != nil {
			// Create struct with account information
			accountInfo := AccountInfo{
				CodeHash:                       targetAccount.CodeHash,
				Balance:                        targetAccount.Balance,
				ThresholdBalanceNeeded:         targetAccount.ThresholdBalanceNeeded(),
				MinimumGasForAccumulate:        targetAccount.MinimumGasForAccumulate,
				MinimumGasForOnTransfer:        targetAccount.MinimumGasForOnTransfer,
				TotalOctetsUsedInStorage:       targetAccount.TotalOctetsUsedInStorage,
				StorageItems:                   targetAccount.TotalItemsUsedInStorage,
				GratisStorageOffset:            targetAccount.GratisStorageOffset,
				CreatedTimeSlot:                targetAccount.CreatedTimeSlot,
				MostRecentAccumulationTimeslot: targetAccount.MostRecentAccumulationTimeslot,
				ParentServiceIndex:             targetAccount.ParentServiceIndex,
			}

			// Serialize the account information
			v = serializer.Serialize(accountInfo)

		}

		f := min(ctx.State.Registers[9], types.Register(len(v)))
		l := min(ctx.State.Registers[10], types.Register(len(v))-f)

		// Write to memory
		if ok := ctx.State.RAM.MutateRangeSafe(uint64(outputOffset), uint64(l), func(dest []byte) {
			copy(dest, v[int(f):int(f+l)])
		}); !ok {
			return ExitReasonPanic, nil
		}

		if v == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
			return ExitReasonGo, nil
		}

		// Set successful result
		ctx.State.Registers[7] = types.Register(len(v))
		return ExitReasonGo, nil
	})
}

func Bless(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		mainIndex := ctx.State.Registers[7]         // m - Main service index
		authIndicesOffset := ctx.State.Registers[8] // a - Authorization service index
		validIndex := ctx.State.Registers[9]        // v - Validation service index
		registrarIndex := ctx.State.Registers[10]   // r - Registrar service index
		offset := ctx.State.Registers[11]           // o - Memory offset
		numEntries := ctx.State.Registers[12]       // n - Number of entries

		// Check if memory range is accessible
		entrySize := uint64(12) // Each entry is 12 bytes (4 for service index, 8 for gas value)

		// Create gas mapping g
		serviceGasMap := make(map[types.ServiceIndex]types.GasValue)

		// Read service-to-gas mappings from memory
		for i := uint64(0); i < uint64(numEntries); i++ {
			// Read service index (4 bytes) and gas value (8 bytes)
			entryOffset := uint64(offset) + i*entrySize

			// Get service index from memory
			serviceBytes := ctx.State.RAM.InspectRangeSafe(entryOffset, 4)
			if serviceBytes == nil {
				return ExitReasonPanic, nil
			}
			serviceIndex := types.ServiceIndex(serializer.DecodeLittleEndian(serviceBytes))

			// Get gas value from memory
			gasBytes := ctx.State.RAM.InspectRangeSafe(entryOffset+4, 8)
			if gasBytes == nil {
				return ExitReasonPanic, nil
			}
			gasValue := types.GasValue(serializer.DecodeLittleEndian(gasBytes))

			// Add to mapping
			serviceGasMap[serviceIndex] = gasValue
		}

		assignIndices := [constants.NumCores]types.ServiceIndex{}
		for i := uint64(0); i < uint64(constants.NumCores); i++ {
			entryOffset := uint64(authIndicesOffset) + i*4
			assignIndicesBytes := ctx.State.RAM.InspectRangeSafe(entryOffset, 4)
			if assignIndicesBytes == nil {
				return ExitReasonPanic, nil
			}
			assignIndices[i] = types.ServiceIndex(serializer.DecodeLittleEndian(assignIndicesBytes))
		}

		if mainIndex > types.Register(^uint32(0)) || validIndex > types.Register(^uint32(0)) || registrarIndex > types.Register(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		// Update the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices = types.PrivilegedServices{
			ManagerServiceIndex:             types.ServiceIndex(mainIndex),
			AssignServiceIndices:            assignIndices,
			DesignateServiceIndex:           types.ServiceIndex(validIndex),
			RegistrarServiceIndex:           types.ServiceIndex(registrarIndex),
			AlwaysAccumulateServicesWithGas: serviceGasMap,
		}
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Assign(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		// Get core index from reg7 and memory offset from reg8
		coreIndex := ctx.State.Registers[7]
		offset := ctx.State.Registers[8]
		assignServiceIndex := ctx.State.Registers[9]

		// Calculate the size of the authorizersQueue array
		queueLength := constants.AuthorizerQueueLength

		// Read the queue of authorizer hashes from memory
		authorizerQueue := [constants.AuthorizerQueueLength][32]byte{}
		for i := range queueLength {
			hashOffset := uint64(offset) + uint64(i)*32
			hashBytes := ctx.State.RAM.InspectRangeSafe(hashOffset, 32)
			if hashBytes == nil {
				return ExitReasonPanic, nil
			}

			// Copy the hash bytes to the authorizer queue
			copy(authorizerQueue[i][:], hashBytes)
		}

		// Check if core index is within valid range
		if coreIndex >= types.Register(constants.NumCores) {
			ctx.State.Registers[7] = types.Register(HostCallCore)
			return ExitReasonGo, nil
		}

		if ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.AssignServiceIndices[coreIndex] {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		if assignServiceIndex > types.Register(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		// Update the authorizer queue in the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.AuthorizersQueue[coreIndex] = authorizerQueue

		ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.AssignServiceIndices[coreIndex] = types.ServiceIndex(assignServiceIndex)

		// Set successful result
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Designate(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		// Get memory offset from reg7
		offset := ctx.State.Registers[7]

		// Read the validator keysets from memory
		validatorKeysets := [constants.NumValidators]types.ValidatorKeyset{}
		for i := 0; i < int(constants.NumValidators); i++ {
			keysetOffset := uint64(offset) + uint64(i)*336
			keysetBytes := ctx.State.RAM.InspectRangeSafe(keysetOffset, 336)
			if keysetBytes == nil {
				return ExitReasonPanic, nil
			}

			// Copy the keyset bytes
			copy(validatorKeysets[i][:], keysetBytes)
		}

		if ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.DesignateServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		// Update the validator keysets in the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.UpcomingValidatorKeysets = validatorKeysets

		// Set successful result
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Checkpoint(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		ctx.Argument.ExceptionalAccumulationResultContext = *ctx.Argument.AccumulationResultContext.DeepCopy()
		ctx.State.Registers[7] = types.Register(ctx.State.Gas)
		return ExitReasonGo, nil
	})
}

func New(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx, timeslot types.Timeslot) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		offset := ctx.State.Registers[7]               // o - memory offset for code hash
		labelLength := ctx.State.Registers[8]          // l - label length
		minGasForAccumulate := ctx.State.Registers[9]  // g - minimum gas for accumulate
		minGasForOnTransfer := ctx.State.Registers[10] // m - minimum gas for on transfer
		gratisStorageOffset := ctx.State.Registers[11] // f - gratis storage offset
		desiredID := ctx.State.Registers[12]           // d - desired ID

		// Read code hash from memory
		codeHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(offset), 32)
		if codeHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var codeHash [32]byte
		copy(codeHash[:], codeHashBytes)

		if gratisStorageOffset != types.Register(0) && ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.ManagerServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		// Create new service account
		newAccount := &serviceaccount.ServiceAccount{
			ServiceAccountData: serviceaccount.ServiceAccountData{
				Version:                        0,
				CodeHash:                       codeHash,
				MinimumGasForAccumulate:        types.GasValue(minGasForAccumulate),
				MinimumGasForOnTransfer:        types.GasValue(minGasForOnTransfer),
				GratisStorageOffset:            types.Balance(gratisStorageOffset),
				CreatedTimeSlot:                timeslot,
				MostRecentAccumulationTimeslot: 0,
				ParentServiceIndex:             ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex,
			},
		}

		// Kind of ugly, but we need to simulate what the threshold balance needed WOULD be if we set the historical status
		// Dont actually set it til we definitely want to add the new account to the state
		newAccount.TotalItemsUsedInStorage += 2
		newAccount.TotalOctetsUsedInStorage += 81 + uint64(labelLength)
		newAccount.Balance = newAccount.ThresholdBalanceNeeded()
		newAccount.TotalItemsUsedInStorage -= 2
		newAccount.TotalOctetsUsedInStorage -= 81 + uint64(labelLength)

		accumulatingServiceAccount := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount
		// Check if source has enough balance after the transfer (sb < (xs)t check)
		// The source account needs enough balance to cover both:
		// 1. Its own threshold balance needs
		// 2. The transfer amount to the new account
		// Prevent underflow by checking balance is sufficient before subtraction
		if accumulatingServiceAccount.Balance < newAccount.Balance || accumulatingServiceAccount.Balance-newAccount.Balance < accumulatingServiceAccount.ThresholdBalanceNeeded() {
			ctx.State.Registers[7] = types.Register(HostCallCash)
			return ExitReasonGo, nil
		}

		// Helper function to finalize new service account creation
		finalizeNewAccount := func(serviceIndex types.ServiceIndex) (ExitReason, error) {
			newAccount.ServiceIndex = serviceIndex
			if err := newAccount.SetPreimageLookupHistoricalStatus(tx, uint32(labelLength), codeHash, []types.Timeslot{}); err != nil {
				return ExitReason{}, err
			}
			serviceaccount.SetServiceAccount(tx, newAccount)
			accumulatingServiceAccount.UpdateBalance(tx, accumulatingServiceAccount.Balance-newAccount.Balance)
			ctx.State.Registers[7] = types.Register(serviceIndex)
			ctx.Argument.AccumulationResultContext.NewServices[serviceIndex] = struct{}{}
			return ExitReasonGo, nil
		}

		// Check if registrar service is creating an account with desired ID
		if accumulatingServiceAccount.ServiceIndex == ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.RegistrarServiceIndex && uint64(desiredID) < constants.MinPublicServiceIndex {
			if _, exists, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(desiredID)); err != nil {
				return ExitReason{}, err
			} else if exists {
				ctx.State.Registers[7] = types.Register(HostCallFull)
				return ExitReasonGo, nil
			} else {
				return finalizeNewAccount(types.ServiceIndex(desiredID))
			}
		}

		// Normal path: use derived service index
		exitReason, err := finalizeNewAccount(ctx.Argument.AccumulationResultContext.DerivedServiceIndex)
		if err != nil {
			return ExitReason{}, err
		}
		ctx.Argument.AccumulationResultContext.DerivedServiceIndex = types.ServiceIndex(constants.MinPublicServiceIndex + (uint64(newAccount.ServiceIndex)-constants.MinPublicServiceIndex+42)%(1<<32-constants.MinPublicServiceIndex-1<<8))
		return exitReason, nil
	})
}

func Upgrade(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		offset := ctx.State.Registers[7]              // o - memory offset for code hash
		minGasForAccumulate := ctx.State.Registers[8] // g - minimum gas for accumulate
		minGasForOnTransfer := ctx.State.Registers[9] // m - minimum gas for on transfer

		codeHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(offset), 32)
		if codeHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var codeHash [32]byte
		copy(codeHash[:], codeHashBytes)

		// Get the accumulating service account
		accumulatingServiceAccount := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount

		// Update the service account with new values
		accumulatingServiceAccount.CodeHash = codeHash
		accumulatingServiceAccount.MinimumGasForAccumulate = types.GasValue(minGasForAccumulate)
		accumulatingServiceAccount.MinimumGasForOnTransfer = types.GasValue(minGasForOnTransfer)

		serviceaccount.SetServiceAccount(ctx.Argument.AccumulationResultContext.Tx, accumulatingServiceAccount)

		// Set return status to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Transfer(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		destServiceIndex := types.ServiceIndex(ctx.State.Registers[7]) // d - destination service index
		amount := types.Balance(ctx.State.Registers[8])                // a - amount to transfer
		gasLimit := types.GasValue(ctx.State.Registers[9])             // l - gas limit
		memoOffset := ctx.State.Registers[10]                          // o - memo offset

		memoBytes := ctx.State.RAM.InspectRangeSafe(uint64(memoOffset), uint64(constants.TransferMemoSize))
		if memoBytes == nil {
			return ExitReasonPanic, nil
		}
		var memo [constants.TransferMemoSize]byte
		copy(memo[:], memoBytes)

		// 2. Check if destination exists in service accounts
		destinationAccount, destinationExists, err := serviceaccount.GetServiceAccount(ctx.Argument.AccumulationResultContext.Tx, destServiceIndex)
		if err != nil {
			return ExitReason{}, err
		}
		if !destinationExists {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		if gasLimit < destinationAccount.MinimumGasForOnTransfer {
			ctx.State.Registers[7] = types.Register(HostCallLow)
			return ExitReasonGo, nil
		}

		// Get source account
		sourceAccount := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount

		// Check if source has enough balance (prevent underflow and ensure threshold is met)
		if sourceAccount.Balance < amount || sourceAccount.Balance-amount < sourceAccount.ThresholdBalanceNeeded() {
			ctx.State.Registers[7] = types.Register(HostCallCash)
			return ExitReasonGo, nil
		}

		// Check if we still have enough gas to cover the transfer
		if types.GasValue(ctx.State.Gas) < gasLimit {
			ctx.State.Gas = 0
			return ExitReasonOutOfGas, nil
		}
		ctx.State.Gas -= types.SignedGasValue(gasLimit)

		// Create transfer object
		transfer := types.DeferredTransfer{
			SenderServiceIndex:   ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex,
			ReceiverServiceIndex: destServiceIndex,
			BalanceTransfer:      amount,
			Memo:                 memo,
			GasLimit:             gasLimit,
		}

		// Update source account balance
		sourceAccount.UpdateBalance(ctx.Argument.AccumulationResultContext.Tx, sourceAccount.Balance-amount)

		// Append transfer to deferred transfers list
		ctx.Argument.AccumulationResultContext.DeferredTransfers = append(
			ctx.Argument.AccumulationResultContext.DeferredTransfers,
			transfer)

		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Eject(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx, timeslot types.Timeslot) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		destServiceIndex := types.ServiceIndex(ctx.State.Registers[7]) // d - destination service index
		hashOffset := ctx.State.Registers[8]                           // o - hash offset

		hashBytes := ctx.State.RAM.InspectRangeSafe(uint64(hashOffset), 32)
		if hashBytes == nil {
			return ExitReasonPanic, nil
		}
		var hash [32]byte
		copy(hash[:], hashBytes)

		// Get service accounts and the accumulating account
		accumulatingServiceAccount := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount

		// 2. Check destination account exists and matches code hash
		if destServiceIndex == accumulatingServiceAccount.ServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		destinationAccount, destinationExists, err := serviceaccount.GetServiceAccount(ctx.Argument.AccumulationResultContext.Tx, destServiceIndex)
		if err != nil {
			return ExitReason{}, err
		}
		if !destinationExists {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		if !bytes.Equal(destinationAccount.CodeHash[:], serializer.EncodeLittleEndian(32, uint64(accumulatingServiceAccount.ServiceIndex))) {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		if destinationAccount.TotalItemsUsedInStorage != 2 {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		length := max(81, destinationAccount.TotalOctetsUsedInStorage) - 81

		historicalStatus, exists, err := destinationAccount.GetPreimageLookupHistoricalStatus(tx, uint32(length), hash)
		if err != nil {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReason{}, err
		}
		if !exists || length > uint64(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		// Get the most recent timeslot in the historical status
		if len(historicalStatus) == 2 {
			// Check the expiration of the most recent timeslot against the current time
			// Using UnreferencePreimageExpungeTimeslots as D from the specification
			lastTimeslot := historicalStatus[1]
			expungeTimeslots := types.Timeslot(constants.UnreferencePreimageExpungeTimeslots)
			var cutoffTime types.Timeslot
			if timeslot >= expungeTimeslots {
				cutoffTime = timeslot - expungeTimeslots
			} else {
				cutoffTime = 0 // If timeslot is too small, use 0 as cutoff
			}
			if lastTimeslot < cutoffTime {
				// Update accumulating account balance
				accumulatingServiceAccount.UpdateBalance(tx, accumulatingServiceAccount.Balance+destinationAccount.Balance)

				// IMPORTANT: actually delete the service account and preimage from state as well
				if err := destinationAccount.DeletePreimageLookupHistoricalStatus(tx, uint32(length), hash); err != nil {
					return ExitReason{}, err
				}
				destinationAccount.DeletePreimageForHash(tx, hash)

				// Remove the entry from destination account
				serviceaccount.DeleteServiceAccount(tx, destServiceIndex)
				ctx.Argument.AccumulationResultContext.DeletedServices[destServiceIndex] = struct{}{}

				// Set status to OK
				ctx.State.Registers[7] = types.Register(HostCallOK)
				return ExitReasonGo, nil
			}
		}
		// Entry not expired
		ctx.State.Registers[7] = types.Register(HostCallHuh)
		return ExitReasonGo, nil
	})
}

func Query(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // Length/Value

		// Get the 32-byte key hash from memory
		keyHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(o), 32)
		if keyHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var keyHash [32]byte
		copy(keyHash[:], keyHashBytes)

		historicalStatus, ok, err := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.GetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash)
		if err != nil {
			return ExitReason{}, err
		}

		if !ok || z > types.Register(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallNone)
			ctx.State.Registers[8] = 0
			return ExitReasonGo, nil
		}

		// Set result registers based on list content according to the spec
		if len(historicalStatus) == 0 {
			ctx.State.Registers[7] = 0
			ctx.State.Registers[8] = 0
		} else if len(historicalStatus) == 1 {
			ctx.State.Registers[7] = 1 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = 0
		} else if len(historicalStatus) == 2 {
			ctx.State.Registers[7] = 2 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = types.Register(historicalStatus[1])
		} else if len(historicalStatus) == 3 {
			ctx.State.Registers[7] = 3 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = types.Register(historicalStatus[1]) + (types.Register(historicalStatus[2]) << 32)
		} else {
			panic(fmt.Sprintf("unreachable: impossible historical status length %v", len(historicalStatus)))
		}

		return ExitReasonGo, nil
	})
}

func Solicit(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx, timeslot types.Timeslot) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // BlobLength

		// Get the 32-byte key hash from memory
		keyHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(o), 32)
		if keyHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var keyHash [32]byte
		copy(keyHash[:], keyHashBytes)

		// Get the accumulating service account (xs)
		serviceAccount := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount

		// Check if the key exists in the historical status map
		originalStatus, originalExists, err := serviceAccount.GetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash)
		if err != nil {
			return ExitReason{}, err
		}

		// Make the changes directly to the service account
		if !originalExists || z > types.Register(^uint32(0)) {
			if err := serviceAccount.SetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash, []types.Timeslot{}); err != nil {
				return ExitReason{}, err
			}
		} else if len(originalStatus) == 2 {
			if err := serviceAccount.SetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash, append(originalStatus, timeslot)); err != nil {
				return ExitReason{}, err
			}
		} else {
			// Key exists but doesn't have exactly two elements
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		// Check if we've exceeded storage limits
		if serviceAccount.Balance < serviceAccount.ThresholdBalanceNeeded() {
			// Revert the changes
			if !originalExists {
				if err := serviceAccount.DeletePreimageLookupHistoricalStatus(tx, uint32(z), keyHash); err != nil {
					return ExitReason{}, err
				}
			} else {
				if err := serviceAccount.SetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash, originalStatus); err != nil {
					return ExitReason{}, err
				}
			}
			ctx.State.Registers[7] = types.Register(HostCallFull)
			return ExitReasonGo, nil
		}

		ctx.State.Registers[7] = types.Register(HostCallOK)
		return ExitReasonGo, nil
	})
}

func Forget(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx, timeslot types.Timeslot) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // BlobLength

		// Get the 32-byte key hash from memory
		keyHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(o), 32)
		if keyHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var keyHash [32]byte
		copy(keyHash[:], keyHashBytes)

		// Get the accumulating service account
		xs := ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount

		// Check if the key exists in the historical status map
		historicalStatus, exists, err := xs.GetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash)
		if err != nil {
			return ExitReason{}, err
		}
		if !exists || z > types.Register(^uint32(0)) {
			// Key doesn't exist, return HUH
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		// Define cutoff time for "old enough" timeslots
		// Check for underflow before subtraction
		var cutoffTime types.Timeslot
		expungeTimeslots := types.Timeslot(constants.UnreferencePreimageExpungeTimeslots)
		if timeslot >= expungeTimeslots {
			cutoffTime = timeslot - expungeTimeslots
		} else {
			cutoffTime = 0 // If timeslot is too small, use 0 as cutoff
		}

		// Handle different cases based on historical status length and values
		if len(historicalStatus) == 0 || (len(historicalStatus) == 2 && historicalStatus[1] < cutoffTime) {
			// Remove the key if status is [] or [x, y] with y < t - D
			if err := xs.DeletePreimageLookupHistoricalStatus(tx, uint32(z), keyHash); err != nil {
				return ExitReason{}, err
			}

			// Also remove the key from PreimageLookup if it exists
			xs.DeletePreimageForHash(tx, keyHash)
		} else if len(historicalStatus) == 1 {
			// Replace [x] with [x, t] if status is [x]
			if err := xs.SetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash, []types.Timeslot{historicalStatus[0], timeslot}); err != nil {
				return ExitReason{}, err
			}
		} else if len(historicalStatus) == 3 && historicalStatus[1] < cutoffTime {
			// Replace [x, y, w] with [w, t] if status is [x, y, w] and y < t - D
			if err := xs.SetPreimageLookupHistoricalStatus(tx, uint32(z), keyHash, []types.Timeslot{historicalStatus[2], timeslot}); err != nil {
				return ExitReason{}, err
			}
		} else {
			// For any other case, return HUH
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		ctx.State.Registers[7] = types.Register(HostCallOK)
		return ExitReasonGo, nil
	})
}

func Yield(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		// Extract offset o from register reg7
		o := ctx.State.Registers[7] // Offset

		// Get the 32-byte key hash from memory
		keyHashBytes := ctx.State.RAM.InspectRangeSafe(uint64(o), 32)
		if keyHashBytes == nil {
			return ExitReasonPanic, nil
		}
		var keyHash [32]byte
		copy(keyHash[:], keyHashBytes)

		// Set the exceptional accumulation result's preimage to this hash
		// x'y = h
		ctx.Argument.AccumulationResultContext.PreimageResult = &keyHash

		// Set OK status in register reg7
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func Provide(ctx *HostFunctionContext[AccumulateInvocationContext], tx *staterepository.TrackedTx) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) (ExitReason, error) {
		// Extract offset o from register reg8
		o := ctx.State.Registers[8] // Offset
		z := ctx.State.Registers[9]

		// Get the blob from memory
		blobBytes := ctx.State.RAM.InspectRangeSafe(uint64(o), uint64(z))
		if blobBytes == nil {
			return ExitReasonPanic, nil
		}

		i := blobBytes

		serviceIndex := ctx.State.Registers[7]
		if serviceIndex == types.Register(^uint64(0)) {
			serviceIndex = types.Register(ctx.Argument.AccumulationResultContext.AccumulatingServiceAccount.ServiceIndex)
		}

		serviceAccount, ok, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(serviceIndex))
		if err != nil {
			return ExitReason{}, err
		}
		if serviceIndex > types.Register(^uint32(0)) || !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		historicalStatus, exists, err := serviceAccount.GetPreimageLookupHistoricalStatus(tx, uint32(z), blake2b.Sum256(i))
		if err != nil {
			return ExitReason{}, err
		}

		if !exists || len(historicalStatus) > 0 {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		preimageProvision := struct {
			ServiceIndex types.ServiceIndex
			BlobString   string
		}{
			ServiceIndex: types.ServiceIndex(serviceIndex),
			BlobString:   string(i),
		}

		if _, ok := ctx.Argument.AccumulationResultContext.PreimageProvisions[preimageProvision]; ok {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		ctx.Argument.AccumulationResultContext.PreimageProvisions[preimageProvision] = struct{}{}

		// Set OK status in register reg7
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return ExitReasonGo, nil
	})
}

func serializeWorkItemForFetch(i wp.WorkItem) []byte {
	return serializer.Serialize(struct {
		ServiceIdentifier                 types.ServiceIndex
		CodeHash                          [32]byte
		Payload                           []byte
		RefinementGasLimit                types.GasValue
		AccumulationGasLimit              types.GasValue
		NumDataSegmentsExported           uint16
		LenImportedDataSegments           uint16
		LenBlobHashesAndLengthsIntroduced uint16
		LenPayload                        uint32
	}{
		ServiceIdentifier:                 i.ServiceIdentifier,
		CodeHash:                          i.CodeHash,
		RefinementGasLimit:                i.RefinementGasLimit,
		AccumulationGasLimit:              i.AccumulationGasLimit,
		NumDataSegmentsExported:           i.NumDataSegmentsExported,
		LenImportedDataSegments:           uint16(len(i.ImportedSegmentsInfo)),
		LenBlobHashesAndLengthsIntroduced: uint16(len(i.BlobHashesAndLengthsIntroduced)),
		LenPayload:                        uint32(len(i.Payload)),
	})
}

func Fetch[T any](ctx *HostFunctionContext[T], workPackage *wp.WorkPackage, n *[32]byte, authorizerOutput *[]byte, importSegmentsIndex *int, importSegments *[][][constants.SegmentSize]byte, blobsIntroduced *[][][]byte, accumulationInputs *[]types.AccumulationInput) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[T]) (ExitReason, error) {
		var preimage []byte
		w11 := ctx.State.Registers[11]
		w12 := ctx.State.Registers[12]
		switch ctx.State.Registers[10] {
		case 0:
			preimage = serializer.SerializeChainParameters()
		case 1:
			if n == nil {
				break
			}
			bytes := (*n)[:]
			preimage = bytes
		case 2:
			if authorizerOutput == nil {
				break
			}
			preimage = *authorizerOutput
		case 3:
			if importSegmentsIndex == nil || w11 >= types.Register(len(*blobsIntroduced)) {
				break
			}

			idx1 := int(w11)
			if w12 >= types.Register(len((*blobsIntroduced)[idx1])) {
				break
			}

			idx2 := int(w12)
			preimage = (*blobsIntroduced)[idx1][idx2]
		case 4:
			if importSegmentsIndex == nil || w11 >= types.Register(len((*blobsIntroduced)[*importSegmentsIndex])) {
				break
			}

			idx1 := int(w11)
			preimage = (*blobsIntroduced)[*importSegmentsIndex][idx1]
		case 5:
			if importSegmentsIndex == nil || w11 >= types.Register(len(*importSegments)) {
				break
			}

			idx1 := int(w11)
			if w12 >= types.Register(len((*importSegments)[idx1])) {
				break
			}

			idx2 := int(w12)
			segment := (*importSegments)[idx1][idx2][:]
			preimage = segment
		case 6:
			if importSegmentsIndex == nil || w11 >= types.Register(len((*importSegments)[*importSegmentsIndex])) {
				break
			}

			idx1 := int(w11)
			segment := (*importSegments)[*importSegmentsIndex][idx1][:]
			preimage = segment
		case 7:
			if workPackage == nil {
				break
			}
			serialized := serializer.Serialize(*workPackage)
			preimage = serialized
		case 8:
			if workPackage == nil {
				break
			}
			preimage = workPackage.AuthorizationConfig
		case 9:
			if workPackage == nil {
				break
			}
			preimage = workPackage.AuthorizationToken
		case 10:
			if workPackage == nil {
				break
			}
			serialized := serializer.Serialize(workPackage.RefinementContext)
			preimage = serialized
		case 11:
			if workPackage == nil {
				break
			}
			blobs := make([]types.Blob, len(workPackage.WorkItems))
			for i, workItem := range workPackage.WorkItems {
				blobs[i] = serializeWorkItemForFetch(workItem)
			}
			serialized := serializer.Serialize(blobs)
			preimage = serialized
		case 12:
			if workPackage == nil {
				break
			}
			if w11 >= types.Register(len(workPackage.WorkItems)) {
				break
			}
			serialized := serializeWorkItemForFetch(workPackage.WorkItems[int(w11)])
			preimage = serialized
		case 13:
			if workPackage == nil {
				break
			}
			if w11 >= types.Register(len(workPackage.WorkItems)) {
				break
			}
			preimage = workPackage.WorkItems[int(w11)].Payload
		case 14:
			if accumulationInputs == nil {
				break
			}
			preimage = serializer.Serialize(*accumulationInputs)
		case 15:
			if accumulationInputs == nil {
				break
			}
			if w11 >= types.Register(len(*accumulationInputs)) {
				break
			}
			serialized := serializer.Serialize((*accumulationInputs)[int(w11)])
			preimage = serialized
		}

		preimageLen := len(preimage)

		o := ctx.State.Registers[7]
		f := min(ctx.State.Registers[8], types.Register(preimageLen))

		l := min(ctx.State.Registers[9], types.Register(preimageLen)-f)

		if preimage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preimageLen)
			if ok := ctx.State.RAM.MutateRangeSafe(uint64(o), uint64(l), func(dest []byte) {
				copy(dest, preimage[int(f):int(f+l)])
			}); !ok {
				return ExitReasonPanic, nil
			}
		}
		return ExitReasonGo, nil
	})
}

func Export(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], exportSegmentOffset int) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		preimageIdx := ctx.State.Registers[7]
		z := min(ctx.State.Registers[8], types.Register(constants.SegmentSize))

		preimage := ctx.State.RAM.InspectRangeSafe(uint64(preimageIdx), uint64(z))
		if preimage != nil {
			return ExitReasonPanic, nil
		}
		if exportSegmentOffset+len(ctx.Argument.ExportSequence) >= int(constants.MaxExportsInWorkPackage) {
			ctx.State.Registers[7] = types.Register(HostCallFull)
			return ExitReasonGo, nil
		}
		x := util.OctetArrayZeroPadding(preimage, int(constants.SegmentSize))
		ctx.State.Registers[7] = types.Register(exportSegmentOffset + len(ctx.Argument.ExportSequence))
		ctx.Argument.ExportSequence = append(ctx.Argument.ExportSequence, x)
		return ExitReasonGo, nil
	})
}

func Machine(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		po := ctx.State.Registers[7]
		pz := ctx.State.Registers[8]
		i := ctx.State.Registers[9]
		p := ctx.State.RAM.InspectRangeSafe(uint64(po), uint64(pz))
		if p == nil {
			return ExitReasonPanic, nil
		}
		if _, _, _, ok := Deblob(p); !ok {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}
		n := uint64(0)
		for {
			if _, ok := ctx.Argument.IntegratedPVMs[n]; !ok {
				break
			}
			n++
		}
		u := NewEmptyRAM(GetExecutionMode() == ModeJIT)
		ctx.State.Registers[7] = types.Register(n)
		ctx.Argument.IntegratedPVMs[n] = IntegratedPVM{
			ProgramCode:        p,
			RAM:                u,
			InstructionCounter: i,
		}
		return ExitReasonGo, nil
	})
}

func Peek(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		// Extract the 4 parameters from registers
		n := ctx.State.Registers[7]  // Source integrated PVM index
		o := ctx.State.Registers[8]  // Destination memory address
		s := ctx.State.Registers[9]  // Source memory address
		z := ctx.State.Registers[10] // Length to copy

		// Check if destination range is writable
		if !ctx.State.RAM.CanWrite(uint64(o), uint64(z)) {
			return ExitReasonPanic, nil
		}

		// Check if integrated PVM exists
		sourcePVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		data := sourcePVM.RAM.InspectRangeSafe(uint64(s), uint64(z))
		if data == nil {
			ctx.State.Registers[7] = types.Register(HostCallOOB)
			return ExitReasonGo, nil
		}

		// Copy the memory
		ctx.State.RAM.MutateRangeHF(uint64(o), uint64(z), NoWrap, func(dest []byte) {
			copy(dest, data)
		})

		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return ExitReasonGo, nil
	})
}

func Pages(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		// Extract the 3 parameters from registers
		n := ctx.State.Registers[7] // Target integrated PVM index
		p := ctx.State.Registers[8] // Start address
		c := ctx.State.Registers[9] // Count/length
		r := ctx.State.Registers[10]

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		// Check for invalid memory range
		if r > 4 || p < 16 || p+c >= (1<<32)/PageSize {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return ExitReasonGo, nil
		}

		if r > 2 {
			// Check accessibility of the entire page range
			startOffset := uint64(p) * PageSize
			totalLength := uint64(c) * PageSize
			if !targetPVM.RAM.CanRead(startOffset, totalLength) {
				ctx.State.Registers[7] = types.Register(HostCallHuh)
				return ExitReasonGo, nil
			}
		}

		if r < 3 {
			for i := uint64(p); i < uint64(p+c); i++ {
				targetPVM.RAM.ZeroPage(uint32(i))
			}
		}

		indexStart := uint64(p * PageSize)
		indexEnd := indexStart + uint64(c*PageSize)

		switch r {
		case 0:
			for i := uint64(p); i < uint64(p+c); i++ {
				targetPVM.RAM.ClearPageAccess(uint32(i))
			}
		case 1:
		case 3:
			targetPVM.RAM.MutateAccessRange(indexStart, indexEnd, Immutable, NoWrap)
		case 2:
		case 4:
			targetPVM.RAM.MutateAccessRange(indexStart, indexEnd, Mutable, NoWrap)
		}

		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return ExitReasonGo, nil
	})
}

func Poke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		// Extract the 4 parameters from registers
		n := ctx.State.Registers[7]  // Target integrated PVM index
		s := ctx.State.Registers[8]  // Source address in current context
		o := ctx.State.Registers[9]  // Destination address in target PVM
		z := ctx.State.Registers[10] // Length to copy

		// Check if source range is accessible in current context
		data := ctx.State.RAM.InspectRangeSafe(uint64(s), uint64(z))
		if data == nil {
			return ExitReasonPanic, nil
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		if ok := targetPVM.RAM.MutateRangeSafe(uint64(o), uint64(z), func(dest []byte) {
			copy(dest, data)
		}); !ok {
			ctx.State.Registers[7] = types.Register(HostCallOOB)
			return ExitReasonGo, nil
		}

		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return ExitReasonGo, nil
	})
}

func Invoke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		// Extract the parameters from registers
		n := ctx.State.Registers[7] // Target integrated PVM index
		o := ctx.State.Registers[8] // Memory offset for gas/weight data

		if !ctx.State.RAM.CanWrite(uint64(o), 112) {
			return ExitReasonPanic, nil
		}

		gasData := ctx.State.RAM.InspectRangeHF(uint64(o), 8, NoWrap)
		registersData := ctx.State.RAM.InspectRangeHF(uint64(o+8), 112, NoWrap)

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		gas := types.GasValue(serializer.DecodeLittleEndian(gasData))
		registers := [13]types.Register{}
		for i := range 13 {
			registers[i] = types.Register(serializer.DecodeLittleEndian(registersData[i*8 : i*8+8]))
		}

		pvm, err := NewPVM(targetPVM.ProgramCode, registers, targetPVM.RAM, targetPVM.InstructionCounter, gas)
		if err != nil {
			return ExitReason{}, err
		}
		if pvm == nil {
			ctx.State.Registers[7] = types.Register(InnerPanic)
			return ExitReasonGo, nil
		}
		exitReason, err := Run(pvm, nil, (*struct{})(nil))
		if err != nil {
			return ExitReason{}, err
		}

		// Update memory with new gas and registers
		ctx.State.RAM.MutateRangeHF(uint64(o), 8, NoWrap, func(dest []byte) {
			binary.LittleEndian.PutUint64(dest, uint64(pvm.State.Gas))
		})

		for i := range 13 {
			ctx.State.RAM.MutateRangeHF(uint64(o+8)+uint64(i*8), 8, NoWrap, func(dest []byte) {
				binary.LittleEndian.PutUint64(dest, uint64(ctx.State.Registers[i]))
			})
		}

		targetPVM.InstructionCounter = pvm.InstructionCounter
		// Handle instruction pointer update based on exit reason
		if exitReason.IsComplex() {
			if exitReason.ComplexExitReason.Type == ExitHostCall {
				// If it's a host call, increment instruction pointer
				targetPVM.InstructionCounter++
				ctx.State.Registers[7] = types.Register(InnerHost)
			} else {
				ctx.State.Registers[7] = types.Register(InnerFault)
			}
			ctx.State.Registers[8] = exitReason.ComplexExitReason.Parameter
		} else {
			switch *exitReason.SimpleExitReason {
			case ExitOutOfGas:
				ctx.State.Registers[7] = types.Register(InnerOOG)
			case ExitPanic:
				ctx.State.Registers[7] = types.Register(InnerPanic)
			case ExitHalt:
				ctx.State.Registers[7] = types.Register(InnerHalt)
			default:
				panic(fmt.Sprintf("unreachable: unhandled simple exit reason %v", *exitReason.SimpleExitReason))
			}
		}
		// Always update the integrated PVM in one place
		ctx.Argument.IntegratedPVMs[uint64(n)] = targetPVM
		return ExitReasonGo, nil
	})
}

// Expunge removes an integrated PVM and returns its index
func Expunge(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		// Extract the parameter from register
		n := ctx.State.Registers[7] // Target integrated PVM index to expunge

		// Check if integrated PVM exists
		_, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			// n is not a key in the map, return WHO error
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return ExitReasonGo, nil
		}

		// PVM exists, store its index in Register 7
		// Here we're assuming the "i" component refers to the index, which is n
		ctx.State.Registers[7] = n

		// Remove the PVM from the map
		delete(ctx.Argument.IntegratedPVMs, uint64(n))

		return ExitReasonGo, nil
	})
}

func Lookup(ctx *HostFunctionContext[struct{}], tx *staterepository.TrackedTx, serviceAccount *serviceaccount.ServiceAccount) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) (ExitReason, error) {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		keyArrayBytes := ctx.State.RAM.InspectRangeSafe(uint64(h), 32)
		if keyArrayBytes == nil {
			return ExitReasonPanic, nil
		}

		var a *serviceaccount.ServiceAccount

		// Determine which service account to use
		if ctx.State.Registers[7] == types.MaxRegister || ctx.State.Registers[7] == types.Register(serviceAccount.ServiceIndex) {
			a = serviceAccount
		} else {
			account, ok, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(ctx.State.Registers[7]))
			if err != nil {
				return ExitReason{}, err
			}
			if ok {
				a = account
			}
		}

		var preImage []byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], keyArrayBytes)
			v, ok, err := a.GetPreimageForHash(tx, keyArray)
			if err != nil {
				return ExitReasonPanic, err
			}
			if ok {
				preImage = v
			}
		}

		// f = min(reg10, |v|)
		f := min(ctx.State.Registers[10], types.Register(len(preImage)))

		// l = min(reg11, |v| - f)
		l := min(ctx.State.Registers[11], types.Register(len(preImage))-f)

		if !ctx.State.RAM.CanWrite(uint64(o), uint64(l)) {
			return ExitReasonPanic, nil
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(len(preImage))
			if l > 0 {
				slicedData := preImage[int(f):int(f+l)]
				ctx.State.RAM.MutateRangeHF(uint64(o), uint64(l), NoWrap, func(dest []byte) {
					copy(dest, slicedData)
				})
			}
		}

		return ExitReasonGo, nil
	})
}

// HistoricalLookup retrieves a historical value for a key from a service account
func HistoricalLookup(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], tx *staterepository.TrackedTx, serviceIndex types.ServiceIndex, serviceAccounts serviceaccount.ServiceAccounts, timeslot types.Timeslot) (ExitReason, error) {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) (ExitReason, error) {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		keyArrayBytes := ctx.State.RAM.InspectRangeSafe(uint64(h), 32)
		if keyArrayBytes == nil {
			return ExitReasonPanic, nil
		}

		var a *serviceaccount.ServiceAccount

		serviceAccountForProvidedIndex, ok := serviceAccounts[serviceIndex]
		// Determine which service account to use
		if ctx.State.Registers[7] == types.MaxRegister && ok {
			a = serviceAccountForProvidedIndex
		} else if serviceAccountForRegister, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
			a = serviceAccountForRegister
		}

		var preImage []byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], keyArrayBytes)

			var err error
			preImage, err = historicallookup.HistoricalLookup(tx, a, timeslot, keyArray)
			if err != nil {
				return ExitReason{}, err
			}
		}

		// Calculate preimage length, offset and length to copy
		preImageLen := 0
		if preImage != nil {
			preImageLen = len(preImage)
		}

		// f = min(reg10, |v|)
		f := min(ctx.State.Registers[10], types.Register(preImageLen))

		// l = min(reg11, |v| - f)
		l := min(ctx.State.Registers[11], types.Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.CanWrite(uint64(o), uint64(l)) {
			return ExitReasonPanic, nil
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preImageLen)
			if l > 0 {
				slicedData := preImage[int(f):int(f+l)]
				ctx.State.RAM.MutateRangeHF(uint64(o), uint64(l), NoWrap, func(dest []byte) {
					copy(dest, slicedData)
				})
			}
		}

		return ExitReasonGo, nil
	})
}

// helpers

func withGasCheck[T any](
	ctx *HostFunctionContext[T],
	fn func(*HostFunctionContext[T]) (ExitReason, error),
) (ExitReason, error) {
	if types.GasValue(ctx.State.Gas) < GasUsage {
		ctx.State.Gas = 0
		return ExitReasonOutOfGas, nil
	}
	ctx.State.Gas -= types.SignedGasValue(GasUsage)
	return fn(ctx)
}

// check finds an unused service index, starting from the provided index
// If the initial index is already in use, it iteratively tries next indices
func check(tx *staterepository.TrackedTx, i types.ServiceIndex) (types.ServiceIndex, error) {

	currentIndex := i

	// Keep trying until we find an unused index
	for {
		// Check if the index is already in use
		_, exists, err := serviceaccount.GetServiceAccount(tx, currentIndex)
		if err != nil {
			return currentIndex, err
		}
		if !exists {
			// If not in use, return it
			return currentIndex, nil
		}

		// Calculate the next index to try
		currentIndex = types.ServiceIndex(constants.MinPublicServiceIndex + ((uint64(currentIndex) - constants.MinPublicServiceIndex + 1) % (1<<32 - (1 << 8) - constants.MinPublicServiceIndex)))
	}
}
