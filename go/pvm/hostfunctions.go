package pvm

import (
	"bytes"
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/util"
	wp "github.com/ascrivener/jam/workpackage"
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

type HostFunction[T any] func(HostFunctionIdentifier, *HostFunctionContext[T]) ExitReason

const GasUsage types.GasValue = 10

func Gas(ctx *HostFunctionContext[struct{}], args ...any) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		ctx.State.Registers[7] = types.Register(ctx.State.Gas)
		return NewSimpleExitReason(ExitGo)
	})
}

// VerifyAndReturnStateForAccessor implements the state lookup host function
// as specified in the graypaper. It verifies access, computes a key hash,
// and returns data from state if available.
func Read(ctx *HostFunctionContext[struct{}], serviceAccount *serviceaccount.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts serviceaccount.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {

		// Determine s* based on ω7
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
			if serviceAcc, ok := serviceAccounts[types.ServiceIndex(sStar)]; ok {
				a = serviceAcc
			}
		}

		// Extract [ko, kz, o] from registers ω8⋅⋅⋅+3
		ko := ctx.State.Registers[8] // Key offset
		kz := ctx.State.Registers[9] // Key length
		o := ctx.State.Registers[10] // Output offset

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(ko), uint64(kz), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Determine 'v'
		var preImage *[]byte

		if a != nil {
			// Create key by hashing service ID and memory contents
			serviceIdBytes := serializer.EncodeLittleEndian(4, uint64(sStar))
			keyBytes := ctx.State.RAM.InspectRange(uint64(ko), uint64(kz), ram.NoWrap, false)
			combinedBytes := append(serviceIdBytes, keyBytes...)

			var keyArray [32]byte
			h := blake2b.Sum256(combinedBytes)
			copy(keyArray[:], h[:])

			// Look up in state if available
			if val, ok := a.StorageDictionary[serviceaccount.StorageDictionaryKeyFromFullKey(keyArray)]; ok {
				byteSlice := []byte(val)
				preImage = &byteSlice
			}
		}

		// Calculate f and l
		var preImageLen int
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		f := min(ctx.State.Registers[11], types.Register(preImageLen))
		l := min(ctx.State.Registers[12], types.Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preImageLen)
			slicedData := (*preImage)[int(f):int(f+l)]
			ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
		}

		return NewSimpleExitReason(ExitGo)
	})
}

func Write(ctx *HostFunctionContext[struct{}], serviceAccount *serviceaccount.ServiceAccount, serviceIndex types.ServiceIndex) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		// Extract [ko, kz, vo, vz] from registers ω7⋅⋅⋅+4
		ko := ctx.State.Registers[7]  // Key offset
		kz := ctx.State.Registers[8]  // Key length
		vo := ctx.State.Registers[9]  // Value offset
		vz := ctx.State.Registers[10] // Value length

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(ko), uint64(kz), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Compute the key hash
		serviceIdBytes := serializer.EncodeLittleEndian(4, uint64(serviceIndex))
		keyBytes := ctx.State.RAM.InspectRange(uint64(ko), uint64(kz), ram.NoWrap, false)
		combinedBytes := append(serviceIdBytes, keyBytes...)

		var keyArray [32]byte
		h := blake2b.Sum256(combinedBytes)
		copy(keyArray[:], h[:])

		key := serviceaccount.StorageDictionaryKeyFromFullKey(keyArray)

		// Determine 'l' - length of previous value if it exists, NONE otherwise
		var l types.Register
		if val, ok := serviceAccount.StorageDictionary[key]; ok {
			l = types.Register(len(val))
		} else {
			l = types.Register(HostCallNone)
		}

		oldValue, ok := serviceAccount.StorageDictionary[key]

		// Handle according to vz (value length)
		if vz == 0 {
			// If vz = 0, remove entry
			delete(serviceAccount.StorageDictionary, key)
		} else if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(vo), uint64(vz), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		} else {
			// Write the value to the account storage
			valueBytes := ctx.State.RAM.InspectRange(uint64(vo), uint64(vz), ram.NoWrap, false)
			serviceAccount.StorageDictionary[key] = valueBytes
		}

		if serviceAccount.ThresholdBalanceNeeded() > serviceAccount.Balance {
			if !ok {
				delete(serviceAccount.StorageDictionary, key)
			} else {
				serviceAccount.StorageDictionary[key] = oldValue
			}
			ctx.State.Registers[7] = types.Register(HostCallFull)
		} else {
			ctx.State.Registers[7] = l
		}

		return NewSimpleExitReason(ExitGo)
	})
}

// AccountInfo represents the structured account information for serialization
type AccountInfo struct {
	CodeHash                       [32]byte              // c
	Balance                        types.GenericNum      // b
	ThresholdBalanceNeeded         types.GenericNum      // t
	MinimumGasForAccumulate        types.GenericGasValue // g
	MinimumGasForOnTransfer        types.GenericGasValue // m
	TotalOctetsUsedInStorage       types.GenericNum      // o
	StorageItems                   types.GenericNum      // i
	GratisStorageOffset            types.GenericNum      // f
	CreatedTimeSlot                types.GenericNum      // r
	MostRecentAccumulationTimeslot types.GenericNum      // a
	ParentServiceIndex             types.GenericNum      // p
}

func Info(ctx *HostFunctionContext[struct{}], serviceIndex types.ServiceIndex, serviceAccounts serviceaccount.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		// Determine the target service account (t)
		var targetAccount *serviceaccount.ServiceAccount

		// If ω7 = 2^64 - 1, use service account parameter, otherwise lookup by index
		if ctx.State.Registers[7] == types.Register(^uint64(0)) {
			s := serviceAccounts[serviceIndex]
			targetAccount = s
		} else if ctx.State.Registers[7] <= types.Register(^uint32(0)) {
			// Check if ω7 can fit in uint32 range
			if account, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
				targetAccount = account
			}
		}

		// Get output offset (o) from ω8
		outputOffset := ctx.State.Registers[8]

		// If target account exists, encode its information
		if targetAccount != nil {
			// Create struct with account information
			accountInfo := AccountInfo{
				CodeHash:                       targetAccount.CodeHash,
				Balance:                        types.GenericNum(targetAccount.Balance),
				ThresholdBalanceNeeded:         types.GenericNum(targetAccount.ThresholdBalanceNeeded()),
				MinimumGasForAccumulate:        types.GenericGasValue(targetAccount.MinimumGasForAccumulate),
				MinimumGasForOnTransfer:        types.GenericGasValue(targetAccount.MinimumGasForOnTransfer),
				TotalOctetsUsedInStorage:       types.GenericNum(targetAccount.TotalOctetsUsedInStorage()),
				StorageItems:                   types.GenericNum(targetAccount.TotalItemsUsedInStorage()),
				GratisStorageOffset:            types.GenericNum(targetAccount.GratisStorageOffset),
				CreatedTimeSlot:                types.GenericNum(targetAccount.CreatedTimeSlot),
				MostRecentAccumulationTimeslot: types.GenericNum(targetAccount.MostRecentAccumulationTimeslot),
				ParentServiceIndex:             types.GenericNum(targetAccount.ParentServiceIndex),
			}

			// Serialize the account information
			serializedInfo := serializer.Serialize(accountInfo)

			// Check if memory range is writable
			if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(outputOffset), uint64(len(serializedInfo)), ram.NoWrap) {
				return NewSimpleExitReason(ExitPanic)
			}

			// Write to memory
			ctx.State.RAM.MutateRange(uint64(outputOffset), serializedInfo, ram.NoWrap, false)

			// Set successful result
			ctx.State.Registers[7] = types.Register(HostCallOK)
		} else {
			// Target account not found
			ctx.State.Registers[7] = types.Register(HostCallNone)
		}

		return NewSimpleExitReason(ExitGo)
	})
}

func Bless(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract registers: [m, a, v, o, n] = ω7⋅⋅⋅+5
		mainIndex := ctx.State.Registers[7]         // m - Main service index
		authIndicesOffset := ctx.State.Registers[8] // a - Authorization service indices offset
		validIndex := ctx.State.Registers[9]        // v - Validation service index
		offset := ctx.State.Registers[10]           // o - Memory offset
		numEntries := ctx.State.Registers[11]       // n - Number of entries

		// Check if memory range is accessible
		entrySize := uint64(12) // Each entry is 12 bytes (4 for service index, 8 for gas value)
		totalSize := entrySize * uint64(numEntries)

		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), totalSize, ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(authIndicesOffset), uint64(4*constants.NumCores), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		if ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.ManagerServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if m, a, v are valid ServiceIndices
		if mainIndex > types.Register(^uint32(0)) || validIndex > types.Register(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Create gas mapping g
		serviceGasMap := make(map[types.ServiceIndex]types.GasValue)

		// Read service-to-gas mappings from memory
		for i := uint64(0); i < uint64(numEntries); i++ {
			// Read service index (4 bytes) and gas value (8 bytes)
			entryOffset := uint64(offset) + i*entrySize

			// Get service index from memory
			serviceBytes := ctx.State.RAM.InspectRange(entryOffset, 4, ram.NoWrap, false)
			serviceIndex := types.ServiceIndex(serializer.DecodeLittleEndian(serviceBytes))

			// Get gas value from memory
			gasBytes := ctx.State.RAM.InspectRange(entryOffset+4, 8, ram.NoWrap, false)
			gasValue := types.GasValue(serializer.DecodeLittleEndian(gasBytes))

			// Add to mapping
			serviceGasMap[serviceIndex] = gasValue
		}

		// Read assign indice array from memory
		assignIndices := [constants.NumCores]types.ServiceIndex{}
		for i := uint64(0); i < uint64(constants.NumCores); i++ {
			entryOffset := uint64(authIndicesOffset) + i*4
			assignIndicesBytes := ctx.State.RAM.InspectRange(entryOffset, 4, ram.NoWrap, false)
			assignIndices[i] = types.ServiceIndex(serializer.DecodeLittleEndian(assignIndicesBytes))
		}

		// Update the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices = types.PrivilegedServices{
			ManagerServiceIndex:             types.ServiceIndex(mainIndex),
			AssignServiceIndices:            assignIndices,
			DesignateServiceIndex:           types.ServiceIndex(validIndex),
			AlwaysAccumulateServicesWithGas: serviceGasMap,
		}
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Assign(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get core index from ω7 and memory offset from ω8
		coreIndex := ctx.State.Registers[7]
		offset := ctx.State.Registers[8]
		assignServiceIndex := ctx.State.Registers[9]

		// Calculate the size of the authorizersQueue array
		queueLength := constants.AuthorizerQueueLength
		totalSize := 32 * queueLength // 32 bytes per hash * queue length

		// Check if memory range is accessible (c = ∇)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), uint64(totalSize), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		if ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.AssignServiceIndices[coreIndex] {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if core index is within valid range
		if coreIndex >= types.Register(constants.NumCores) {
			ctx.State.Registers[7] = types.Register(HostCallCore)
			return NewSimpleExitReason(ExitGo)
		}

		// Read the queue of authorizer hashes from memory
		authorizerQueue := [constants.AuthorizerQueueLength][32]byte{}
		for i := range queueLength {
			hashOffset := uint64(offset) + uint64(i)*32
			hashBytes := ctx.State.RAM.InspectRange(hashOffset, 32, ram.NoWrap, false)

			// Copy the hash bytes to the authorizer queue
			copy(authorizerQueue[i][:], hashBytes)
		}

		// Update the authorizer queue in the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.AuthorizersQueue[coreIndex] = authorizerQueue
		ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.AssignServiceIndices[coreIndex] = types.ServiceIndex(assignServiceIndex)

		// Set successful result
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Designate(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get memory offset from ω7
		offset := ctx.State.Registers[7]

		// Calculate total size needed for validator keysets
		// Each validator keyset is 336 bytes, and we need constants.NumValidators of them
		totalSize := uint64(336 * uint64(constants.NumValidators))

		// Check if memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), totalSize, ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		if ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.DesignateServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Read the validator keysets from memory
		validatorKeysets := [constants.NumValidators]types.ValidatorKeyset{}
		for i := 0; i < int(constants.NumValidators); i++ {
			keysetOffset := uint64(offset) + uint64(i)*336
			keysetBytes := ctx.State.RAM.InspectRange(keysetOffset, 336, ram.NoWrap, false)

			// Copy the keyset bytes
			copy(validatorKeysets[i][:], keysetBytes)
		}

		// Update the validator keysets in the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.UpcomingValidatorKeysets = validatorKeysets

		// Set successful result
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Checkpoint(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		ctx.Argument.ExceptionalAccumulationResultContext = *ctx.Argument.AccumulationResultContext.DeepCopy()
		ctx.State.Registers[7] = types.Register(ctx.State.Gas)

		return NewSimpleExitReason(ExitGo)
	})
}

func New(ctx *HostFunctionContext[AccumulateInvocationContext], timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get parameters from registers [o, l, g, m] = ω7⋅⋅⋅+4
		offset := ctx.State.Registers[7]               // o - memory offset for code hash
		labelLength := ctx.State.Registers[8]          // l - label length
		minGasForAccumulate := ctx.State.Registers[9]  // g - minimum gas for accumulate
		minGasForOnTransfer := ctx.State.Registers[10] // m - minimum gas for on transfer
		gratisStorageOffset := ctx.State.Registers[11] // f - gratis storage offset

		// Check if memory range for code hash is accessible (c = ∇ check)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), 32, ram.NoWrap) || labelLength > types.Register(^uint32(0)) {
			return NewSimpleExitReason(ExitPanic)
		}

		if gratisStorageOffset > types.Register(^uint64(0)) && ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex != ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices.ManagerServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Read code hash from memory
		codeHashBytes := ctx.State.RAM.InspectRange(uint64(offset), 32, ram.NoWrap, false)
		var codeHash [32]byte
		copy(codeHash[:], codeHashBytes)

		// Create preimage history map with the code hash and label length as key
		preimageHistory := make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot)
		key := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(codeHash, types.BlobLength(labelLength))
		preimageHistory[key] = []types.Timeslot{}

		// Create new service account
		newAccount := &serviceaccount.ServiceAccount{
			CodeHash:                       codeHash,
			StorageDictionary:              make(map[serviceaccount.StorageDictionaryKey]types.Blob),
			PreimageLookupHistoricalStatus: preimageHistory,
			MinimumGasForAccumulate:        types.GasValue(minGasForAccumulate),
			MinimumGasForOnTransfer:        types.GasValue(minGasForOnTransfer),
			PreimageLookup:                 make(map[serviceaccount.PreimageLookupKey]types.Blob),
			GratisStorageOffset:            types.Balance(gratisStorageOffset),
			CreatedTimeSlot:                timeslot,
			MostRecentAccumulationTimeslot: 0,
			ParentServiceIndex:             ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex,
		}
		newAccount.Balance = newAccount.ThresholdBalanceNeeded()

		accumulatingServiceAccount := ctx.Argument.AccumulatingServiceAccount()
		// Check if source has enough balance after the transfer (sb < (xs)t check)
		// The source account needs enough balance to cover both:
		// 1. Its own threshold balance needs
		// 2. The transfer amount to the new account
		b := accumulatingServiceAccount.Balance - newAccount.ThresholdBalanceNeeded()
		if b < accumulatingServiceAccount.ThresholdBalanceNeeded() {
			ctx.State.Registers[7] = types.Register(HostCallCash)
			return NewSimpleExitReason(ExitGo)
		}
		accumulatingServiceAccount.Balance = b

		currentDerivedServiceIndex := ctx.Argument.AccumulationResultContext.DerivedServiceIndex
		newDerivedServiceIndex := types.ServiceIndex((1 << 8) + ((uint64(currentDerivedServiceIndex) - (1 << 8) + 42 + (1<<32 - 1<<9)) % (1<<32 - 1<<9)))

		// Get current service accounts and update them
		ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts[currentDerivedServiceIndex] = newAccount

		ctx.State.Registers[7] = types.Register(currentDerivedServiceIndex)
		ctx.Argument.AccumulationResultContext.DerivedServiceIndex = check(newDerivedServiceIndex, &ctx.Argument.AccumulationResultContext.StateComponents)

		return NewSimpleExitReason(ExitGo)
	})
}

func Upgrade(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get parameters from registers [o, g, m] = ω7⋅⋅⋅+3
		offset := ctx.State.Registers[7]              // o - memory offset for code hash
		minGasForAccumulate := ctx.State.Registers[8] // g - minimum gas for accumulate
		minGasForOnTransfer := ctx.State.Registers[9] // m - minimum gas for on transfer

		// Check if memory range for code hash is accessible (c = ∇ check)
		// if No⋅⋅⋅+32 ⊂ Vμ condition
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), 32, ram.NoWrap) {
			// (ε′, ω′7, (x′s)c, (x′s)g, (x′s)m) ≡ (☇, ω7, (xs)c, (xs)g, (xs)m) if c = ∇
			return NewSimpleExitReason(ExitPanic)
		}

		// Read code hash from memory (μo⋅⋅⋅+32)
		codeHashBytes := ctx.State.RAM.InspectRange(uint64(offset), 32, ram.NoWrap, false)
		var codeHash [32]byte
		copy(codeHash[:], codeHashBytes)

		// Get the accumulating service account
		accumulatingServiceAccount := ctx.Argument.AccumulatingServiceAccount()

		// Update the service account with new values
		// (ε′, ω′7, (x′s)c, (x′s)g, (x′s)m) ≡ (▸, OK, c, g, m) otherwise
		accumulatingServiceAccount.CodeHash = codeHash
		accumulatingServiceAccount.MinimumGasForAccumulate = types.GasValue(minGasForAccumulate)
		accumulatingServiceAccount.MinimumGasForOnTransfer = types.GasValue(minGasForOnTransfer)

		// Set return status to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Transfer(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	ctx.State.Gas -= types.SignedGasValue(ctx.State.Registers[9])
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract parameters from registers [d, a, l, o] = ω7⋅⋅⋅+4
		destServiceIndex := types.ServiceIndex(ctx.State.Registers[7]) // d - destination service index
		amount := types.Balance(ctx.State.Registers[8])                // a - amount to transfer
		gasLimit := types.GasValue(ctx.State.Registers[9])             // l - gas limit
		memoOffset := ctx.State.Registers[10]                          // o - memo offset

		// 1. FIRST check if memo memory range is accessible (No⋅⋅⋅+WT ⊂ Vμ)
		// This determines if t = ∇, which is the first condition in the exit reason
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(memoOffset), uint64(constants.TransferMemoSize), ram.NoWrap) {
			// (ε′, ω′7, xt, (xs)b) ≡ (☇, ω7, xt, (xs)b) if t = ∇
			return NewSimpleExitReason(ExitPanic)
		}

		// Read memo from memory (μo⋅⋅⋅+WT)
		memoBytes := ctx.State.RAM.InspectRange(uint64(memoOffset), uint64(constants.TransferMemoSize), ram.NoWrap, false)
		var memo [constants.TransferMemoSize]byte
		copy(memo[:], memoBytes)

		// Get service accounts
		serviceAccounts := ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts

		// 2. Check if destination exists in service accounts (d ∈ K(d))
		destinationAccount, destinationExists := serviceAccounts[destServiceIndex]
		if !destinationExists {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// 3. Check if gas limit is sufficient (l < d[d]m)
		if gasLimit < destinationAccount.MinimumGasForOnTransfer {
			ctx.State.Registers[7] = types.Register(HostCallLow)
			return NewSimpleExitReason(ExitGo)
		}

		// Get source account
		sourceAccount := ctx.Argument.AccumulatingServiceAccount()

		// Calculate new balance (b = (xs)b − a)
		newBalance := sourceAccount.Balance - amount

		// 4. Check if source has enough balance after transfer (b < (xs)t)
		if newBalance < sourceAccount.ThresholdBalanceNeeded() {
			ctx.State.Registers[7] = types.Register(HostCallCash)
			return NewSimpleExitReason(ExitGo)
		}

		// Create transfer object
		transfer := DeferredTransfer{
			SenderServiceIndex:   ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex,
			ReceiverServiceIndex: destServiceIndex,
			BalanceTransfer:      amount,
			Memo:                 memo,
			GasLimit:             gasLimit,
		}

		// Update source account balance
		sourceAccount.Balance = newBalance

		// Append transfer to deferred transfers list
		ctx.Argument.AccumulationResultContext.DeferredTransfers = append(
			ctx.Argument.AccumulationResultContext.DeferredTransfers,
			transfer)

		// Set return status to OK - (ε′, ω′7, xt, (xs)b) ≡ (▸, OK, xt t, b) otherwise
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Eject(ctx *HostFunctionContext[AccumulateInvocationContext], timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract parameters from registers [d, o] = ω7,8
		destServiceIndex := types.ServiceIndex(ctx.State.Registers[7]) // d - destination service index
		hashOffset := ctx.State.Registers[8]                           // o - hash offset

		// 1. Check if memory for hash is accessible (Zo⋅⋅⋅+32 ⊂ Vμ)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(hashOffset), 32, ram.NoWrap) {
			// (ε′, ω′7, (x′u)d) ≡ (☇, ω7, (xu)d) if h = ∇
			return NewSimpleExitReason(ExitPanic)
		}

		// Read hash from memory (μo⋅⋅⋅+32)
		hashBytes := ctx.State.RAM.InspectRange(uint64(hashOffset), 32, ram.NoWrap, false)
		var hash [32]byte
		copy(hash[:], hashBytes)

		// Get service accounts and the accumulating account
		serviceAccounts := ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts
		accumulatingServiceAccount := ctx.Argument.AccumulatingServiceAccount()

		// 2. Check destination account exists and matches code hash
		// (d ≠ xs ∧ d ∈ K((xu)d)) && (dc ≠ E32(xs))
		if destServiceIndex == ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		destinationAccount, destinationExists := serviceAccounts[destServiceIndex]
		if !destinationExists {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Compare code hashes (dc ≠ E32(xs))
		if !bytes.Equal(destinationAccount.CodeHash[:], serializer.EncodeLittleEndian(32, uint64(ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex))) {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// 3. Check interface type and if hash/lock pair exists in list
		// (di ≠ 2 ∨ (h, l) ~∈ dl)
		if destinationAccount.TotalItemsUsedInStorage() != 2 { // Assuming InterfaceID 2 corresponds to lockable interface
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		length := max(81, destinationAccount.TotalOctetsUsedInStorage()) - 81

		// Create the key for lookup
		lookupKey := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(hash, types.BlobLength(length))

		historicalStatus, exists := destinationAccount.PreimageLookupHistoricalStatus[lookupKey]
		if !exists || length > uint64(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Get the most recent timeslot in the historical status
		if len(historicalStatus) == 2 {
			// Check the expiration of the most recent timeslot against the current time
			// Using UnreferencePreimageExpungeTimeslots as D from the specification
			lastTimeslot := historicalStatus[1]
			if lastTimeslot < timeslot-types.Timeslot(constants.UnreferencePreimageExpungeTimeslots) {
				// Update accumulating account balance (s′b = ((xu)d)[xs]b + db)
				// For simplicity, we're assuming the balance to transfer is associated with the destination account
				accumulatingServiceAccount.Balance += destinationAccount.Balance

				// Remove the entry from destination account
				// ((xu)d ∖ {d} ∪ {xs ↦ s′})
				delete(serviceAccounts, destServiceIndex)

				// Set status to OK
				ctx.State.Registers[7] = types.Register(HostCallOK)
				return NewSimpleExitReason(ExitGo)
			}
		}
		// Entry not expired
		ctx.State.Registers[7] = types.Register(HostCallHuh)
		return NewSimpleExitReason(ExitGo)
	})
}

func Query(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract [o, z] from registers ω7,8
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // Length/Value

		// Check if memory at o is accessible for 32 bytes (μo⋅⋅⋅+32 ⊂ Vμ)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(o), 32, ram.NoWrap) {
			// If memory is inaccessible, set registers to (☇, ω7, ω8) and return panic
			return NewSimpleExitReason(ExitPanic)
		}

		// Get the 32-byte key hash from memory
		var keyHash [32]byte
		copy(keyHash[:], ctx.State.RAM.InspectRange(uint64(o), 32, ram.NoWrap, false))

		historicalStatus, ok := ctx.Argument.AccumulatingServiceAccount().PreimageLookupHistoricalStatus[serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(keyHash, types.BlobLength(z))]

		if !ok || z > types.Register(^uint32(0)) {
			ctx.State.Registers[7] = types.Register(HostCallNone)
			ctx.State.Registers[8] = 0
			return NewSimpleExitReason(ExitGo)
		}

		// Set result registers based on list content according to the spec
		if len(historicalStatus) == 0 {
			// a = []: Set (▸, 0, 0)
			ctx.State.Registers[7] = 0
			ctx.State.Registers[8] = 0
		} else if len(historicalStatus) == 1 {
			// a = [x]: Set (▸, 1 + 2^32*x, 0)
			ctx.State.Registers[7] = 1 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = 0
		} else if len(historicalStatus) == 2 {
			// a = [x, y]: Set (▸, 2 + 2^32*x, y)
			ctx.State.Registers[7] = 2 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = types.Register(historicalStatus[1])
		} else if len(historicalStatus) == 3 {
			// a = [x, y, z, ...]: Set (▸, 3 + 2^32*x, y + 2^32*z)
			ctx.State.Registers[7] = 3 + (types.Register(historicalStatus[0]) << 32)
			ctx.State.Registers[8] = types.Register(historicalStatus[1]) + (types.Register(historicalStatus[2]) << 32)
		} else {
			panic(fmt.Sprintf("unreachable: impossible historical status length %v", len(historicalStatus)))
		}

		return NewSimpleExitReason(ExitGo)
	})
}

func Solicit(ctx *HostFunctionContext[AccumulateInvocationContext], timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract [o, z] from registers ω7,8
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // BlobLength

		// Check if memory at o is accessible for 32 bytes (μo⋅⋅⋅+32 ⊂ Vμ)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(o), 32, ram.NoWrap) {
			// If memory is inaccessible, return panic (h = ∇)
			return NewSimpleExitReason(ExitPanic)
		}

		// Get the 32-byte key hash from memory
		var keyHash [32]byte
		copy(keyHash[:], ctx.State.RAM.InspectRange(uint64(o), 32, ram.NoWrap, false))

		// Prepare the key for looking up historical status
		histKey := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(keyHash, types.BlobLength(z))

		// Get the accumulating service account (xs)
		serviceAccount := ctx.Argument.AccumulatingServiceAccount()

		// Check if the key exists in the historical status map
		originalStatus, originalExists := serviceAccount.PreimageLookupHistoricalStatus[histKey]

		// Make the changes directly to the service account
		if !originalExists || z > types.Register(^uint32(0)) {
			serviceAccount.PreimageLookupHistoricalStatus[histKey] = []types.Timeslot{}
		} else if len(originalStatus) == 2 {
			serviceAccount.PreimageLookupHistoricalStatus[histKey] = append(originalStatus, timeslot)
		} else {
			// Key exists but doesn't have exactly two elements
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if we've exceeded storage limits
		if serviceAccount.Balance < serviceAccount.ThresholdBalanceNeeded() {
			// Revert the changes
			if !originalExists {
				delete(serviceAccount.PreimageLookupHistoricalStatus, histKey)
			} else {
				serviceAccount.PreimageLookupHistoricalStatus[histKey] = originalStatus
			}
			ctx.State.Registers[7] = types.Register(HostCallFull)
			return NewSimpleExitReason(ExitGo)
		}

		ctx.State.Registers[7] = types.Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Forget(ctx *HostFunctionContext[AccumulateInvocationContext], timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract [o, z] from registers ω7,8
		o := ctx.State.Registers[7] // Offset
		z := ctx.State.Registers[8] // BlobLength

		// Check if memory at o is accessible for 32 bytes (μo⋅⋅⋅+32 ⊂ Vμ)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(o), 32, ram.NoWrap) {
			// If memory is inaccessible, return panic (h = ∇)
			return NewSimpleExitReason(ExitPanic)
		}

		// Get the 32-byte key hash from memory
		var keyHash [32]byte
		copy(keyHash[:], ctx.State.RAM.InspectRange(uint64(o), 32, ram.NoWrap, false))

		// Prepare the key for looking up historical status
		histKey := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(keyHash, types.BlobLength(z))

		// Get the accumulating service account (xs)
		xs := ctx.Argument.AccumulatingServiceAccount()

		// Check if the key exists in the historical status map
		historicalStatus, exists := xs.PreimageLookupHistoricalStatus[histKey]
		if !exists || z > types.Register(^uint32(0)) {
			// Key doesn't exist, return HUH
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Define cutoff time for "old enough" timeslots (t - D)
		cutoffTime := timeslot - types.Timeslot(constants.UnreferencePreimageExpungeTimeslots)

		// Handle different cases based on historical status length and values
		if len(historicalStatus) == 0 || (len(historicalStatus) == 2 && historicalStatus[1] < cutoffTime) {
			// Remove the key if status is [] or [x, y] with y < t - D
			delete(xs.PreimageLookupHistoricalStatus, histKey)

			// Also remove the key from PreimageLookup if it exists
			delete(xs.PreimageLookup, serviceaccount.PreimageLookupKeyFromFullKey(keyHash))
		} else if len(historicalStatus) == 1 {
			// Replace [x] with [x, t] if status is [x]
			xs.PreimageLookupHistoricalStatus[histKey] = []types.Timeslot{historicalStatus[0], timeslot}
		} else if len(historicalStatus) == 3 && historicalStatus[1] < cutoffTime {
			// Replace [x, y, w] with [w, t] if status is [x, y, w] and y < t - D
			xs.PreimageLookupHistoricalStatus[histKey] = []types.Timeslot{historicalStatus[2], timeslot}
		} else {
			// For any other case, return HUH
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		ctx.State.Registers[7] = types.Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Yield(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract offset o from register ω7
		o := ctx.State.Registers[7] // Offset

		// Check if memory at o is accessible for 32 bytes (μo⋅⋅⋅+32 ⊂ Vμ)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(o), 32, ram.NoWrap) {
			// If memory is inaccessible, return panic (h = ∇)
			return NewSimpleExitReason(ExitPanic)
		}

		// Get the 32-byte key hash from memory
		var keyHash [32]byte
		copy(keyHash[:], ctx.State.RAM.InspectRange(uint64(o), 32, ram.NoWrap, false))

		// Set the exceptional accumulation result's preimage to this hash
		// x'y = h
		ctx.Argument.AccumulationResultContext.PreimageResult = &keyHash

		// Set OK status in register ω7
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Provide(ctx *HostFunctionContext[AccumulateInvocationContext], serviceIndex types.ServiceIndex) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract offset o from register ω8
		o := ctx.State.Registers[8] // Offset
		z := ctx.State.Registers[9]

		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(o), uint64(z), ram.NoWrap) {
			// If memory is inaccessible, return panic (h = ∇)
			return NewSimpleExitReason(ExitPanic)
		}

		i := ctx.State.RAM.InspectRange(uint64(o), uint64(z), ram.NoWrap, false)

		d := ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts

		sStar := ctx.State.Registers[7]
		if sStar == types.Register(^uint64(0)) {
			sStar = types.Register(serviceIndex)
		}

		serviceAccount, ok := d[types.ServiceIndex(sStar)]
		if sStar > types.Register(^uint32(0)) || !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		preimageLookupHistoricalStatusKey := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(blake2b.Sum256(i), types.BlobLength(z))

		historicalStatus, ok := serviceAccount.PreimageLookupHistoricalStatus[preimageLookupHistoricalStatusKey]

		if !ok || len(historicalStatus) > 0 {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		preimageProvision := struct {
			ServiceIndex types.ServiceIndex
			BlobString   string
		}{
			ServiceIndex: types.ServiceIndex(sStar),
			BlobString:   string(i),
		}

		if _, ok := ctx.Argument.AccumulationResultContext.PreimageProvisions[preimageProvision]; ok {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		ctx.Argument.AccumulationResultContext.PreimageProvisions[preimageProvision] = struct{}{}

		// Set OK status in register ω7
		ctx.State.Registers[7] = types.Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
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
		LenImportedDataSegments:           uint16(len(i.ImportedDataSegments)),
		LenBlobHashesAndLengthsIntroduced: uint16(len(i.BlobHashesAndLengthsIntroduced)),
		LenPayload:                        uint32(len(i.Payload)),
	})
}

func Fetch[T any](ctx *HostFunctionContext[T], workPackage *wp.WorkPackage, n *[32]byte, authorizerOutput *[]byte, importSegmentsIndex *int, importSegments *[][][constants.SegmentSize]byte, blobsIntroduced *[][][]byte, operandTuples *[]OperandTuple, deferredTransfers *[]DeferredTransfer) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[T]) ExitReason {
		var preimage *[]byte
		w11 := ctx.State.Registers[11]
		w12 := ctx.State.Registers[12]
		switch ctx.State.Registers[10] {
		case 0:
			serialized := serializer.SerializeChainParameters()
			preimage = &serialized
		case 1:
			if n == nil {
				break
			}
			bytes := (*n)[:]
			preimage = &bytes
		case 2:
			if authorizerOutput == nil {
				break
			}
			preimage = authorizerOutput
		case 3:
			if importSegmentsIndex == nil || w11 >= types.Register(len(*blobsIntroduced)) {
				break
			}

			idx1 := int(w11)
			if w12 >= types.Register(len((*blobsIntroduced)[idx1])) {
				break
			}

			idx2 := int(w12)
			preimage = &(*blobsIntroduced)[idx1][idx2]
		case 4:
			if importSegmentsIndex == nil || w11 >= types.Register(len((*blobsIntroduced)[*importSegmentsIndex])) {
				break
			}

			idx1 := int(w11)
			preimage = &(*blobsIntroduced)[*importSegmentsIndex][idx1]
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
			preimage = &segment
		case 6:
			if importSegmentsIndex == nil || w11 >= types.Register(len((*importSegments)[*importSegmentsIndex])) {
				break
			}

			idx1 := int(w11)
			segment := (*importSegments)[*importSegmentsIndex][idx1][:]
			preimage = &segment
		case 7:
			if workPackage == nil {
				break
			}
			serialized := serializer.Serialize(*workPackage)
			preimage = &serialized
		case 8:
			if workPackage == nil {
				break
			}
			serialized := serializer.Serialize(struct {
				CodeHash [32]byte
				Blob     []byte
			}{
				CodeHash: workPackage.AuthorizationCodeHash,
				Blob:     workPackage.ParameterizationBlob,
			})
			preimage = &serialized
		case 9:
			if workPackage == nil {
				break
			}
			preimage = &workPackage.AuthorizationToken
		case 10:
			if workPackage == nil {
				break
			}
			serialized := serializer.Serialize(workPackage.RefinementContext)
			preimage = &serialized
		case 11:
			if workPackage == nil {
				break
			}
			blobs := make([]types.Blob, len(workPackage.WorkItems))
			for i, workItem := range workPackage.WorkItems {
				blobs[i] = serializeWorkItemForFetch(workItem)
			}
			serialized := serializer.Serialize(blobs)
			preimage = &serialized
		case 12:
			if workPackage == nil {
				break
			}
			if w11 >= types.Register(len(workPackage.WorkItems)) {
				break
			}
			serialized := serializeWorkItemForFetch(workPackage.WorkItems[int(w11)])
			preimage = &serialized
		case 13:
			if workPackage == nil {
				break
			}
			if w11 >= types.Register(len(workPackage.WorkItems)) {
				break
			}
			preimage = &workPackage.WorkItems[int(w11)].Payload
		case 14:
			if operandTuples == nil {
				break
			}
			serialized := serializer.Serialize(*operandTuples)
			preimage = &serialized
		case 15:
			if operandTuples == nil {
				break
			}
			if w11 >= types.Register(len(*operandTuples)) {
				break
			}
			serialized := serializer.Serialize((*operandTuples)[int(w11)])
			preimage = &serialized
		case 16:
			if deferredTransfers == nil {
				break
			}
			serialized := serializer.Serialize(*deferredTransfers)
			preimage = &serialized
		case 17:
			if deferredTransfers == nil {
				break
			}
			if w11 >= types.Register(len(*deferredTransfers)) {
				break
			}
			serialized := serializer.Serialize((*deferredTransfers)[int(w11)])
			preimage = &serialized
		}

		preimageLen := 0
		if preimage != nil {
			preimageLen = len(*preimage)
		}

		o := ctx.State.Registers[7]
		f := min(ctx.State.Registers[8], types.Register(preimageLen))

		// l = min(ω9, |v| - f)
		l := min(ctx.State.Registers[9], types.Register(preimageLen)-f)

		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		} else if preimage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preimageLen)
			slicedData := (*preimage)[int(f):int(f+l)]
			ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
		}
		return NewSimpleExitReason(ExitGo)
	})
}

func Export(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], exportSegmentOffset int) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		preimage := ctx.State.Registers[7]
		z := min(ctx.State.Registers[8], types.Register(constants.SegmentSize))
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(preimage), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}
		if exportSegmentOffset+len(ctx.Argument.ExportSequence) >= int(constants.MaxExportsInWorkPackage) {
			ctx.State.Registers[7] = types.Register(HostCallFull)
			return NewSimpleExitReason(ExitGo)
		}
		x := util.OctetArrayZeroPadding(ctx.State.RAM.InspectRange(uint64(preimage), uint64(z), ram.Wrap, false), int(constants.SegmentSize))
		ctx.State.Registers[7] = types.Register(exportSegmentOffset + len(ctx.Argument.ExportSequence))
		ctx.Argument.ExportSequence = append(ctx.Argument.ExportSequence, x)
		return NewSimpleExitReason(ExitGo)
	})
}

func Machine(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		po := ctx.State.Registers[7]
		pz := ctx.State.Registers[8]
		i := ctx.State.Registers[9]
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(po), uint64(pz), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}
		p := ctx.State.RAM.InspectRange(uint64(po), uint64(pz), ram.NoWrap, false)
		if _, _, _, ok := Deblob(p); !ok {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}
		n := uint64(0)
		for {
			if _, ok := ctx.Argument.IntegratedPVMs[n]; !ok {
				break
			}
			n++
		}
		u := ram.NewEmptyRAM()
		ctx.State.Registers[7] = types.Register(n)
		ctx.Argument.IntegratedPVMs[n] = IntegratedPVM{
			ProgramCode:        p,
			RAM:                u,
			InstructionCounter: i,
		}
		return NewSimpleExitReason(ExitGo)
	})
}

func Peek(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 4 parameters from registers
		n := ctx.State.Registers[7]  // Source integrated PVM index
		o := ctx.State.Registers[8]  // Destination memory address
		s := ctx.State.Registers[9]  // Source memory address
		z := ctx.State.Registers[10] // Length to copy

		// Check if destination range is accessible
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		sourcePVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		if sourcePVM.RAM.RangeHas(ram.Inaccessible, uint64(s), uint64(z), ram.NoWrap) {
			ctx.State.Registers[7] = types.Register(HostCallOOB)
			return NewSimpleExitReason(ExitGo)
		}

		// Copy the memory
		ctx.State.RAM.MutateRange(uint64(o), sourcePVM.RAM.InspectRange(uint64(s), uint64(z), ram.NoWrap, false), ram.Wrap, false)

		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Pages(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 3 parameters from registers
		n := ctx.State.Registers[7] // Target integrated PVM index
		p := ctx.State.Registers[8] // Start address
		c := ctx.State.Registers[9] // Count/length
		r := ctx.State.Registers[10]

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Check for invalid memory range
		// p < 16 ∨ p + c ≥ 2^32 / ZP
		if r > 4 || p < 16 || p+c >= (1<<32)/ram.PageSize {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		if r > 2 && targetPVM.RAM.RangeHas(ram.Inaccessible, uint64(p)*ram.PageSize, uint64(c)*ram.PageSize, ram.NoWrap) {
			ctx.State.Registers[7] = types.Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		if r < 3 {
			for i := uint64(p); i < uint64(p+c); i++ {
				targetPVM.RAM.ZeroPage(uint32(i))
			}
		}

		indexStart := uint64(p * ram.PageSize)
		indexEnd := indexStart + uint64(c*ram.PageSize)

		switch r {
		case 0:
			for i := uint64(p); i < uint64(p+c); i++ {
				targetPVM.RAM.ClearPageAccess(uint32(i))
			}
		case 1:
		case 3:
			targetPVM.RAM.MutateAccessRange(indexStart, indexEnd, ram.Immutable, ram.NoWrap)
		case 2:
		case 4:
			targetPVM.RAM.MutateAccessRange(indexStart, indexEnd, ram.Mutable, ram.NoWrap)
		}
		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Poke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 4 parameters from registers
		n := ctx.State.Registers[7]  // Target integrated PVM index
		s := ctx.State.Registers[8]  // Source address in current context
		o := ctx.State.Registers[9]  // Destination address in target PVM
		z := ctx.State.Registers[10] // Length to copy

		// Check if source range is accessible in current context
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(s), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if destination range is writable in target PVM
		if !targetPVM.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(z), ram.NoWrap) {
			ctx.State.Registers[7] = types.Register(HostCallOOB)
			return NewSimpleExitReason(ExitGo)
		}

		targetPVM.RAM.MutateRange(uint64(o), ctx.State.RAM.InspectRange(uint64(s), uint64(z), ram.Wrap, false), ram.NoWrap, false)

		// Set result to OK
		ctx.State.Registers[7] = types.Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Invoke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the parameters from registers
		n := ctx.State.Registers[7] // Target integrated PVM index
		o := ctx.State.Registers[8] // Memory offset for gas/weight data

		// Check if memory range o to o+112 is accessible for reading
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(112), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		gasData := ctx.State.RAM.InspectRange(uint64(o), 8, ram.NoWrap, false)
		registersData := ctx.State.RAM.InspectRange(uint64(o+8), 112, ram.NoWrap, false)

		gas := types.GasValue(serializer.DecodeLittleEndian(gasData))
		registers := [13]types.Register{}
		for i := range 13 {
			registers[i] = types.Register(serializer.DecodeLittleEndian(registersData[i*8 : i*8+8]))
		}

		pvm := NewPVM(targetPVM.ProgramCode, registers, targetPVM.RAM, targetPVM.InstructionCounter, gas)
		if pvm == nil {
			ctx.State.Registers[7] = types.Register(InnerPanic)
			return NewSimpleExitReason(ExitGo)
		}
		exitReason := pvm.Ψ()

		// Update memory with new gas and registers
		gasBytes := serializer.EncodeLittleEndian(8, uint64(pvm.State.Gas))
		ctx.State.RAM.MutateRange(uint64(o), gasBytes, ram.NoWrap, false)

		for i := range 13 {
			regBytes := serializer.EncodeLittleEndian(8, uint64(ctx.State.Registers[i]))
			ctx.State.RAM.MutateRange(uint64(o+8)+uint64(i*8), regBytes, ram.NoWrap, false)
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
		return NewSimpleExitReason(ExitGo)
	})
}

// Expunge removes an integrated PVM and returns its index
func Expunge(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the parameter from register
		n := ctx.State.Registers[7] // Target integrated PVM index to expunge

		// Check if integrated PVM exists
		_, ok := ctx.Argument.IntegratedPVMs[uint64(n)]
		if !ok {
			// n is not a key in the map, return WHO error
			ctx.State.Registers[7] = types.Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// PVM exists, store its index in Register 7
		// Here we're assuming the "i" component refers to the index, which is n
		ctx.State.Registers[7] = n

		// Remove the PVM from the map (m ∖ n)
		delete(ctx.Argument.IntegratedPVMs, uint64(n))

		return NewSimpleExitReason(ExitGo)
	})
}

func Lookup(ctx *HostFunctionContext[struct{}], serviceAccount *serviceaccount.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts serviceaccount.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(h), uint64(32), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		var a *serviceaccount.ServiceAccount

		// Determine which service account to use
		if ctx.State.Registers[7] == types.MaxRegister || ctx.State.Registers[7] == types.Register(serviceIndex) {
			a = serviceAccount
		} else if account, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
			a = account
		}

		var preImage *[]byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], ctx.State.RAM.InspectRange(uint64(h), 32, ram.NoWrap, false))
			if v, ok := a.PreimageLookup[serviceaccount.PreimageLookupKeyFromFullKey(keyArray)]; ok {
				byteSlice := []byte(v)
				preImage = &byteSlice
			}
		}

		// Calculate preimage length, offset and length to copy
		preImageLen := 0
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		// f = min(ω10, |v|)
		f := min(ctx.State.Registers[10], types.Register(preImageLen))

		// l = min(ω11, |v| - f)
		l := min(ctx.State.Registers[11], types.Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preImageLen)
			if l > 0 {
				slicedData := (*preImage)[int(f):int(f+l)]
				ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
			}
		}

		return NewSimpleExitReason(ExitGo)
	})
}

// HistoricalLookup retrieves a historical value for a key from a service account
func HistoricalLookup(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], serviceIndex types.ServiceIndex, serviceAccounts serviceaccount.ServiceAccounts, timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(h), uint64(32), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		var a *serviceaccount.ServiceAccount

		serviceAccountForProvidedIndex, ok := serviceAccounts[serviceIndex]
		// Determine which service account to use
		if ctx.State.Registers[7] == types.MaxRegister && ok {
			a = serviceAccountForProvidedIndex
		} else if serviceAccountForRegister, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
			a = serviceAccountForRegister
		}

		var preImage *[]byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], ctx.State.RAM.InspectRange(uint64(h), 32, ram.NoWrap, false))

			preImage = historicallookup.HistoricalLookup(a, timeslot, keyArray)
		}

		// Calculate preimage length, offset and length to copy
		preImageLen := 0
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		// f = min(ω10, |v|)
		f := min(ctx.State.Registers[10], types.Register(preImageLen))

		// l = min(ω11, |v| - f)
		l := min(ctx.State.Registers[11], types.Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = types.Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = types.Register(preImageLen)
			if l > 0 {
				slicedData := (*preImage)[int(f):int(f+l)]
				ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
			}
		}

		return NewSimpleExitReason(ExitGo)
	})
}

// helpers

func withGasCheck[T any](
	ctx *HostFunctionContext[T],
	fn func(*HostFunctionContext[T]) ExitReason,
) ExitReason {
	ctx.State.Gas -= types.SignedGasValue(GasUsage)
	if ctx.State.Gas < 0 {
		return NewSimpleExitReason(ExitOutOfGas)
	}
	return fn(ctx)
}

// check finds an unused service index, starting from the provided index
// If the initial index is already in use, it iteratively tries next indices
func check(i types.ServiceIndex, stateComponents *AccumulationStateComponents) types.ServiceIndex {
	// Get the service accounts map
	serviceAccounts := stateComponents.ServiceAccounts

	currentIndex := i

	// Keep trying until we find an unused index
	for {
		// Check if the index is already in use
		if _, exists := serviceAccounts[currentIndex]; !exists {
			// If not in use, return it
			return currentIndex
		}

		// Calculate the next index to try
		// (i − 2^8 + 1) mod (2^32 − 2^9) + 2^8
		currentIndex = types.ServiceIndex((1 << 8) + ((uint32(currentIndex) - (1 << 8) + 1) % (1<<32 - (1 << 9))))
	}
}
