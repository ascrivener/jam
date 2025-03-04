package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	s "github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/util"
	"github.com/ascrivener/jam/workpackage"
	"golang.org/x/crypto/blake2b"
)

type HostFunctionIdentifier int

const (
	GasID HostFunctionIdentifier = iota
	LookupID
	ReadID
	WriteID
	InfoID
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
	HistoricalLookupID
	FetchID
	ExportID
	MachineID
	PeekID
	PokeID
	ZeroID
	VoidID
	InvokeID
	ExpungeID
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

func Gas(state *State, args ...any) ExitReason {
	if state.Gas < 0 {
		return NewSimpleExitReason(ExitOutOfGas)
	}
	return NewSimpleExitReason(ExitGo)
}

// VerifyAndReturnStateForAccessor implements the state lookup host function
// as specified in the graypaper. It verifies access, computes a key hash,
// and returns data from state if available.
func Read(ctx *HostFunctionContext[struct{}], serviceAccount s.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts s.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {

		// Determine s* based on ω7
		var sStar Register
		if ctx.State.Registers[7] == Register(^uint64(0)) { // 2^64 - 1
			sStar = Register(serviceIndex)
		} else {
			sStar = ctx.State.Registers[7]
		}

		// Determine 'a' based on s*
		var a *s.ServiceAccount
		if sStar == Register(serviceIndex) {
			// a = s
			a = &serviceAccount
		} else if sStar <= Register(^uint32(0)) {
			// Check if sStar can fit in uint32 range
			if serviceAcc, ok := serviceAccounts[types.ServiceIndex(sStar)]; ok {
				a = &serviceAcc
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
			if val, ok := a.StorageDictionary[keyArray]; ok {
				preImage = &val
			}
		}

		// Calculate f and l
		var preImageLen int
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		f := min(ctx.State.Registers[11], Register(preImageLen))
		l := min(ctx.State.Registers[12], Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = Register(preImageLen)
			slicedData := (*preImage)[int(f):int(f+l)]
			ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
		}

		return NewSimpleExitReason(ExitGo)
	})
}

func Write(ctx *HostFunctionContext[struct{}], serviceAccount *s.ServiceAccount, serviceIndex types.ServiceIndex) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		// Extract [ko, kz, vo, vz] from registers ω7⋅⋅⋅+4
		ko := ctx.State.Registers[7]  // Key offset
		kz := ctx.State.Registers[8]  // Key length
		vo := ctx.State.Registers[9]  // Value offset
		vz := ctx.State.Registers[10] // Value length

		// Check if key memory range is accessible
		keyValid := !ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(ko), uint64(kz), ram.NoWrap)
		if !keyValid {
			return NewSimpleExitReason(ExitPanic)
		}

		// Compute the key hash
		serviceIdBytes := serializer.EncodeLittleEndian(4, uint64(serviceIndex))
		keyBytes := ctx.State.RAM.InspectRange(uint64(ko), uint64(kz), ram.NoWrap, false)
		combinedBytes := append(serviceIdBytes, keyBytes...)

		var keyArray [32]byte
		h := blake2b.Sum256(combinedBytes)
		copy(keyArray[:], h[:])

		// Prepare modified account
		modifiedAccount := serviceAccount // Create a copy

		// Handle according to vz (value length)
		if vz == 0 {
			// If vz = 0, remove entry
			delete(modifiedAccount.StorageDictionary, keyArray)
		} else {
			// Check if value memory range is accessible
			if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(vo), uint64(vz), ram.NoWrap) {
				return NewSimpleExitReason(ExitPanic)
			}

			// Write the value to the account storage
			valueBytes := ctx.State.RAM.InspectRange(uint64(vo), uint64(vz), ram.NoWrap, false)
			modifiedAccount.StorageDictionary[keyArray] = valueBytes
		}

		// Determine 'l' - length of previous value if it exists, NONE otherwise
		var l Register
		if val, ok := serviceAccount.StorageDictionary[keyArray]; ok {
			l = Register(len(val))
		} else {
			l = Register(HostCallNone)
		}

		if modifiedAccount.ThresholdBalanceNeeded() > modifiedAccount.Balance {
			ctx.State.Registers[7] = Register(HostCallFull)
		} else {
			ctx.State.Registers[7] = l
			// Update the service account
			*serviceAccount = *modifiedAccount
		}

		return NewSimpleExitReason(ExitGo)
	})
}

// AccountInfo represents the structured account information for serialization
type AccountInfo struct {
	CodeHash                       [32]byte                                                 // c
	Balance                        types.Balance                                            // b
	ThresholdBalanceNeeded         types.Balance                                            // t
	MinimumGasForAccumulate        types.GasValue                                           // g
	MinimumGasForOnTransfer        types.GasValue                                           // m
	PreimageLookupHistoricalStatus map[s.PreimageLookupHistoricalStatusKey][]types.Timeslot // l
	StorageItems                   uint32                                                   // i
}

func Info(ctx *HostFunctionContext[struct{}], serviceIndex types.ServiceIndex, serviceAccounts s.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		// Determine the target service account (t)
		var targetAccount *s.ServiceAccount

		// If ω7 = 2^64 - 1, use service account parameter, otherwise lookup by index
		if ctx.State.Registers[7] == Register(^uint64(0)) {
			s := serviceAccounts[serviceIndex]
			targetAccount = &s
		} else if ctx.State.Registers[7] <= Register(^uint32(0)) {
			// Check if ω7 can fit in uint32 range
			if account, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
				targetAccount = &account
			}
		}

		// Get output offset (o) from ω8
		outputOffset := ctx.State.Registers[8]

		// If target account exists, encode its information
		if targetAccount != nil {
			// Create struct with account information
			accountInfo := AccountInfo{
				CodeHash:                       targetAccount.CodeHash,
				Balance:                        targetAccount.Balance,
				ThresholdBalanceNeeded:         targetAccount.ThresholdBalanceNeeded(),
				MinimumGasForAccumulate:        targetAccount.MinimumGasForAccumulate,
				MinimumGasForOnTransfer:        targetAccount.MinimumGasForOnTransfer,
				PreimageLookupHistoricalStatus: targetAccount.PreimageLookupHistoricalStatus,
				StorageItems:                   targetAccount.TotalItemsUsedInStorage(),
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
			ctx.State.Registers[7] = Register(HostCallOK)
		} else {
			// Target account not found
			ctx.State.Registers[7] = Register(HostCallNone)
		}

		return NewSimpleExitReason(ExitGo)
	})
}

func Bless(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Extract registers: [m, a, v, o, n] = ω7⋅⋅⋅+5
		mainIndex := ctx.State.Registers[7]   // m - Main service index
		authIndex := ctx.State.Registers[8]   // a - Authorization service index
		validIndex := ctx.State.Registers[9]  // v - Validation service index
		offset := ctx.State.Registers[10]     // o - Memory offset
		numEntries := ctx.State.Registers[11] // n - Number of entries

		// Check if memory range is accessible
		entrySize := uint64(12) // Each entry is 12 bytes (4 for service index, 8 for gas value)
		totalSize := entrySize * uint64(numEntries)

		memoryValid := !ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), totalSize, ram.NoWrap)
		if !memoryValid {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if m, a, v are valid ServiceIndices
		if mainIndex > Register(^uint32(0)) || authIndex > Register(^uint32(0)) || validIndex > Register(^uint32(0)) {
			ctx.State.Registers[7] = Register(HostCallWho)
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

		// Update the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.PrivilegedServices = state.PrivilegedServices{
			ManagerServiceIndex:             types.ServiceIndex(mainIndex),
			AssignServiceIndex:              types.ServiceIndex(authIndex),
			DesignateServiceIndex:           types.ServiceIndex(validIndex),
			AlwaysAccumulateServicesWithGas: serviceGasMap,
		}
		ctx.State.Registers[7] = Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Assign(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get core index from ω7 and memory offset from ω8
		coreIndex := ctx.State.Registers[7]
		offset := ctx.State.Registers[8]

		// Calculate the size of the authorizersQueue array
		queueLength := constants.AuthorizerQueueLength
		totalSize := 32 * queueLength // 32 bytes per hash * queue length

		// Check if memory range is accessible (c = ∇)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), uint64(totalSize), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if core index is within valid range
		if coreIndex >= Register(constants.NumCores) {
			ctx.State.Registers[7] = Register(HostCallCore)
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

		// Set successful result
		ctx.State.Registers[7] = Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Designate(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get memory offset from ω7
		offset := ctx.State.Registers[7]

		// Calculate total size needed for validator keysets
		// Each validator keyset is 336 bytes, and we need constants.NumValidators of them
		totalSize := uint64(336 * constants.NumValidators)

		// Check if memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), totalSize, ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Read the validator keysets from memory
		validatorKeysets := [constants.NumValidators]types.ValidatorKeyset{}
		for i := 0; i < constants.NumValidators; i++ {
			keysetOffset := uint64(offset) + uint64(i)*336
			keysetBytes := ctx.State.RAM.InspectRange(keysetOffset, 336, ram.NoWrap, false)

			// Copy the keyset bytes
			copy(validatorKeysets[i][:], keysetBytes)
		}

		// Update the validator keysets in the accumulation context
		ctx.Argument.AccumulationResultContext.StateComponents.UpcomingValidatorKeysets = validatorKeysets

		// Set successful result
		ctx.State.Registers[7] = Register(HostCallOK)

		return NewSimpleExitReason(ExitGo)
	})
}

func Checkpoint(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		ctx.Argument.ExceptionalAccumulationResultContext = ctx.Argument.AccumulationResultContext
		ctx.State.Registers[7] = Register(ctx.State.Gas)

		return NewSimpleExitReason(ExitGo)
	})
}

func New(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[AccumulateInvocationContext]) ExitReason {
		// Get parameters from registers [o, l, g, m] = ω7⋅⋅⋅+4
		offset := ctx.State.Registers[7]               // o - memory offset for code hash
		labelLength := ctx.State.Registers[8]          // l - label length
		minGasForAccumulate := ctx.State.Registers[9]  // g - minimum gas for accumulate
		minGasForOnTransfer := ctx.State.Registers[10] // m - minimum gas for on transfer

		// Check if memory range for code hash is accessible (c = ∇ check)
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(offset), 32, ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Read code hash from memory
		codeHashBytes := ctx.State.RAM.InspectRange(uint64(offset), 32, ram.NoWrap, false)
		var codeHash [32]byte
		copy(codeHash[:], codeHashBytes)

		// Create preimage history map with the code hash and label length as key
		preimageHistory := make(map[s.PreimageLookupHistoricalStatusKey][]types.Timeslot)
		key := s.PreimageLookupHistoricalStatusKey{
			Preimage:   codeHash,
			BlobLength: types.BlobLength(labelLength),
		}
		preimageHistory[key] = []types.Timeslot{}

		// Create new service account
		newAccount := s.ServiceAccount{
			CodeHash:                       codeHash,
			StorageDictionary:              make(map[[32]byte][]byte),
			PreimageLookupHistoricalStatus: preimageHistory,
			MinimumGasForAccumulate:        types.GasValue(minGasForAccumulate),
			MinimumGasForOnTransfer:        types.GasValue(minGasForOnTransfer),
		}
		newAccount.Balance = newAccount.ThresholdBalanceNeeded()

		accumulatingServiceAccount := ctx.Argument.AccumulatingServiceAccount()
		accumulatingServiceAccount.Balance -= newAccount.ThresholdBalanceNeeded()
		// Check if source has enough balance after the transfer (sb < (xs)t check)
		// The source account needs enough balance to cover both:
		// 1. Its own threshold balance needs
		// 2. The transfer amount to the new account
		if accumulatingServiceAccount.Balance < ctx.Argument.AccumulatingServiceAccount().ThresholdBalanceNeeded() {
			ctx.State.Registers[7] = Register(HostCallCash)
			return NewSimpleExitReason(ExitGo)
		}

		currentDerivedServiceIndex := ctx.Argument.AccumulationResultContext.DerivedServiceIndex
		newDerivedServiceIndex := types.ServiceIndex((1 << 8) + (currentDerivedServiceIndex-(1<<8)+42)%(1<<32-1<<9))

		// Get current service accounts and update them
		serviceAccounts := ctx.Argument.AccumulationResultContext.StateComponents.ServiceAccounts
		serviceAccounts[ctx.Argument.AccumulationResultContext.AccumulatingServiceIndex] = accumulatingServiceAccount
		serviceAccounts[currentDerivedServiceIndex] = newAccount

		ctx.State.Registers[7] = Register(currentDerivedServiceIndex)
		ctx.Argument.AccumulationResultContext.DerivedServiceIndex = check(newDerivedServiceIndex, ctx.Argument.AccumulationResultContext.StateComponents)

		return NewSimpleExitReason(ExitGo)
	})
}

func Fetch(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], importSegmentsIndex int, workPackage workpackage.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		var preimage *[]byte
		switch ctx.State.Registers[10] {
		case 0:
			serialized := serializer.Serialize(workPackage)
			preimage = &serialized
		case 1:
			preimage = &authorizerOutput
		case 2:
			if ctx.State.Registers[11] < Register(len(workPackage.WorkItems)) {
				preimage = &workPackage.WorkItems[int(ctx.State.Registers[11])].Payload
			}
		case 3:
			if ctx.State.Registers[11] < Register(len(workPackage.WorkItems)) {
				blobHashesAndLengthsIntroduced := workPackage.WorkItems[int(ctx.State.Registers[11])].BlobHashesAndLengthsIntroduced
				if ctx.State.Registers[12] < Register(len(blobHashesAndLengthsIntroduced)) {
					blobHash := blobHashesAndLengthsIntroduced[int(ctx.State.Registers[12])].BlobHash[:]
					preimage = &blobHash
				}
			}
		case 4:
			blobHashesAndLengthsIntroduced := workPackage.WorkItems[importSegmentsIndex].BlobHashesAndLengthsIntroduced
			if ctx.State.Registers[11] < Register(len(blobHashesAndLengthsIntroduced)) {
				blobHash := blobHashesAndLengthsIntroduced[int(ctx.State.Registers[11])].BlobHash[:]
				preimage = &blobHash
			}
		case 5:
			if ctx.State.Registers[11] < Register(len(importSegments)) && ctx.State.Registers[12] < Register(len(importSegments[ctx.State.Registers[11]])) {
				segment := importSegments[ctx.State.Registers[11]][ctx.State.Registers[12]][:]
				preimage = &segment
			}
		case 6:
			if ctx.State.Registers[11] < Register(len(importSegments[importSegmentsIndex])) {
				segment := importSegments[importSegmentsIndex][ctx.State.Registers[11]][:]
				preimage = &segment
			}
		case 7:
			preimage = &workPackage.ParameterizationBlob
		}

		preimageLen := 0
		if preimage != nil {
			preimageLen = len(*preimage)
		}

		o := ctx.State.Registers[7]
		f := min(ctx.State.Registers[8], Register(preimageLen))

		// l = min(ω11, |v| - f)
		l := min(ctx.State.Registers[9], Register(preimageLen)-f)

		if !ctx.State.RAM.RangeUniform(ram.RamAccess(WriteID), uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		} else if preimage == nil {
			ctx.State.Registers[7] = Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = Register(preimageLen)
			slicedData := (*preimage)[int(f):int(f+l)]
			ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
		}
		return NewSimpleExitReason(ExitGo)
	})
}

func Export(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], exportSegmentOffset int) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		preimage := ctx.State.Registers[7]
		z := min(ctx.State.Registers[8], Register(SegmentSize))
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(preimage), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}
		if exportSegmentOffset+len(ctx.Argument.ExportSequence) >= WorkPackageManifestMaxEntries {
			ctx.State.Registers[7] = Register(HostCallFull)
			return NewSimpleExitReason(ExitGo)
		}
		x := util.OctetArrayZeroPadding(ctx.State.RAM.InspectRange(uint64(preimage), uint64(z), ram.Wrap, false), SegmentSize)
		ctx.State.Registers[7] = Register(exportSegmentOffset + len(ctx.Argument.ExportSequence))
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
			ctx.State.Registers[7] = Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}
		n := 0
		for {
			if _, ok := ctx.Argument.IntegratedPVMs[n]; !ok {
				break
			}
			n++
		}
		u := ram.NewEmptyRAM()
		ctx.State.Registers[7] = Register(n)
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
		n := int(ctx.State.Registers[7]) // Source integrated PVM index
		o := ctx.State.Registers[8]      // Destination memory address
		s := ctx.State.Registers[9]      // Source memory address
		z := ctx.State.Registers[10]     // Length to copy

		// Check if destination range is accessible
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		sourcePVM, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		if sourcePVM.RAM.RangeHas(ram.Inaccessible, uint64(s), uint64(z), ram.NoWrap) {
			ctx.State.Registers[7] = Register(HostCallOOB)
			return NewSimpleExitReason(ExitGo)
		}

		// Copy the memory
		ctx.State.RAM.MutateRange(uint64(o), sourcePVM.RAM.InspectRange(uint64(s), uint64(z), ram.NoWrap, false), ram.Wrap, false)

		// Set result to OK
		ctx.State.Registers[7] = Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Zero(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 3 parameters from registers
		n := int(ctx.State.Registers[7]) // Target integrated PVM index
		p := ctx.State.Registers[8]      // Start address
		c := ctx.State.Registers[9]      // Count/length

		// Check for invalid memory range
		// p < 16 ∨ p + c ≥ 2^32 / ZP
		if p < 16 || p+c >= (1<<32)/ram.PageSize {
			ctx.State.Registers[7] = Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		pPageStart := p * ram.PageSize
		cPagesSize := c * ram.PageSize
		// Zero out the memory range
		// First create a zero-filled slice of the right size
		zeroBytes := make([]byte, cPagesSize)
		targetPVM.RAM.MutateRange(uint64(pPageStart), zeroBytes, ram.NoWrap, false)
		targetPVM.RAM.MutateAccessRange(uint64(pPageStart), uint64(cPagesSize), ram.Mutable, ram.NoWrap)

		// Set result to OK
		ctx.State.Registers[7] = Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Poke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 4 parameters from registers
		n := int(ctx.State.Registers[7]) // Target integrated PVM index
		s := ctx.State.Registers[8]      // Source address in current context
		o := ctx.State.Registers[9]      // Destination address in target PVM
		z := ctx.State.Registers[10]     // Length to copy

		// Check if source range is accessible in current context
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(s), uint64(z), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if destination range is writable in target PVM
		if !targetPVM.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(z), ram.NoWrap) {
			ctx.State.Registers[7] = Register(HostCallOOB)
			return NewSimpleExitReason(ExitGo)
		}

		targetPVM.RAM.MutateRange(uint64(o), ctx.State.RAM.InspectRange(uint64(s), uint64(z), ram.Wrap, false), ram.NoWrap, false)

		// Set result to OK
		ctx.State.Registers[7] = Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Void(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the 3 parameters from registers
		n := int(ctx.State.Registers[7])     // Target integrated PVM index
		pPageIndex := ctx.State.Registers[8] // Start address
		cPages := ctx.State.Registers[9]     // length
		pPageStart := pPageIndex * ram.PageSize
		cPagesSize := cPages * ram.PageSize

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// Check if memory range is valid and accessible
		if pPageIndex < 16 || pPageIndex+cPages >= (1<<32)/ram.PageSize ||
			targetPVM.RAM.RangeHas(ram.Inaccessible, uint64(pPageStart), uint64(cPagesSize), ram.NoWrap) {
			ctx.State.Registers[7] = Register(HostCallHuh)
			return NewSimpleExitReason(ExitGo)
		}

		// Zero out the memory by filling it with zeros
		zeroBytes := make([]byte, cPagesSize)
		targetPVM.RAM.MutateRange(uint64(pPageStart), zeroBytes, ram.NoWrap, false)
		// Set the memory to inaccessible
		targetPVM.RAM.MutateAccessRange(uint64(pPageStart), uint64(cPagesSize), ram.Inaccessible, ram.NoWrap)

		// Set result to OK
		ctx.State.Registers[7] = Register(HostCallOK)
		return NewSimpleExitReason(ExitGo)
	})
}

func Invoke(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the parameters from registers
		n := int(ctx.State.Registers[7]) // Target integrated PVM index
		o := ctx.State.Registers[8]      // Memory offset for gas/weight data

		// Check if memory range o to o+112 is accessible for reading
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(112), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Check if integrated PVM exists
		targetPVM, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		gasData := ctx.State.RAM.InspectRange(uint64(o), 8, ram.NoWrap, false)
		registersData := ctx.State.RAM.InspectRange(uint64(o+8), 112, ram.NoWrap, false)

		gas := types.GasValue(serializer.DecodeLittleEndian(gasData))
		registers := [13]Register{}
		for i := range 13 {
			registers[i] = Register(serializer.DecodeLittleEndian(registersData[i*8 : i*8+8]))
		}

		pvm := NewPVM(targetPVM.ProgramCode, registers, targetPVM.RAM, targetPVM.InstructionCounter, gas)
		if pvm == nil {
			ctx.State.Registers[7] = Register(InnerPanic)
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
				ctx.State.Registers[7] = Register(InnerHost)
			} else {
				ctx.State.Registers[7] = Register(InnerFault)
			}
			ctx.State.Registers[8] = exitReason.ComplexExitReason.Parameter
		} else {
			switch *exitReason.SimpleExitReason {
			case ExitOutOfGas:
				ctx.State.Registers[7] = Register(InnerOOG)
			case ExitPanic:
				ctx.State.Registers[7] = Register(InnerPanic)
			case ExitHalt:
				ctx.State.Registers[7] = Register(InnerHalt)
			default:
				panic(fmt.Sprintf("unreachable: unhandled simple exit reason %v", *exitReason.SimpleExitReason))
			}
		}
		// Always update the integrated PVM in one place
		ctx.Argument.IntegratedPVMs[n] = targetPVM
		return NewSimpleExitReason(ExitGo)
	})
}

// Expunge removes an integrated PVM and returns its index
func Expunge(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		// Extract the parameter from register
		n := int(ctx.State.Registers[7]) // Target integrated PVM index to expunge

		// Check if integrated PVM exists
		_, ok := ctx.Argument.IntegratedPVMs[n]
		if !ok {
			// n is not a key in the map, return WHO error
			ctx.State.Registers[7] = Register(HostCallWho)
			return NewSimpleExitReason(ExitGo)
		}

		// PVM exists, store its index in Register 7
		// Here we're assuming the "i" component refers to the index, which is n
		ctx.State.Registers[7] = Register(n)

		// Remove the PVM from the map (m ∖ n)
		delete(ctx.Argument.IntegratedPVMs, n)

		return NewSimpleExitReason(ExitGo)
	})
}

func Lookup(ctx *HostFunctionContext[struct{}], serviceAccount s.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts s.ServiceAccounts) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[struct{}]) ExitReason {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(h), uint64(32), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		var a *s.ServiceAccount

		// Determine which service account to use
		if ctx.State.Registers[7] == MaxRegister || ctx.State.Registers[7] == Register(serviceIndex) {
			a = &serviceAccount
		} else if account, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
			a = &account
		}

		var preImage *[]byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], ctx.State.RAM.InspectRange(uint64(h), 32, ram.NoWrap, false))
			if v, ok := a.PreimageLookup[keyArray]; ok {
				preImage = &v
			}
		}

		// Calculate preimage length, offset and length to copy
		preImageLen := 0
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		// f = min(ω10, |v|)
		f := min(ctx.State.Registers[10], Register(preImageLen))

		// l = min(ω11, |v| - f)
		l := min(ctx.State.Registers[11], Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = Register(preImageLen)
			if l > 0 {
				slicedData := (*preImage)[int(f):int(f+l)]
				ctx.State.RAM.MutateRange(uint64(o), slicedData, ram.NoWrap, false)
			}
		}

		return NewSimpleExitReason(ExitGo)
	})
}

// HistoricalLookup retrieves a historical value for a key from a service account
func HistoricalLookup(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence], serviceIndex types.ServiceIndex, serviceAccounts s.ServiceAccounts, timeslot types.Timeslot) ExitReason {
	return withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
		h := ctx.State.Registers[8] // Address of the key
		o := ctx.State.Registers[9] // Output address

		// Check if key memory range is accessible
		if ctx.State.RAM.RangeHas(ram.Inaccessible, uint64(h), uint64(32), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		var a *s.ServiceAccount

		serviceAccountForProvidedIndex, ok := serviceAccounts[serviceIndex]
		// Determine which service account to use
		if ctx.State.Registers[7] == MaxRegister && ok {
			a = &serviceAccountForProvidedIndex
		} else if serviceAccountForRegister, ok := serviceAccounts[types.ServiceIndex(ctx.State.Registers[7])]; ok {
			a = &serviceAccountForRegister
		}

		var preImage *[]byte
		if a != nil {
			var keyArray [32]byte
			copy(keyArray[:], ctx.State.RAM.InspectRange(uint64(h), 32, ram.NoWrap, false))

			preImage = historicallookup.HistoricalLookup(*a, timeslot, keyArray)
		}

		// Calculate preimage length, offset and length to copy
		preImageLen := 0
		if preImage != nil {
			preImageLen = len(*preImage)
		}

		// f = min(ω10, |v|)
		f := min(ctx.State.Registers[10], Register(preImageLen))

		// l = min(ω11, |v| - f)
		l := min(ctx.State.Registers[11], Register(preImageLen)-f)

		// Check if output memory range is writable
		if !ctx.State.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(l), ram.NoWrap) {
			return NewSimpleExitReason(ExitPanic)
		}

		// Set result in register 7 and copy data to memory
		if preImage == nil {
			ctx.State.Registers[7] = Register(HostCallNone)
		} else {
			ctx.State.Registers[7] = Register(preImageLen)
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
	exitReason := Gas(ctx.State)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason
	}
	return fn(ctx)
}

// check finds an unused service index, starting from the provided index
// If the initial index is already in use, it iteratively tries next indices
func check(i types.ServiceIndex, stateComponents AccumulationStateComponents) types.ServiceIndex {
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
		// (i − 28 + 1) mod (232 − 29) + 28
		currentIndex = types.ServiceIndex((1 << 8) + ((uint32(currentIndex) - (1 << 8) + 1) % (1<<32 - (1 << 9))) + (1 << 8))
	}
}
