package pvm

import (
	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workpackage"
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

type HostCallResult uint64

const maxUint64 = ^uint64(0)

const (
	// OK indicates general success.
	HostCallOK   HostCallResult = 0
	HostCallNone HostCallResult = HostCallResult(maxUint64 - 0) // 2^64 - 1: The item does not exist.
	HostCallWhat HostCallResult = HostCallResult(maxUint64 - 1) // 2^64 - 2: Name unknown.
	HostCallOOB  HostCallResult = HostCallResult(maxUint64 - 2) // 2^64 - 3: Memory index not accessible.
	HostCallWho  HostCallResult = HostCallResult(maxUint64 - 3) // 2^64 - 4: Index unknown.
	HostCallFull HostCallResult = HostCallResult(maxUint64 - 4) // 2^64 - 5: Storage full.
	HostCallCore HostCallResult = HostCallResult(maxUint64 - 5) // 2^64 - 6: Core index unknown.
	HostCallCash HostCallResult = HostCallResult(maxUint64 - 6) // 2^64 - 7: Insufficient funds.
	HostCallLow  HostCallResult = HostCallResult(maxUint64 - 7) // 2^64 - 8: Gas limit too low.
	HostCallHuh  HostCallResult = HostCallResult(maxUint64 - 8) // 2^64 - 9: Already solicited or cannot be forgotten.
)

func IsValidHostCallError(code HostCallResult) bool {
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

type HostFunction[X any] func(HostFunctionIdentifier, *State, X) (ExitReason, X)

const GasUsage types.GasValue = 10

// checkGas performs the common gas check pattern and returns the exit reason and post-gas value
func checkGas(gas types.GasValue) (ExitReason, types.SignedGasValue) {
	if gas < GasUsage {
		return NewSimpleExitReason(ExitOutOfGas), types.SignedGasValue(gas)
	}
	return NewSimpleExitReason(ExitGo), types.SignedGasValue(gas - GasUsage)
}

func Gas(gas types.GasValue, registers [13]Register, args ...any) (ExitReason, types.SignedGasValue, [13]Register, []any) {
	exitReason, postGas := checkGas(gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason, postGas, registers, args
	}
	registers[7] = Register(postGas)
	return exitReason, postGas, registers, args
}

func Lookup(gas types.GasValue, registers [13]Register, ram *RAM, serviceAccount state.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	// Define regular preimage retrieval strategy
	retrievePreimage := func(account *state.ServiceAccount, key [32]byte) *[]byte {
		v, ok := account.PreimageLookup[key]
		if ok {
			return &v
		}
		return nil
	}

	return performLookup(gas, registers, ram, serviceAccount, serviceIndex, serviceAccounts, false, retrievePreimage)
}

func HistoricalLookup(gas types.GasValue, registers [13]Register, ram *RAM, _ IntegratedPVMsAndExportSequence, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts, timeslot types.Timeslot, serviceAccount state.ServiceAccount) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	// Define historical preimage retrieval strategy
	retrievePreimage := func(account *state.ServiceAccount, key [32]byte) *[]byte {
		return historicallookup.HistoricalLookup(*account, timeslot, key)
	}

	return performLookup(gas, registers, ram, serviceAccount, serviceIndex, serviceAccounts, true, retrievePreimage)
}

func Fetch(gas types.GasValue, registers [13]Register, ram *RAM, _ IntegratedPVMsAndExportSequence, importSegmentsIndex int, workPackage workpackage.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte, serviceAccount state.ServiceAccount) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	exitReason, postGas := checkGas(gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason, postGas, registers, ram, serviceAccount
	}
	var preimage *[]byte
	switch registers[10] {
	case 0:
		serialized := serializer.Serialize(workPackage)
		preimage = &serialized
	case 1:
		preimage = &authorizerOutput
	case 2:
		if registers[11] < Register(len(workPackage.WorkItems)) {
			preimage = &workPackage.WorkItems[int(registers[11])].Payload
		}
	case 3:
		if registers[11] < Register(len(workPackage.WorkItems)) {
			blobHashesAndLengthsIntroduced := workPackage.WorkItems[int(registers[11])].BlobHashesAndLengthsIntroduced
			if registers[12] < Register(len(blobHashesAndLengthsIntroduced)) {
				blobHash := blobHashesAndLengthsIntroduced[int(registers[12])].BlobHash[:]
				preimage = &blobHash
			}
		}
	case 4:
		blobHashesAndLengthsIntroduced := workPackage.WorkItems[importSegmentsIndex].BlobHashesAndLengthsIntroduced
		if registers[11] < Register(len(blobHashesAndLengthsIntroduced)) {
			blobHash := blobHashesAndLengthsIntroduced[int(registers[11])].BlobHash[:]
			preimage = &blobHash
		}
	case 5:
		if registers[11] < Register(len(importSegments)) && registers[12] < Register(len(importSegments[registers[11]])) {
			segment := importSegments[registers[11]][registers[12]][:]
			preimage = &segment
		}
	case 6:
		if registers[11] < Register(len(importSegments[importSegmentsIndex])) {
			segment := importSegments[importSegmentsIndex][registers[11]][:]
			preimage = &segment
		}
	case 7:
		preimage = &workPackage.ParameterizationBlob
	}
	return processPreimage(
		postGas,
		registers,
		ram,
		serviceAccount,
		preimage,
		7,
		8,
		9,
		7,
	)
}

// helpers

func getServiceAccount(registers [13]Register, serviceIndex types.ServiceIndex, serviceAccount state.ServiceAccount, serviceAccounts state.ServiceAccounts, isHistorical bool) *state.ServiceAccount {
	var a *state.ServiceAccount

	if isHistorical {
		if registers[7] == MaxRegister {
			if s, ok := serviceAccounts[serviceIndex]; ok {
				a = &s
			}
		} else if s, ok := serviceAccounts[types.ServiceIndex(registers[7])]; ok {
			a = &s
		}
	} else {
		if registers[7] == Register(serviceIndex) || registers[7] == MaxRegister {
			a = &serviceAccount
		} else if s, ok := serviceAccounts[types.ServiceIndex(registers[7])]; ok {
			a = &s
		}
	}

	return a
}

func processPreimage(
	postGas types.SignedGasValue,
	registers [13]Register,
	ram *RAM,
	serviceAccount state.ServiceAccount,
	preimage *[]byte,
	outputRegister int, // Register containing output address
	offsetRegister int, // Register containing offset
	lengthRegister int, // Register containing length
	resultRegister int, // Register where result will be stored
) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	exitReason := NewSimpleExitReason(ExitGo) // Default to success

	preimageLen := 0
	if preimage != nil {
		preimageLen = len(*preimage)
	}

	o := registers[outputRegister]
	f := min(registers[offsetRegister], Register(preimageLen))
	l := min(registers[lengthRegister], Register(preimageLen)-f)

	if !ram.rangeUniform(RamAccess(WriteID), RamIndex(o), RamIndex(o+l)) {
		exitReason = NewSimpleExitReason(ExitPanic)
	} else if preimage == nil {
		registers[resultRegister] = Register(HostCallNone)
	} else {
		registers[resultRegister] = Register(preimageLen)
		slicedData := (*preimage)[int(f):int(f+l)]
		ram.mutateRange(o, slicedData, &[]RamIndex{})
	}

	return exitReason, postGas, registers, ram, serviceAccount
}

// PreimageRetriever defines a function type for retrieving preimages
type PreimageRetriever func(account *state.ServiceAccount, key [32]byte) *[]byte

// performLookup handles the common lookup logic for both regular and historical lookups
func performLookup(
	gas types.GasValue,
	registers [13]Register,
	ram *RAM,
	serviceAccount state.ServiceAccount,
	serviceIndex types.ServiceIndex,
	serviceAccounts state.ServiceAccounts,
	isHistorical bool,
	retrievePreimage PreimageRetriever,
) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	exitReason, postGas := checkGas(gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason, postGas, registers, ram, serviceAccount
	}

	a := getServiceAccount(registers, serviceIndex, serviceAccount, serviceAccounts, isHistorical)
	h := registers[8]

	var preimage *[]byte
	if ram.rangeHas(Inaccessible, RamIndex(h), RamIndex(h+32)) {
		return NewSimpleExitReason(ExitPanic), postGas, registers, ram, serviceAccount
	} else if a != nil {
		var key [32]byte
		copy(key[:], ram.inspectRange(h, 32, &[]RamIndex{}))
		preimage = retrievePreimage(a, key)
	}

	return processPreimage(postGas, registers, ram, serviceAccount, preimage, 9, 10, 11, 7)
}
