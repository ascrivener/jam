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

type HostCallResultType uint64

const maxUint64 = ^uint64(0)

const (
	// OK indicates general success.
	HostCallOK   HostCallResultType = 0
	HostCallNone HostCallResultType = HostCallResultType(maxUint64 - 0) // 2^64 - 1: The item does not exist.
	HostCallWhat HostCallResultType = HostCallResultType(maxUint64 - 1) // 2^64 - 2: Name unknown.
	HostCallOOB  HostCallResultType = HostCallResultType(maxUint64 - 2) // 2^64 - 3: Memory index not accessible.
	HostCallWho  HostCallResultType = HostCallResultType(maxUint64 - 3) // 2^64 - 4: Index unknown.
	HostCallFull HostCallResultType = HostCallResultType(maxUint64 - 4) // 2^64 - 5: Storage full.
	HostCallCore HostCallResultType = HostCallResultType(maxUint64 - 5) // 2^64 - 6: Core index unknown.
	HostCallCash HostCallResultType = HostCallResultType(maxUint64 - 6) // 2^64 - 7: Insufficient funds.
	HostCallLow  HostCallResultType = HostCallResultType(maxUint64 - 7) // 2^64 - 8: Gas limit too low.
	HostCallHuh  HostCallResultType = HostCallResultType(maxUint64 - 8) // 2^64 - 9: Already solicited or cannot be forgotten.
)

func IsValidHostCallError(code HostCallResultType) bool {
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

// HostResult encapsulates the common return values from host functions
type HostCallResult struct {
	ExitReason     ExitReason
	PostGas        types.SignedGasValue
	Registers      [13]Register
	RAM            *RAM
	ServiceAccount state.ServiceAccount
}

type HostCallContext struct {
	Gas            types.GasValue
	Registers      [13]Register
	RAM            *RAM
	ServiceAccount state.ServiceAccount
}

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

func Lookup(ctx HostCallContext, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts) HostCallResult {
	// Define regular preimage retrieval strategy
	retrievePreimage := func(account *state.ServiceAccount, key [32]byte) *[]byte {
		v, ok := account.PreimageLookup[key]
		if ok {
			return &v
		}
		return nil
	}

	return performLookup(ctx, serviceIndex, serviceAccounts, false, retrievePreimage)
}

func HistoricalLookup(ctx HostCallContext, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts, timeslot types.Timeslot) HostCallResult {
	// Define historical preimage retrieval strategy
	retrievePreimage := func(account *state.ServiceAccount, key [32]byte) *[]byte {
		return historicallookup.HistoricalLookup(*account, timeslot, key)
	}

	return performLookup(ctx, serviceIndex, serviceAccounts, true, retrievePreimage)
}

func Fetch(ctx HostCallContext, importSegmentsIndex int, workPackage workpackage.WorkPackage, authorizerOutput []byte, importSegments [][][SegmentSize]byte) HostCallResult {
	return withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		var preimage *[]byte
		switch ctx.Registers[10] {
		case 0:
			serialized := serializer.Serialize(workPackage)
			preimage = &serialized
		case 1:
			preimage = &authorizerOutput
		case 2:
			if ctx.Registers[11] < Register(len(workPackage.WorkItems)) {
				preimage = &workPackage.WorkItems[int(ctx.Registers[11])].Payload
			}
		case 3:
			if ctx.Registers[11] < Register(len(workPackage.WorkItems)) {
				blobHashesAndLengthsIntroduced := workPackage.WorkItems[int(ctx.Registers[11])].BlobHashesAndLengthsIntroduced
				if ctx.Registers[12] < Register(len(blobHashesAndLengthsIntroduced)) {
					blobHash := blobHashesAndLengthsIntroduced[int(ctx.Registers[12])].BlobHash[:]
					preimage = &blobHash
				}
			}
		case 4:
			blobHashesAndLengthsIntroduced := workPackage.WorkItems[importSegmentsIndex].BlobHashesAndLengthsIntroduced
			if ctx.Registers[11] < Register(len(blobHashesAndLengthsIntroduced)) {
				blobHash := blobHashesAndLengthsIntroduced[int(ctx.Registers[11])].BlobHash[:]
				preimage = &blobHash
			}
		case 5:
			if ctx.Registers[11] < Register(len(importSegments)) && ctx.Registers[12] < Register(len(importSegments[ctx.Registers[11]])) {
				segment := importSegments[ctx.Registers[11]][ctx.Registers[12]][:]
				preimage = &segment
			}
		case 6:
			if ctx.Registers[11] < Register(len(importSegments[importSegmentsIndex])) {
				segment := importSegments[importSegmentsIndex][ctx.Registers[11]][:]
				preimage = &segment
			}
		case 7:
			preimage = &workPackage.ParameterizationBlob
		}
		return processPreimage(
			ctx,
			postGas,
			preimage,
			7,
			8,
			9,
			7,
		)
	})
}

// func Export(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence, exportSegmentOffset int) HostCallResult {
// 	return withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {

// 	})
// }

// helpers

func withGasCheck(
	ctx HostCallContext,
	fn func(HostCallContext, types.SignedGasValue) HostCallResult,
) HostCallResult {
	exitReason, postGas := checkGas(ctx.Gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return HostCallResult{
			ExitReason:     exitReason,
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	}

	// Pass postGas as a separate parameter
	return fn(ctx, postGas)
}

func getServiceAccount(ctx HostCallContext, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts, isHistorical bool) *state.ServiceAccount {
	var a *state.ServiceAccount

	if isHistorical {
		if ctx.Registers[7] == MaxRegister {
			if s, ok := serviceAccounts[serviceIndex]; ok {
				a = &s
			}
		} else if s, ok := serviceAccounts[types.ServiceIndex(ctx.Registers[7])]; ok {
			a = &s
		}
	} else {
		if ctx.Registers[7] == MaxRegister {
			a = &ctx.ServiceAccount
		} else if s, ok := serviceAccounts[types.ServiceIndex(ctx.Registers[7])]; ok {
			a = &s
		}
	}

	return a
}

func processPreimage(
	ctx HostCallContext,
	postGas types.SignedGasValue,
	preimage *[]byte,
	outputRegister int, // Register containing output address
	offsetRegister int, // Register containing offset
	lengthRegister int, // Register containing length
	resultRegister int, // Register where result will be stored
) HostCallResult {
	exitReason := NewSimpleExitReason(ExitGo) // Default to success

	preimageLen := 0
	if preimage != nil {
		preimageLen = len(*preimage)
	}

	o := ctx.Registers[outputRegister]
	f := min(ctx.Registers[offsetRegister], Register(preimageLen))
	l := min(ctx.Registers[lengthRegister], Register(preimageLen)-f)

	if !ctx.RAM.rangeUniform(RamAccess(WriteID), RamIndex(o), RamIndex(o+l)) {
		exitReason = NewSimpleExitReason(ExitPanic)
	} else if preimage == nil {
		ctx.Registers[resultRegister] = Register(HostCallNone)
	} else {
		ctx.Registers[resultRegister] = Register(preimageLen)
		slicedData := (*preimage)[int(f):int(f+l)]
		ctx.RAM.mutateRange(o, slicedData, &[]RamIndex{})
	}

	return HostCallResult{exitReason, postGas, ctx.Registers, ctx.RAM, ctx.ServiceAccount}
}

// PreimageRetriever defines a function type for retrieving preimages
type PreimageRetriever func(account *state.ServiceAccount, key [32]byte) *[]byte

// performLookup handles the common lookup logic for both regular and historical lookups
func performLookup(
	ctx HostCallContext,
	serviceIndex types.ServiceIndex,
	serviceAccounts state.ServiceAccounts,
	isHistorical bool,
	retrievePreimage PreimageRetriever,
) HostCallResult {
	return withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		a := getServiceAccount(ctx, serviceIndex, serviceAccounts, isHistorical)
		h := ctx.Registers[8]

		var preimage *[]byte
		if ctx.RAM.rangeHas(Inaccessible, RamIndex(h), RamIndex(h+32)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		} else if a != nil {
			var key [32]byte
			copy(key[:], ctx.RAM.inspectRange(h, 32, &[]RamIndex{}))
			preimage = retrievePreimage(a, key)
		}

		return processPreimage(ctx, postGas, preimage, 9, 10, 11, 7)
	})
}
