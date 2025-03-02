package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/util"
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
	RAM            *ram.RAM
	ServiceAccount state.ServiceAccount
}

type HostCallContext struct {
	Gas            types.GasValue
	Registers      [13]Register
	RAM            *ram.RAM
	ServiceAccount state.ServiceAccount
}

const GasUsage types.GasValue = 10

// checkGas performs the common gas check pattern and returns the exit reason and post-gas value
func checkGas(gas types.GasValue) (ExitReason, types.SignedGasValue) {
	nextGas := types.SignedGasValue(gas) - types.SignedGasValue(GasUsage)
	if nextGas < 0 {
		return NewSimpleExitReason(ExitOutOfGas), nextGas
	}
	return NewSimpleExitReason(ExitGo), nextGas
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

func Export(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence, exportSegmentOffset int) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		preimage := ctx.Registers[7]
		z := min(ctx.Registers[8], Register(SegmentSize))
		if ctx.RAM.RangeHas(ram.Inaccessible, uint64(preimage), uint64(preimage+z)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		if exportSegmentOffset+len(integratedPVMsAndExportSequence.ExportSequence) >= WorkPackageManifestMaxEntries {
			ctx.Registers[7] = Register(HostCallFull)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		x := util.OctetArrayZeroPadding(ctx.RAM.GetValueSlice(uint64(preimage), uint64(preimage+z)), SegmentSize)
		ctx.Registers[7] = Register(exportSegmentOffset + len(integratedPVMsAndExportSequence.ExportSequence))
		updatedSequence.ExportSequence = append(updatedSequence.ExportSequence, x)
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})
	return hostResult, updatedSequence
}

func Machine(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedIntegratedPVMsAndExportSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		po := ctx.Registers[7]
		pz := ctx.Registers[8]
		i := ctx.Registers[9]
		if ctx.RAM.RangeHas(ram.Inaccessible, uint64(po), uint64(po+pz)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		p := ctx.RAM.GetValueSlice(uint64(po), uint64(po+pz))
		if _, _, _, ok := Deblob(p); !ok {
			ctx.Registers[7] = Register(HostCallHuh)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		n := 0
		for {
			if _, ok := integratedPVMsAndExportSequence.IntegratedPVMs[n]; !ok {
				break
			}
			n++
		}
		u := ram.NewEmptyRAM()
		ctx.Registers[7] = Register(n)
		updatedIntegratedPVMsAndExportSequence.IntegratedPVMs[n] = IntegratedPVM{
			ProgramCode:        p,
			RAM:                u,
			InstructionCounter: i,
		}
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})
	return hostResult, updatedIntegratedPVMsAndExportSequence
}

func Peek(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) HostCallResult {
	return withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		// Extract the 4 parameters from registers
		n := int(ctx.Registers[7]) // Source integrated PVM index
		o := ctx.Registers[8]      // Destination memory address
		s := ctx.Registers[9]      // Source memory address
		z := ctx.Registers[10]     // Length to copy

		// Check if destination range is accessible
		if !ctx.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(o+z)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check if integrated PVM exists
		sourcePVM, ok := integratedPVMsAndExportSequence.IntegratedPVMs[n]
		if !ok {
			ctx.Registers[7] = Register(HostCallWho)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		if sourcePVM.RAM.RangeHas(ram.Inaccessible, uint64(s), uint64(s+z)) {
			ctx.Registers[7] = Register(HostCallOOB)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Copy the memory
		ctx.RAM.SetValueSlice(sourcePVM.RAM.GetValueSlice(uint64(s), uint64(s+z)), uint64(o))

		// Set result to OK
		ctx.Registers[7] = Register(HostCallOK)
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})
}

func Zero(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		// Extract the 3 parameters from registers
		n := int(ctx.Registers[7]) // Target integrated PVM index
		p := ctx.Registers[8]      // Start address
		c := ctx.Registers[9]      // Count/length

		// Check for invalid memory range
		// p < 16 ∨ p + c ≥ 2^32 / ZP
		if p < 16 || p+c >= (1<<32)/ram.PageSize {
			ctx.Registers[7] = Register(HostCallHuh)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check if integrated PVM exists
		targetPVM, ok := updatedSequence.IntegratedPVMs[n]
		if !ok {
			ctx.Registers[7] = Register(HostCallWho)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Zero out the memory
		zeros := make([]byte, int(c))
		targetPVM.RAM.SetValueSlice(zeros, uint64(p))

		targetPVM.RAM.SetSectionAccess(uint64(p), uint64(p+c), ram.Mutable)

		// Set result to OK
		ctx.Registers[7] = Register(HostCallOK)
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})

	return hostResult, updatedSequence
}

func Poke(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		// Extract the 4 parameters from registers
		n := int(ctx.Registers[7]) // Target integrated PVM index
		s := ctx.Registers[8]      // Source address in current context
		o := ctx.Registers[9]      // Destination address in target PVM
		z := ctx.Registers[10]     // Length to copy

		// Check if source range is accessible in current context
		if ctx.RAM.RangeHas(ram.Inaccessible, uint64(s), uint64(s+z)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check if integrated PVM exists
		targetPVM, ok := updatedSequence.IntegratedPVMs[n]
		if !ok {
			ctx.Registers[7] = Register(HostCallWho)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check if destination range is not all mutable in target PVM
		if !targetPVM.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(o+z)) {
			ctx.Registers[7] = Register(HostCallOOB)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		targetPVM.RAM.SetValueSlice(ctx.RAM.GetValueSlice(uint64(s), uint64(s+z)), uint64(o))

		// Set result to OK
		ctx.Registers[7] = Register(HostCallOK)
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})

	return hostResult, updatedSequence
}

func Void(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		// Extract the 3 parameters from registers
		n := int(ctx.Registers[7])     // Target integrated PVM index
		pPageIndex := ctx.Registers[8] // Start address
		cPages := ctx.Registers[9]     // length
		pPageStart := pPageIndex * ram.PageSize
		cPagesSize := cPages * ram.PageSize

		// Check if integrated PVM exists
		targetPVM, ok := updatedSequence.IntegratedPVMs[n]
		if !ok {
			ctx.Registers[7] = Register(HostCallWho)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check for invalid memory range
		if pPageIndex < 16 || pPageIndex+cPages >= (1<<32)/ram.PageSize || targetPVM.RAM.RangeHas(ram.Inaccessible, uint64(pPageStart), uint64(pPageStart+cPagesSize)) {
			ctx.Registers[7] = Register(HostCallHuh)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Zero out the memory
		zeros := make([]byte, int(cPagesSize))
		targetPVM.RAM.SetValueSlice(zeros, uint64(pPageStart))

		// Set access to Inaccessible
		targetPVM.RAM.SetSectionAccess(uint64(pPageStart), uint64(pPageStart+cPagesSize), ram.Inaccessible)

		// Set result to OK
		ctx.Registers[7] = Register(HostCallOK)
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})

	return hostResult, updatedSequence
}

func Invoke(ctx HostCallContext, integratedPVMsAndExportSequence IntegratedPVMsAndExportSequence) (HostCallResult, IntegratedPVMsAndExportSequence) {
	updatedSequence := integratedPVMsAndExportSequence
	hostResult := withGasCheck(ctx, func(ctx HostCallContext, postGas types.SignedGasValue) HostCallResult {
		// Extract the parameters from registers
		n := int(ctx.Registers[7]) // Target integrated PVM index
		o := ctx.Registers[8]      // Memory offset for gas/weight data

		// Check if memory range o to o+112 is accessible for reading
		if !ctx.RAM.RangeUniform(ram.Mutable, uint64(o), uint64(o+112)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		// Check if integrated PVM exists
		targetPVM, ok := updatedSequence.IntegratedPVMs[n]
		if !ok {
			ctx.Registers[7] = Register(HostCallWho)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}

		gasData := ctx.RAM.GetValueSlice(uint64(o), uint64(o+8))           // Assuming E8(g) is 64 bytes
		registersData := ctx.RAM.GetValueSlice(uint64(o+8), uint64(o+112)) // Assuming E#8(w) is 48 bytes

		gas := types.GasValue(serializer.DecodeLittleEndian(gasData))
		registers := [13]Register{}
		for i := range 13 {
			registers[i] = Register(serializer.DecodeLittleEndian(registersData[i*8 : i*8+8]))
		}

		pvm := NewPVM[struct{}](targetPVM.ProgramCode, registers, targetPVM.RAM, targetPVM.InstructionCounter, gas)
		if pvm == nil {
			ctx.Registers[7] = Register(InnerPanic)
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		exitReason := pvm.Ψ()

		// Update memory with new gas and registers
		gasBytes := serializer.EncodeLittleEndian(8, uint64(pvm.State.Gas))
		ctx.RAM.SetValueSlice(gasBytes, uint64(o))

		for i := range 13 {
			regBytes := serializer.EncodeLittleEndian(8, uint64(pvm.State.Registers[i]))
			ctx.RAM.SetValueSlice(regBytes, uint64(o+8)+uint64(i*8))
		}

		targetPVM.InstructionCounter = pvm.State.InstructionCounter
		// Handle instruction pointer update based on exit reason
		if exitReason.IsComplex() {
			if exitReason.ComplexExitReason.Type == ExitHostCall {
				// If it's a host call, increment instruction pointer
				targetPVM.InstructionCounter++
				ctx.Registers[7] = Register(InnerHost)
			} else {
				ctx.Registers[7] = Register(InnerFault)
			}
			ctx.Registers[8] = exitReason.ComplexExitReason.Parameter
			updatedSequence.IntegratedPVMs[n] = targetPVM
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitGo),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		}
		switch *exitReason.SimpleExitReason {
		case ExitOutOfGas:
			ctx.Registers[7] = Register(InnerOOG)
		case ExitPanic:
			ctx.Registers[7] = Register(InnerPanic)
		case ExitHalt:
			ctx.Registers[7] = Register(InnerHalt)
		default:
			panic(fmt.Sprintf("unreachable: unhandled simple exit reason %v", *exitReason.SimpleExitReason))
		}
		updatedSequence.IntegratedPVMs[n] = targetPVM
		return HostCallResult{
			ExitReason:     NewSimpleExitReason(ExitGo),
			PostGas:        postGas,
			Registers:      ctx.Registers,
			RAM:            ctx.RAM,
			ServiceAccount: ctx.ServiceAccount,
		}
	})

	return hostResult, updatedSequence
}

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

	if !ctx.RAM.RangeUniform(ram.RamAccess(WriteID), uint64(o), uint64(o+l)) {
		exitReason = NewSimpleExitReason(ExitPanic)
	} else if preimage == nil {
		ctx.Registers[resultRegister] = Register(HostCallNone)
	} else {
		ctx.Registers[resultRegister] = Register(preimageLen)
		slicedData := (*preimage)[int(f):int(f+l)]
		ctx.RAM.SetValueSlice(slicedData, uint64(o))
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
		if ctx.RAM.RangeHas(ram.Inaccessible, uint64(h), uint64(h+32)) {
			return HostCallResult{
				ExitReason:     NewSimpleExitReason(ExitPanic),
				PostGas:        postGas,
				Registers:      ctx.Registers,
				RAM:            ctx.RAM,
				ServiceAccount: ctx.ServiceAccount,
			}
		} else if a != nil {
			var key [32]byte
			copy(key[:], ctx.RAM.GetValueSlice(uint64(h), uint64(h+32)))
			preimage = retrievePreimage(a, key)
		}

		return processPreimage(ctx, postGas, preimage, 9, 10, 11, 7)
	})
}
