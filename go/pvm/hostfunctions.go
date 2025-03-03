package pvm

import (
	"fmt"

	"github.com/ascrivener/jam/historicallookup"
	"github.com/ascrivener/jam/ram"
	"github.com/ascrivener/jam/serializer"
	s "github.com/ascrivener/jam/state"
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
	hostResult := withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
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
	return hostResult
}

func Machine(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
	hostResult := withGasCheck(ctx, func(ctx *HostFunctionContext[IntegratedPVMsAndExportSequence]) ExitReason {
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
	return hostResult
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
