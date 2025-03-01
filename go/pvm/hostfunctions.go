package pvm

import (
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
)

type HostFunctionIdentifier int

const (
	Gas HostFunctionIdentifier = iota
	Lookup
	Read
	Write
	Info
	Bless
	Assign
	Designate
	Checkpoint
	New
	Upgrade
	Transfer
	Eject
	Query
	Solicit
	Forget
	Yield
	HistoricalLookup
	Fetch
	Export
	Machine
	Peek
	Poke
	Zero
	Void
	Invoke
	Expunge
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

func isValidHostCallError(code HostCallResult) bool {
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

func gas(gas types.GasValue, registers [13]Register, args ...any) (ExitReason, types.SignedGasValue, [13]Register, []any) {
	exitReason, postGas := checkGas(gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason, postGas, registers, args
	}
	registers[7] = Register(postGas)
	return exitReason, postGas, registers, args
}

func lookup(gas types.GasValue, registers [13]Register, ram *RAM, serviceAccount state.ServiceAccount, serviceIndex types.ServiceIndex, serviceAccounts state.ServiceAccounts) (ExitReason, types.SignedGasValue, [13]Register, *RAM, state.ServiceAccount) {
	exitReason, postGas := checkGas(gas)
	if exitReason.IsSimple() && *exitReason.SimpleExitReason == ExitOutOfGas {
		return exitReason, postGas, registers, ram, serviceAccount
	}
	var a *state.ServiceAccount
	if registers[7] == Register(serviceIndex) || registers[7] == MaxRegister {
		a = &serviceAccount
	} else if s, ok := serviceAccounts[types.ServiceIndex(registers[7])]; ok {
		a = &s
	}
	h := registers[8]
	o := registers[9]

	var preimage *[]byte
	var inaccessible bool
	if ram.rangeHas(Inaccessible, RamIndex(h), RamIndex(h+32)) {
		inaccessible = true
	} else if a != nil {
		var key [32]byte
		copy(key[:], ram.inspectRange(h, 32, &[]RamIndex{}))
		v, ok := a.PreimageLookup[key]
		if ok {
			preimage = &v
		}
	}

	preimageLen := 0
	if preimage != nil {
		preimageLen = len(*preimage)
	}

	f := min(registers[10], Register(preimageLen))
	l := min(registers[11], Register(preimageLen)-f)

	if inaccessible || !ram.rangeUniform(RamAccess(Write), RamIndex(o), RamIndex(o+l)) {
		exitReason = NewSimpleExitReason(ExitPanic)
	} else if preimage == nil {
		registers[7] = Register(HostCallNone)
	} else {
		registers[7] = Register(preimageLen)
		// Copy the sliced preimage data to RAM
		slicedData := (*preimage)[int(f):int(f+l)]
		ram.mutateRange(o, slicedData, &[]RamIndex{})
	}

	return exitReason, postGas, registers, ram, serviceAccount
}
