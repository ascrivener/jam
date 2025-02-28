package pvm

import "github.com/ascrivener/jam/types"

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

func gas(gas types.GasValue, registers [13]Register, args ...any) (ExitReason, types.SignedGasValue, [13]Register, []any) {
	if gas < GasUsage {
		return NewSimpleExitReason(ExitOutOfGas), types.SignedGasValue(gas), registers, args
	}
	postGas := types.SignedGasValue(gas - GasUsage)
	exitReason := NewSimpleExitReason(ExitGo)
	registers[7] = Register(postGas)
	return exitReason, postGas, registers, args
}
