package pvm

import (
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
	wp "github.com/ascrivener/jam/workpackage"
)

func isAuthorized(workpackage wp.WorkPackage, core types.CoreIndex) ArgumentInvocationExitReason {
	var hf HostFunction[struct{}] = func(n HostFunctionIdentifier, state *State, _ struct{}) (ExitReason, struct{}) {
		if n == Gas {
			exitReason, _, _, _ := gas(types.GasValue(state.Gas), state.Registers, state.RAM)
			return exitReason, struct{}{}
		}
		state.Registers[7] = Register(HostCallWhat)
		state.Gas = state.Gas - types.SignedGasValue(GasUsage)
		return NewSimpleExitReason(ExitGo), struct{}{}
	}
	args := serializer.Serialize(struct {
		WorkPackage wp.WorkPackage
		Core        types.CoreIndex
	}{
		WorkPackage: workpackage,
		Core:        core,
	})
	_, exitReason, _ := ΨM(workpackage.AuthorizationCode(), 0, types.GasValue(IsAuthorizedGasAllocation), args, hf, struct{}{})
	return exitReason
}
