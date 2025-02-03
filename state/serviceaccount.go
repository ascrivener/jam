package state

import "github.com/ascrivener/jam/types"

type ServiceAccount struct {
	StorageDictionary               map[[32]byte][]byte
	PreimageLookup                  map[[32]byte][]byte
	PreimageLookupLengthToTimeslots map[struct {
		Preimage   [32]byte
		BlobLength types.BlobLength
	}][]types.Timeslot
	CodeHash                [32]byte
	Balance                 types.Balance
	MinimumGasForAccumulate types.GasValue
	MinimumGasForOnTransfer types.GasValue
}
