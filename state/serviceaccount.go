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

func (s ServiceAccount) TotalOctetsUsedInStorage() uint64 {
	total := uint64(0)
	for key := range s.PreimageLookupLengthToTimeslots {
		total += 81 + uint64(key.BlobLength)
	}
	for _, blob := range s.StorageDictionary {
		total += 32 + uint64(len(blob))
	}
	return total
}

func (s ServiceAccount) TotalItemsUsedInStorage() uint32 {
	return uint32(2)*uint32(len(s.PreimageLookupLengthToTimeslots)) + uint32(len(s.StorageDictionary))
}
