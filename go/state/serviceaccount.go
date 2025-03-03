package state

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

type ServiceAccounts map[types.ServiceIndex]ServiceAccount

type PreimageLookupHistoricalStatusKey struct {
	Preimage   [32]byte
	BlobLength types.BlobLength
}

type ServiceAccount struct {
	StorageDictionary              map[[32]byte][]byte                                    // s
	PreimageLookup                 map[[32]byte][]byte                                    // p
	PreimageLookupHistoricalStatus map[PreimageLookupHistoricalStatusKey][]types.Timeslot // l
	CodeHash                       [32]byte                                               // c
	Balance                        types.Balance                                          // b
	MinimumGasForAccumulate        types.GasValue                                         // g
	MinimumGasForOnTransfer        types.GasValue                                         // m
}

func (s ServiceAccount) TotalOctetsUsedInStorage() uint64 { // o
	total := uint64(0)
	for key := range s.PreimageLookupHistoricalStatus {
		total += 81 + uint64(key.BlobLength)
	}
	for _, blob := range s.StorageDictionary {
		total += 32 + uint64(len(blob))
	}
	return total
}

// i
func (s ServiceAccount) TotalItemsUsedInStorage() uint32 {
	return uint32(2)*uint32(len(s.PreimageLookupHistoricalStatus)) + uint32(len(s.StorageDictionary))
}

// t
func (s ServiceAccount) ThresholdBalanceNeeded() types.Balance {
	return types.Balance(constants.ServiceMinimumBalance + constants.ServiceMinimumBalancePerItem*int(s.TotalItemsUsedInStorage()) + constants.ServiceMinimumBalancePerOctet*int(s.TotalOctetsUsedInStorage()))
}
