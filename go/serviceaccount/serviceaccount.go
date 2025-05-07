package serviceaccount

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

type PreimageLookupHistoricalStatusKey struct {
	Preimage   [32]byte
	BlobLength types.BlobLength
}

type ServiceAccount struct {
	StorageDictionary              map[[31]byte]types.Blob                                // s
	PreimageLookup                 map[[32]byte]types.Blob                                // p
	PreimageLookupHistoricalStatus map[PreimageLookupHistoricalStatusKey][]types.Timeslot // l
	CodeHash                       [32]byte                                               // c
	Balance                        types.Balance                                          // b
	MinimumGasForAccumulate        types.GasValue                                         // g
	MinimumGasForOnTransfer        types.GasValue                                         // m
}

// o
func (s ServiceAccount) TotalOctetsUsedInStorage() uint64 {
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
	return types.Balance(constants.ServiceMinimumBalance + constants.ServiceMinimumBalancePerItem*uint64(s.TotalItemsUsedInStorage()) + constants.ServiceMinimumBalancePerOctet*uint64(s.TotalOctetsUsedInStorage()))
}

// bold m, bold c

func (s *ServiceAccount) MetadataAndCode() (*[]byte, *[]byte) {
	if preimage, ok := s.PreimageLookup[s.CodeHash]; ok {
		offset := 0
		L_m, n, ok := serializer.DecodeGeneralNatural(preimage[offset:])
		if !ok {
			panic("failed to decode metadata length")
		}
		offset += n
		m := preimage[offset : offset+int(L_m)]
		offset += int(L_m)
		c := preimage[offset:]

		// Convert types.Blob to []byte before taking address
		mBytes := []byte(m)
		cBytes := []byte(c)
		return &mBytes, &cBytes
	}
	return nil, nil
}
