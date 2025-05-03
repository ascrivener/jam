// Package lookup provides an in-memory, thread-safe store for mapping
// a composite key—(service index, [32]byte hash)—to its corresponding preimage data.
package historicallookup

import (
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
)

func HistoricalLookup(serviceAccount *serviceaccount.ServiceAccount, timeslot types.Timeslot, hash [32]byte) *[]byte {
	p, ok := serviceAccount.PreimageLookup[hash]
	if !ok {
		return nil
	}

	key := serviceaccount.PreimageLookupHistoricalStatusKey{
		Preimage:   hash,
		BlobLength: types.BlobLength(len(p)),
	}
	historicalStatus := serviceAccount.PreimageLookupHistoricalStatus[key]

	switch len(historicalStatus) {
	case 0:
		return nil
	case 1:
		if historicalStatus[0] <= timeslot {
			byteSlice := []byte(p)
			return &byteSlice
		}
	case 2:
		if historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot {
			byteSlice := []byte(p)
			return &byteSlice
		}
	default:
		if (historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot) || historicalStatus[2] <= timeslot {
			byteSlice := []byte(p)
			return &byteSlice
		}
	}

	return nil
}

// gets posterior service accounts for a particular block with a header hash headerHash, timeslot timeslot
// TODO: implement
func GetPosteriorServiceAccounts(headerHash [32]byte, timeslot types.Timeslot) serviceaccount.ServiceAccounts {
	return make(serviceaccount.ServiceAccounts)
}
