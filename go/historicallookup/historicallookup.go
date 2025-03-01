// Package lookup provides an in-memory, thread-safe store for mapping
// a composite key—(service index, [32]byte hash)—to its corresponding preimage data.
package historicallookup

import (
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
)

func HistoricalLookup(serviceAccount state.ServiceAccount, timeslot types.Timeslot, hash [32]byte) *[]byte {
	p, ok := serviceAccount.PreimageLookup[hash]
	if !ok {
		return nil
	}

	key := state.PreimageLookupHistoricalStatusKey{
		Preimage:   hash,
		BlobLength: types.BlobLength(len(p)),
	}
	historicalStatus := serviceAccount.PreimageLookupHistoricalStatus[key]

	switch len(historicalStatus) {
	case 0:
		return nil
	case 1:
		if historicalStatus[0] <= timeslot {
			return &p
		}
	case 2:
		if historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot {
			return &p
		}
	default:
		if (historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot) || historicalStatus[2] <= timeslot {
			return &p
		}
	}

	return nil
}

// gets posterior service accounts for a particular block with a header hash headerHash, timeslot timeslot
// TODO: implement
func GetPosteriorServiceAccounts(headerHash [32]byte, timeslot types.Timeslot) state.ServiceAccounts {
	return make(state.ServiceAccounts)
}
