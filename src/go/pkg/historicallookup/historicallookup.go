// Package lookup provides an in-memory, thread-safe store for mapping
// a composite key—(service index, [32]byte hash)—to its corresponding preimage data.
package historicallookup

import (
	"jam/pkg/serviceaccount"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
)

func HistoricalLookup(batch *pebble.Batch, serviceAccount *serviceaccount.ServiceAccount, timeslot types.Timeslot, hash [32]byte) ([]byte, error) {
	p, ok, err := serviceAccount.GetPreimageForHash(batch, hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	historicalStatus, ok, err := serviceAccount.GetPreimageLookupHistoricalStatus(batch, uint32(types.BlobLength(len(p))), hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	switch len(historicalStatus) {
	case 0:
		return nil, nil
	case 1:
		if historicalStatus[0] <= timeslot {
			byteSlice := []byte(p)
			return byteSlice, nil
		}
	case 2:
		if historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot {
			byteSlice := []byte(p)
			return byteSlice, nil
		}
	default:
		if (historicalStatus[0] <= timeslot && historicalStatus[1] < timeslot) || historicalStatus[2] <= timeslot {
			byteSlice := []byte(p)
			return byteSlice, nil
		}
	}

	return nil, nil
}

// gets posterior service accounts for a particular block with a header hash headerHash, timeslot timeslot
// TODO: implement
func GetPosteriorServiceAccounts(headerHash [32]byte, timeslot types.Timeslot) serviceaccount.ServiceAccounts {
	return make(serviceaccount.ServiceAccounts)
}
