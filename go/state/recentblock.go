package state

import "github.com/ascrivener/jam/merklizer"

type RecentBlock struct {
	HeaderHash            [32]byte              // h
	AccumulationResultMMR merklizer.MMRRange    // b
	StateRoot             [32]byte              // s
	WorkPackageHashes     map[[32]byte][32]byte // p
}

// DeepCopy creates a new RecentBlock with all nested structures properly copied
func (rb RecentBlock) DeepCopy() RecentBlock {
	newRB := RecentBlock{
		HeaderHash: rb.HeaderHash, // [32]byte is already copied by value
		StateRoot:  rb.StateRoot,  // [32]byte is already copied by value
	}

	// Deep copy the AccumulationResultMMR
	if rb.AccumulationResultMMR != nil {
		newRB.AccumulationResultMMR = rb.AccumulationResultMMR.DeepCopy()
	}

	// Deep copy the WorkPackageHashes map
	if rb.WorkPackageHashes != nil {
		newRB.WorkPackageHashes = make(map[[32]byte][32]byte, len(rb.WorkPackageHashes))
		for k, v := range rb.WorkPackageHashes {
			newRB.WorkPackageHashes[k] = v
		}
	}

	return newRB
}
