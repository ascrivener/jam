package state

import "github.com/ascrivener/jam/merklizer"

type RecentBlock struct {
	HeaderHash            [32]byte              // h
	AccumulationResultMMR merklizer.MMRRange    // b
	StateRoot             [32]byte              // s
	WorkPackageHashes     map[[32]byte][32]byte // p
}
