package state

type RecentBlock struct {
	HeaderHash            [32]byte
	AccumulationResultMMR []*[32]byte
	StateRoot             [32]byte
	WorkPackageHashes     map[[32]byte][32]byte
}
