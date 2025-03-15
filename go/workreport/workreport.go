package workreport

import "github.com/ascrivener/jam/types"

type WorkReport struct {
	WorkPackageSpecification AvailabilitySpecification // s
	RefinementContext        RefinementContext         // x
	CoreIndex                types.CoreIndex           // c
	AuthorizerHash           [32]byte                  // a
	Output                   []byte                    // o
	SegmentRootLookup        map[[32]byte][32]byte     // l
	WorkResults              []WorkResult              // r
}

type AvailabilitySpecification struct {
	WorkPackageHash  [32]byte         // h
	WorkBundleLength types.BlobLength // l
	ErasureRoot      [32]byte         // u
	SegmentRoot      [32]byte         // e
	SegmentCount     uint64           // n
}

type RefinementContext struct {
	AnchorHeaderHash              [32]byte              // a
	PosteriorStateRoot            [32]byte              // s
	PosteriorBEEFYRoot            [32]byte              // b
	LookupAnchorHeaderHash        [32]byte              // l
	Timeslot                      types.Timeslot        // t
	PrerequisiteWorkPackageHashes map[[32]byte]struct{} // p
}

type WorkResult struct {
	ServiceIndex           types.ServiceIndex        // s
	ServiceCodeHash        [32]byte                  // c
	PayloadHash            [32]byte                  // y
	GasPrioritizationRatio types.GasValue            // g
	WorkOutput             types.ExecutionExitReason // d
}

type WorkReportWithWorkPackageHashes struct {
	WorkReport        WorkReport
	WorkPackageHashes map[[32]byte]struct{}
}
