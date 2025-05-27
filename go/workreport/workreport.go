package workreport

import "github.com/ascrivener/jam/types"

type WorkReport struct {
	WorkPackageSpecification   AvailabilitySpecification // s
	RefinementContext          RefinementContext         // x
	CoreIndex                  types.GenericNum          // c
	AuthorizerHash             [32]byte                  // a
	Output                     []byte                    // o
	SegmentRootLookup          map[[32]byte][32]byte     // l
	WorkDigests                []WorkDigest              // r
	IsAuthorizedGasConsumption types.GenericGasValue     // g
}

type AvailabilitySpecification struct {
	WorkPackageHash  [32]byte         // h
	WorkBundleLength types.BlobLength // l
	ErasureRoot      [32]byte         // u
	SegmentRoot      [32]byte         // e
	SegmentCount     uint16           // n
}

type RefinementContext struct {
	AnchorHeaderHash              [32]byte              // a
	PosteriorStateRoot            [32]byte              // s
	PosteriorBEEFYRoot            [32]byte              // b
	LookupAnchorHeaderHash        [32]byte              // l
	Timeslot                      types.Timeslot        // t
	PrerequisiteWorkPackageHashes map[[32]byte]struct{} // p
}

type WorkDigest struct {
	ServiceIndex                 types.ServiceIndex        // s
	ServiceCodeHash              [32]byte                  // h
	PayloadHash                  [32]byte                  // y
	AccumulateGasLimit           types.GasValue            // g
	WorkResult                   types.ExecutionExitReason // d
	ActualRefinementGasUsed      types.GenericGasValue     // u
	NumSegmentsImportedFrom      types.GenericNum          // i
	NumExtrinsicsUsed            types.GenericNum          // x
	SizeInOctetsOfExtrinsicsUsed types.GenericNum          // z
	NumSegmentsExportedInto      types.GenericNum          // e
}

type WorkReportWithWorkPackageHashes struct {
	WorkReport        WorkReport
	WorkPackageHashes map[[32]byte]struct{}
}
