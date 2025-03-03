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
	ServiceIndex           types.ServiceIndex // s
	ServiceCodeHash        [32]byte           // c
	PayloadHash            [32]byte           // l
	GasPrioritizationRatio types.GasValue     // g
	WorkOutput             WorkOutput         // o
}

type WorkExecutionError byte

const (
	OutOfGasError                   WorkExecutionError = 1
	UnexpectedProgramTermination    WorkExecutionError = 2
	NumExportsInvalidlyReported     WorkExecutionError = 3
	ServiceCodeUnavailableForLookup WorkExecutionError = 4
	CodeBeyondMaximumSize           WorkExecutionError = 5
)

type WorkOutput struct {
	// Only one of these should be set
	Err  WorkExecutionError
	Data []byte
}

// HasError indicates if this WorkOutput represents an error.
func (wo WorkOutput) HasError() bool {
	return wo.Err != 0
}

// Data returns the output data if no error is present.
func (wo WorkOutput) GetData() ([]byte, bool) {
	if wo.HasError() {
		return nil, false
	}
	return wo.Data, true
}

// Err returns the error if present.
func (wo WorkOutput) GetErr() (WorkExecutionError, bool) {
	if wo.HasError() {
		return wo.Err, true
	}
	return 0, false
}

type WorkReportWithWorkPackageHashes struct {
	WorkReport        WorkReport
	WorkPackageHashes map[[32]byte]struct{}
}
