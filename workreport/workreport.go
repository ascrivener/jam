package workreport

import "github.com/ascrivener/jam/types"

type WorkReport struct {
	WorkPackageSpecification AvailabilitySpecification
	RefinementContext        RefinementContext
	CoreIndex                types.CoreIndex
	AuthorizerHash           [32]byte
	Output                   []byte
	SegmentRootLookup        map[[32]byte][32]byte
	WorkResults              []WorkResult
}

type AvailabilitySpecification struct {
	WorkPackageHash  [32]byte
	WorkBundleLength types.BlobLength
	ErasureRoot      [32]byte
	SegmentRoot      [32]byte
	SegmentCount     uint64
}

type RefinementContext struct {
	AnchorHeaderHash              [32]byte
	PosteriorStateRoot            [32]byte
	PosteriorBEEFYRoot            [32]byte
	LookupAnchorHeaderHash        [32]byte
	Timeslot                      types.TimeslotIndex
	PrerequisiteWorkPackageHashes map[[32]byte]struct{}
}

type WorkResult struct {
	ServiceIndex           types.ServiceIndex
	ServiceCodeHash        [32]byte
	PayloadHash            [32]byte
	GasPrioritizationRatio types.GasValue
	WorkOutput             WorkOutput
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
