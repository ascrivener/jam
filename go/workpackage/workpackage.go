package workpackage

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

type WorkPackage struct {
	AuthorizationToken            []byte             // j
	AuthorizationCodeServiceIndex types.ServiceIndex // h
	AuthorizationCodeHash         [32]byte           // u
	ParameterizationBlob          []byte             // p
	RefinementContext             RefinementContext  // x
	WorkItems                     []WorkItem         // w
}

type RefinementContext struct {
	AnchorHeaderHash              [32]byte              // a
	PosteriorStateRoot            [32]byte              // s
	PosteriorBEEFYRoot            [32]byte              // b
	LookupAnchorHeaderHash        [32]byte              // l
	Timeslot                      types.Timeslot        // t
	PrerequisiteWorkPackageHashes map[[32]byte]struct{} // p
}

// TODO: implement // c
func (wp WorkPackage) AuthorizationCode() []byte {
	return []byte{}
}

// TODO: implement // a
func (wp WorkPackage) Authorizer() [32]byte {
	return [32]byte{}
}

type ImportedSegmentInfo struct {
	Hash struct {
		Identifier                   [32]byte
		IsHashOfExportingWorkPackage bool
	}
	Index int
}

type WorkItem struct {
	ServiceIdentifier              types.ServiceIndex            // s
	CodeHash                       [32]byte                      // h
	Payload                        []byte                        // y
	RefinementGasLimit             types.GasValue                // g
	AccumulationGasLimit           types.GasValue                // a
	NumDataSegmentsExported        uint16                        // e
	ImportedSegmentsInfo           []ImportedSegmentInfo         // i
	BlobHashesAndLengthsIntroduced []BlobHashAndLengthIntroduced // x
}

func (i WorkItem) MaxTotalSize() int {
	totalBlobLength := 0
	for _, blobHashAndLengthIntroduced := range i.BlobHashesAndLengthsIntroduced {
		totalBlobLength += blobHashAndLengthIntroduced.Length
	}
	return len(i.Payload) + len(i.ImportedSegmentsInfo)*int(constants.MaxImportsInWorkPackage) + totalBlobLength
}

type BlobHashAndLengthIntroduced struct { // x
	BlobHash [32]byte
	Length   int
}
