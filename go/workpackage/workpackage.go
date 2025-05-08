package workpackage

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type WorkPackage struct {
	AuthorizationToken            []byte                       // j
	AuthorizationCodeServiceIndex types.ServiceIndex           // h
	AuthorizationCodeHash         [32]byte                     // u
	ParameterizationBlob          []byte                       // p
	RefinementContext             workreport.RefinementContext // x
	WorkItems                     []WorkItem                   // w
}

// TODO: implement // c
func (wp WorkPackage) AuthorizationCode() []byte {
	return []byte{}
}

// TODO: implement // a
func (wp WorkPackage) Authorizer() [32]byte {
	return [32]byte{}
}

type WorkItem struct {
	ServiceIdentifier       types.ServiceIndex // s
	CodeHash                [32]byte           // h
	Payload                 []byte             // y
	RefinementGasLimit      types.GasValue     // g
	AccumulationGasLimit    types.GasValue     // a
	NumDataSegmentsExported uint16             // e
	ImportedDataSegments    []struct {
		ExportingWorkPackageHash struct {
			Identifier                   [32]byte
			IsHashOfExportingWorkPackage bool
		}
		Index int
	} // i
	BlobHashesAndLengthsIntroduced []BlobHashAndLengthIntroduced // x
}

func (i WorkItem) MaxTotalSize() int {
	totalBlobLength := 0
	for _, blobHashAndLengthIntroduced := range i.BlobHashesAndLengthsIntroduced {
		totalBlobLength += blobHashAndLengthIntroduced.Length
	}
	return len(i.Payload) + len(i.ImportedDataSegments)*int(constants.MaxImportsInWorkPackage) + totalBlobLength
}

type BlobHashAndLengthIntroduced struct { // x
	BlobHash [32]byte
	Length   int
}
