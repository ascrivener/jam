package workpackage

import (
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type WorkPackage struct {
	AuthorizationToken            []byte
	AuthorizationCodeServiceIndex types.ServiceIndex
	AuthorizationCodeHash         [32]byte
	ParameterizationBlob          []byte
	RefinementContext             workreport.RefinementContext
	WorkItems                     []WorkItem // at least 1, at most MaxWorkItemsInPackage
}

// TODO: implement
func (wp WorkPackage) AuthorizationCode() []byte {
	return []byte{}
}

type WorkItem struct {
	ServiceIdentifier       types.ServiceIndex
	CodeHash                [32]byte
	Payload                 []byte
	RefinementGasLimit      types.GasValue
	AccumulationGasLimit    types.GasValue
	NumDataSegmentsExported int
	ImportedDataSegments    []struct {
		ExportingWorkPackageHash struct {
			Identifier                   [32]byte
			IsHashOfExportingWorkPackage bool
		}
		Index int
	}
	BlobHashesAndLengthsIntroduced []struct {
		BlobHash [32]byte
		Length   int
	}
}
