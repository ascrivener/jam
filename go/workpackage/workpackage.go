package workpackage

import (
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type WorkPackage struct {
	AuthorizationToken            []byte                       // j
	AuthorizationCodeServiceIndex types.ServiceIndex           // h
	AuthorizationCodeHash         [32]byte                     // u
	ParameterizationBlob          []byte                       // p
	RefinementContext             workreport.RefinementContext // x
	WorkItems                     []WorkItem                   // at least 1, at most MaxWorkItemsInPackage // w
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
	ServiceIdentifier       types.ServiceIndex //s
	CodeHash                [32]byte           //c
	Payload                 []byte             //y
	RefinementGasLimit      types.GasValue     // g
	AccumulationGasLimit    types.GasValue     // a
	NumDataSegmentsExported int                //e
	ImportedDataSegments    []struct {         // i
		ExportingWorkPackageHash struct {
			Identifier                   [32]byte
			IsHashOfExportingWorkPackage bool
		}
		Index int
	}
	BlobHashesAndLengthsIntroduced []struct { // x
		BlobHash [32]byte
		Length   int
	}
}
