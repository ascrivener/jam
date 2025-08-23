package workreport

import (
	"fmt"

	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/workpackage"

	"github.com/cockroachdb/pebble"
)

type WorkReport struct {
	WorkPackageSpecification   AvailabilitySpecification     // s
	RefinementContext          workpackage.RefinementContext // c
	CoreIndex                  types.GenericNum              // c
	AuthorizerHash             [32]byte                      // a
	IsAuthorizedGasConsumption types.GenericGasValue         // g
	Output                     []byte                        // t
	SegmentRootLookup          map[[32]byte][32]byte         // l
	WorkDigests                []WorkDigest                  // d
}

type AvailabilitySpecification struct {
	WorkPackageHash  [32]byte         // p
	WorkBundleLength types.BlobLength // l
	ErasureRoot      [32]byte         // u
	SegmentRoot      [32]byte         // e
	SegmentCount     uint16           // n
}

type WorkDigest struct {
	ServiceIndex                 types.ServiceIndex        // s
	ServiceCodeHash              [32]byte                  // c
	PayloadHash                  [32]byte                  // y
	AccumulateGasLimit           types.GasValue            // g
	WorkResult                   types.ExecutionExitReason // l
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

// Store a work report with both lookup paths - using segment root as primary key
func (workReport WorkReport) Set(batch *pebble.Batch) error {
	workPackageHash := workReport.WorkPackageSpecification.WorkPackageHash
	segmentRoot := workReport.WorkPackageSpecification.SegmentRoot

	// Serialize the work report once
	serialized := serializer.Serialize(workReport)

	// Store the primary record by segment root
	primaryKey := append([]byte("workreport:sr:"), segmentRoot[:]...)
	if err := staterepository.Set(batch, primaryKey, serialized); err != nil {
		return fmt.Errorf("failed to store work report by segment root: %w", err)
	}

	// Store a reference from work package hash to segment root
	indexKey := append([]byte("workreport:wph:"), workPackageHash[:]...)
	if err := staterepository.Set(batch, indexKey, segmentRoot[:]); err != nil {
		return fmt.Errorf("failed to store work package hash index: %w", err)
	}

	return nil
}

// Get a work report by segment root (direct lookup)
func GetWorkReportBySegmentRoot(batch *pebble.Batch, segmentRoot [32]byte) (WorkReport, error) {
	prefixedKey := append([]byte("workreport:sr:"), segmentRoot[:]...)
	return getWorkReportByKey(batch, prefixedKey)
}

// Get a work report by work package hash (index lookup + main lookup)
func GetWorkReportByWorkPackageHash(batch *pebble.Batch, workPackageHash [32]byte) (WorkReport, error) {
	segmentRoot, err := GetSegmentRootByWorkPackageHash(batch, workPackageHash)
	if err != nil {
		return WorkReport{}, fmt.Errorf("failed to find segment root for work package hash %x: %w", workPackageHash, err)
	}

	// Then do the main lookup
	return GetWorkReportBySegmentRoot(batch, segmentRoot)
}

// Get segment root directly from work package hash without loading full work report
func GetSegmentRootByWorkPackageHash(batch *pebble.Batch, workPackageHash [32]byte) ([32]byte, error) {
	// Look up the segment root from the index
	indexKey := append([]byte("workreport:wph:"), workPackageHash[:]...)
	value, closer, err := staterepository.Get(batch, indexKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to find segment root for work package hash %x: %w", workPackageHash, err)
	}

	// Copy the segment root value before closing
	var segmentRoot [32]byte
	copy(segmentRoot[:], value)
	closer.Close()

	return segmentRoot, nil
}

// Helper function for the actual deserialization
func getWorkReportByKey(batch *pebble.Batch, key []byte) (WorkReport, error) {
	value, closer, err := staterepository.Get(batch, key)
	if err != nil {
		return WorkReport{}, fmt.Errorf("failed to get work report: %w", err)
	}

	// Copy the value before closing
	dataCopy := make([]byte, len(value))
	copy(dataCopy, value)
	closer.Close()

	var workReport WorkReport
	if err := serializer.Deserialize(dataCopy, &workReport); err != nil {
		return WorkReport{}, fmt.Errorf("failed to deserialize work report: %w", err)
	}

	return workReport, nil
}
