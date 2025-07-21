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
	RefinementContext          workpackage.RefinementContext // x
	CoreIndex                  types.GenericNum              // c
	AuthorizerHash             [32]byte                      // a
	Output                     []byte                        // o
	SegmentRootLookup          map[[32]byte][32]byte         // l
	WorkDigests                []WorkDigest                  // r
	IsAuthorizedGasConsumption types.GenericGasValue         // g
}

type AvailabilitySpecification struct {
	WorkPackageHash  [32]byte         // h
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

// Store a work report with both lookup paths - using segment root as primary key
func (workReport WorkReport) Set(repo staterepository.PebbleStateRepository) error {
	workPackageHash := workReport.WorkPackageSpecification.WorkPackageHash
	segmentRoot := workReport.WorkPackageSpecification.SegmentRoot

	// Create a batch for atomic operations
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Serialize the work report once
	serialized := serializer.Serialize(workReport)

	// Store the primary record by segment root
	primaryKey := append([]byte("workreport:sr:"), segmentRoot[:]...)
	if err := batch.Set(primaryKey, serialized, nil); err != nil {
		return fmt.Errorf("failed to store work report by segment root: %w", err)
	}

	// Store a reference from work package hash to segment root
	indexKey := append([]byte("workreport:wph:"), workPackageHash[:]...)
	if err := batch.Set(indexKey, segmentRoot[:], nil); err != nil {
		return fmt.Errorf("failed to store work package hash index: %w", err)
	}

	if ownBatch {
		return batch.Commit(pebble.Sync)
	}

	return nil
}

// Get a work report by segment root (direct lookup)
func GetWorkReportBySegmentRoot(repo staterepository.PebbleStateRepository, segmentRoot [32]byte) (WorkReport, error) {
	prefixedKey := append([]byte("workreport:sr:"), segmentRoot[:]...)
	return getWorkReportByKey(repo, prefixedKey)
}

// Get a work report by work package hash (index lookup + main lookup)
func GetWorkReportByWorkPackageHash(repo staterepository.PebbleStateRepository, workPackageHash [32]byte) (WorkReport, error) {
	segmentRoot, err := GetSegmentRootByWorkPackageHash(repo, workPackageHash)
	if err != nil {
		return WorkReport{}, fmt.Errorf("failed to find segment root for work package hash %x: %w", workPackageHash, err)
	}

	// Then do the main lookup
	return GetWorkReportBySegmentRoot(repo, segmentRoot)
}

// Get segment root directly from work package hash without loading full work report
func GetSegmentRootByWorkPackageHash(repo staterepository.PebbleStateRepository, workPackageHash [32]byte) ([32]byte, error) {
	// Look up the segment root from the index
	indexKey := append([]byte("workreport:wph:"), workPackageHash[:]...)
	value, closer, err := repo.Get(indexKey)
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
func getWorkReportByKey(repo staterepository.PebbleStateRepository, key []byte) (WorkReport, error) {
	value, closer, err := repo.Get(key)
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
