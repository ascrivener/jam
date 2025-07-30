package pvm

import (
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/erasurecoding"
	"jam/pkg/merklizer"
	"jam/pkg/preimages"
	"jam/pkg/state"
	"jam/pkg/types"
	"jam/pkg/workpackage"
	"jam/pkg/workreport"

	"golang.org/x/crypto/blake2b"
)

func WorkPackageToWorkReport(wp workpackage.WorkPackage, core types.CoreIndex) (workreport.WorkReport, error) {
	state, err := state.GetState()
	if err != nil {
		return workreport.WorkReport{}, err
	}
	exitReason, _, err := IsAuthorized(wp, core)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	if exitReason.IsError() || uint32(len(*exitReason.Blob)) > constants.MaxTotalSizeWorkReportBlobs {
		return workreport.WorkReport{}, nil
	}

	importSegments := make([][][constants.SegmentSize]byte, len(wp.WorkItems))
	extrinsicData := make([][]types.Blob, len(wp.WorkItems))
	justifications := make([][][][32]byte, len(wp.WorkItems))
	totalNumDataSegmentsExported := uint16(0)
	segmentRootLookup := make(map[[32]byte][32]byte)
	for workItemIdx, workItem := range wp.WorkItems {
		// extrinsic data
		workItemExtrinsicData := make([]types.Blob, len(workItem.BlobHashesAndLengthsIntroduced))
		for blobHashAndLengthIntroducedIdx, blobHashAndLengthIntroduced := range workItem.BlobHashesAndLengthsIntroduced {
			blob, err := preimages.GetPreimage(blobHashAndLengthIntroduced.BlobHash)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			workItemExtrinsicData[blobHashAndLengthIntroducedIdx] = types.Blob(blob)
		}
		extrinsicData[workItemIdx] = workItemExtrinsicData
		// imported segments and justifications
		workItemImportedSegments := make([][constants.SegmentSize]byte, len(workItem.ImportedSegmentsInfo))
		workItemJustifications := make([][][32]byte, len(workItem.ImportedSegmentsInfo))
		for importedDataSegmentIdx, importedDataSegment := range workItem.ImportedSegmentsInfo {
			hash := importedDataSegment.Hash
			var segmentRoot [32]byte
			if !hash.IsHashOfExportingWorkPackage {
				segmentRoot = hash.Identifier
			} else {
				workPackageHash := hash.Identifier
				segmentRoot, err := workreport.GetSegmentRootByWorkPackageHash(workPackageHash)
				if err != nil {
					return workreport.WorkReport{}, err
				}
				segmentRootLookup[workPackageHash] = segmentRoot
			}
			// check if segment root is known and not expired
			exportingWorkReport, err := workreport.GetWorkReportBySegmentRoot(segmentRoot)
			if err != nil {
				return workreport.WorkReport{}, err
			}

			erasureRoot := exportingWorkReport.WorkPackageSpecification.ErasureRoot
			segmentChunks, err := getSegmentShards(erasureRoot, importedDataSegment.Index)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			recover := erasurecoding.CreateRecoveryForErasureCodedPiecesCount(int(constants.ErasureCodedPiecesInSegment))
			segment, err := recover(segmentChunks)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			if len(segment) != int(constants.SegmentSize) {
				return workreport.WorkReport{}, fmt.Errorf("segment size is %d, expected %d", len(segment), constants.SegmentSize)
			}
			proofPageChunks, err := getSegmentShards(erasureRoot, int(workItem.NumDataSegmentsExported)+importedDataSegment.Index/64)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			proofPage, err := recover(proofPageChunks)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			if len(proofPage) != int(constants.SegmentSize) {
				return workreport.WorkReport{}, fmt.Errorf("proof page size is %d, expected %d", len(proofPage), constants.SegmentSize)
			}
			justification, err := merklizer.JustificationFromProofPage(proofPage, importedDataSegment.Index, blake2b.Sum256)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			calculatedRoot := merklizer.GetRootUsingJustification(segment, importedDataSegment.Index, int(exportingWorkReport.WorkPackageSpecification.SegmentCount), justification, blake2b.Sum256)

			// Compare with the expected segment root
			if calculatedRoot != segmentRoot {
				return workreport.WorkReport{}, fmt.Errorf("justification verification failed: calculated root %x doesn't match segment root %x", calculatedRoot, segmentRoot)
			}
			workItemImportedSegments[importedDataSegmentIdx] = [constants.SegmentSize]byte(segment)
			workItemJustifications[importedDataSegmentIdx] = justification
		}
		importSegments[workItemIdx] = workItemImportedSegments
		justifications[workItemIdx] = workItemJustifications
		totalNumDataSegmentsExported += workItem.NumDataSegmentsExported
	}
	Refine(0, wp, nil, importSegments, 0, state.ServiceAccounts)
	return workreport.WorkReport{}, nil
}

func getSegmentShards(erasureRoot [32]byte, segmentIndex int) (map[types.ValidatorIndex][]byte, error) {
	// todo: use 140 protocol to get segment shards from 342 validators.
	// use the justifications passed in the response to immediately validate
	// by bubbling up the merkle tree to compute the root and compare with erasureRoot
	return map[types.ValidatorIndex][]byte{}, nil
}
