package statetransition

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"sync"

	"jam/pkg/bandersnatch"
	"jam/pkg/block"
	"jam/pkg/block/extrinsics"
	"jam/pkg/block/header"
	"jam/pkg/constants"
	"jam/pkg/errors"
	"jam/pkg/merklizer"
	"jam/pkg/pvm"
	"jam/pkg/sealingkeysequence"
	"jam/pkg/serializer"
	"jam/pkg/serviceaccount"
	"jam/pkg/state"
	"jam/pkg/staterepository"
	"jam/pkg/ticket"
	"jam/pkg/types"
	"jam/pkg/validatorstatistics"
	"jam/pkg/workreport"

	"golang.org/x/crypto/blake2b"
)

// Converts a slice of work reports to a set of work package hashes
func WorkReportsToWorkPackageHashes(workReports []workreport.WorkReport) map[[32]byte]struct{} {
	workPackageHashes := make(map[[32]byte]struct{})
	for _, workReport := range workReports {
		workPackageHashes[workReport.WorkPackageSpecification.WorkPackageHash] = struct{}{}
	}
	return workPackageHashes
}

// FilterWorkReportsByWorkPackageHashes filters work reports by excluding those that reference
// work packages already in the accumulated work package hashes
func FilterWorkReportsByWorkPackageHashes(r []workreport.WorkReportWithWorkPackageHashes, accumulatedWorkPackageHashes map[[32]byte]struct{}) []workreport.WorkReportWithWorkPackageHashes {
	updatedWorkReports := make([]workreport.WorkReportWithWorkPackageHashes, 0)
	for _, w := range r {
		workReport := w.WorkReport
		if _, exists := accumulatedWorkPackageHashes[workReport.WorkPackageSpecification.WorkPackageHash]; exists {
			continue
		}
		workPackageHashes := make(map[[32]byte]struct{})
		for workPackageHash := range w.WorkPackageHashes {
			if _, exists := accumulatedWorkPackageHashes[workPackageHash]; !exists {
				workPackageHashes[workPackageHash] = struct{}{}
			}
		}
		updatedWorkReports = append(updatedWorkReports, workreport.WorkReportWithWorkPackageHashes{
			WorkReport:        workReport,
			WorkPackageHashes: workPackageHashes,
		})
	}
	return updatedWorkReports
}

func STF(curBlock block.Block) ([32]byte, error) {

	// 1. Begin a transaction for reorganization
	tx, err := staterepository.NewTrackedTx(curBlock.Header.PriorStateRoot)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to begin reorganization transaction: %w", err)
	}
	// Use a separate txErr variable to track transaction errors
	defer tx.Close()

	parentBlock, err := block.Get(tx, curBlock.Header.ParentHash)
	// (5.2) implicitly, there is no block whose header hash is equal to b.Header.ParentHash
	if err != nil {
		return [32]byte{}, err
	}

	// (5.4)
	if curBlock.Header.ExtrinsicHash != curBlock.Extrinsics.MerkleCommitment() {
		return [32]byte{}, errors.ProtocolErrorf("extrinsic hash does not match actual extrinsic hash")
	}

	// (5.7)
	if curBlock.Header.TimeSlot <= parentBlock.Block.Header.TimeSlot {
		return [32]byte{}, errors.ProtocolErrorf("time slot is not greater than parent block time slot")
	}

	// if curBlock.Header.TimeSlot*types.Timeslot(constants.SlotPeriodInSeconds) > types.Timeslot(time.Now().Unix()-constants.JamCommonEraStartUnixTime) {
	// 	return fmt.Errorf("block timestamp is in the future relative to current time")
	// }

	// If current tip is not the parent block, we need to reorganize
	if curBlock.Header.PriorStateRoot != parentBlock.Info.PosteriorStateRoot {
		panic("not handling reorganization yet")
		// // 1. Find latest snapshot before parent block
		// latestSnapshot, err := block.FindLatestSnapshotBefore(parentBlock)
		// if err != nil {
		// 	return [32]byte{}, fmt.Errorf("failed to find latest snapshot: %w", err)
		// }

		// // 2. Load snapshot state
		// if err := staterepository.LoadSnapshot(tx, latestSnapshot.StateRoot); err != nil {
		// 	return [32]byte{}, fmt.Errorf("failed to load snapshot: %w", err)
		// }

		// // 3. Replay forward changes from snapshot to parent
		// pathFromSnapshot, err := parentBlock.GetPathFromAncestor(tx, latestSnapshot)
		// if err != nil {
		// 	return [32]byte{}, fmt.Errorf("failed to get path from snapshot: %w", err)
		// }

		// if err := block.ReplayPath(tx, pathFromSnapshot); err != nil {
		// 	return [32]byte{}, err
		// }
	}

	// 5.8
	if curBlock.Header.PriorStateRoot != parentBlock.Info.PosteriorStateRoot {
		return [32]byte{}, fmt.Errorf("parent block state root does not match merklized state")
	}

	// Run state transition function on globalBatch (so it sees the parentBlock state)
	if err := stfHelper(tx, curBlock); err != nil {
		return [32]byte{}, err
	}

	if err := tx.FlushMemoryToDB(); err != nil {
		return [32]byte{}, err
	}

	root := tx.GetStateRoot()

	blockWithInfo := &block.BlockWithInfo{
		Block: curBlock,
		Info: block.BlockInfo{
			PosteriorStateRoot: root,
			Height:             parentBlock.Info.Height + 1,
		},
	}

	if err := blockWithInfo.Set(tx); err != nil {
		return [32]byte{}, fmt.Errorf("failed to save block with info: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return [32]byte{}, err
	}

	return root, nil
}

// StateTransitionFunction computes the new state given a state state and a valid block.
// Each field in the new state is computed concurrently. Each compute function returns the
// "posterior" value (the new field) and an optional error.
func stfHelper(tx *staterepository.TrackedTx, curBlock block.Block) error {

	// Load state
	priorState, err := state.GetState(tx)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Verify block
	if err := curBlock.Verify(tx, priorState); err != nil {
		return err
	}

	posteriorMostRecentBlockTimeslot := computeMostRecentBlockTimeslot(curBlock.Header)

	intermediateRecentBlocks := computeIntermediateRecentBlocks(curBlock.Header, priorState.RecentActivity.RecentBlocks)

	for _, refinementContext := range curBlock.Extrinsics.Guarantees.RefinementContexts() {
		found := false
		// (11.33)
		for _, recentBlock := range intermediateRecentBlocks {
			if refinementContext.AnchorHeaderHash != recentBlock.HeaderHash {
				continue
			}
			if refinementContext.PosteriorStateRoot != recentBlock.StateRoot {
				continue
			}
			if refinementContext.PosteriorBEEFYRoot != recentBlock.MMRSuperPeak {
				continue
			}
			found = true
		}
		if !found {
			return errors.ProtocolErrorf("refinement context work package hash not found in recent blocks")
		}
	}

	posteriorEntropyAccumulator, err := computeEntropyAccumulator(curBlock.Header, priorState.MostRecentBlockTimeslot, priorState.EntropyAccumulator)
	if err != nil {
		return err
	}

	posteriorValidatorKeysetsActive := computeValidatorKeysetsActive(curBlock.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsActive, priorState.SafroleBasicState)

	posteriorDisputes := computeDisputes(curBlock.Extrinsics.Disputes, priorState.Disputes)

	// Start Safrole computation using reusable worker (eliminates goroutine creation overhead)
	safroleWorkerOnce.Do(initSafroleWorker)
	safroleResultChan := make(chan safroleResult, 1)

	task := safroleTask{
		header:                          curBlock.Header,
		mostRecentBlockTimeslot:         priorState.MostRecentBlockTimeslot,
		tickets:                         curBlock.Extrinsics.Tickets,
		safroleBasicState:               priorState.SafroleBasicState,
		validatorKeysetsStaging:         priorState.ValidatorKeysetsStaging,
		posteriorValidatorKeysetsActive: posteriorValidatorKeysetsActive,
		posteriorDisputes:               posteriorDisputes,
		posteriorEntropyAccumulator:     posteriorEntropyAccumulator,
		resultChan:                      safroleResultChan,
	}
	safroleTaskChan <- task

	posteriorValidatorKeysetsPriorEpoch := computeValidatorKeysetsPriorEpoch(curBlock.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsPriorEpoch, priorState.ValidatorKeysetsActive)

	postJudgementIntermediatePendingReports := computePostJudgementIntermediatePendingReports(curBlock.Extrinsics.Disputes, priorState.PendingReports)

	availableReports, err := computeAvailableReports(postJudgementIntermediatePendingReports, curBlock.Extrinsics.Assurances)
	if err != nil {
		return err
	}

	accumulatableWorkReports, queuedExecutionWorkReports := computeAccumulatableWorkReportsAndQueuedExecutionWorkReports(curBlock.Header, curBlock.Extrinsics.Assurances, availableReports, priorState.AccumulationHistory, priorState.AccumulationQueue)

	accumulationStateComponents, accumulationOutputSequence, posteriorAccumulationQueue, posteriorAccumulationHistory, deferredTransferStatistics, accumulationStatistics, err := accumulateAndIntegrate(
		tx,
		priorState,
		posteriorMostRecentBlockTimeslot,
		accumulatableWorkReports,
		queuedExecutionWorkReports,
		posteriorEntropyAccumulator,
	)
	if err != nil {
		return err
	}

	postguaranteesExtrinsicIntermediatePendingReports := computePostGuaranteesExtrinsicIntermediatePendingReports(curBlock.Header, curBlock.Extrinsics.Assurances, postJudgementIntermediatePendingReports)

	for _, guarantee := range curBlock.Extrinsics.Guarantees {
		// (11.29)
		if postguaranteesExtrinsicIntermediatePendingReports[guarantee.WorkReport.CoreIndex] != nil {
			return errors.ProtocolErrorf("duplicate guarantee for core %d", guarantee.WorkReport.CoreIndex)
		}
		authorizersPoolHasWorkReport := false
		for _, authorizer := range priorState.AuthorizersPool[guarantee.WorkReport.CoreIndex] {
			if authorizer == guarantee.WorkReport.AuthorizerHash {
				authorizersPoolHasWorkReport = true
				break
			}
		}
		if !authorizersPoolHasWorkReport {
			return errors.ProtocolErrorf("authorizer %s not in authorizers pool for core %d", guarantee.WorkReport.AuthorizerHash, guarantee.WorkReport.CoreIndex)
		}
	}

	posteriorPendingReports := computePendingReports(curBlock.Extrinsics.Guarantees, postguaranteesExtrinsicIntermediatePendingReports, posteriorMostRecentBlockTimeslot)

	posteriorRecentActivity := computeRecentActivity(curBlock.Header, curBlock.Extrinsics.Guarantees, intermediateRecentBlocks, priorState.RecentActivity.AccumulationOutputLog, accumulationOutputSequence)

	if err := computeServiceAccounts(tx, curBlock.Extrinsics.Preimages, posteriorMostRecentBlockTimeslot); err != nil {
		return fmt.Errorf("failed to compute service accounts: %w", err)
	}

	authorizersPool := computeAuthorizersPool(curBlock.Header, curBlock.Extrinsics.Guarantees, priorState.AuthorizerQueue, priorState.AuthorizersPool)

	validatorStatistics := computeValidatorStatistics(curBlock.Extrinsics.Guarantees, curBlock.Extrinsics.Preimages, curBlock.Extrinsics.Assurances, curBlock.Extrinsics.Tickets, priorState.MostRecentBlockTimeslot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch, priorState.ValidatorStatistics, curBlock.Header, availableReports, deferredTransferStatistics, accumulationStatistics, posteriorEntropyAccumulator, posteriorDisputes)

	// Wait for Safrole computation to complete
	safroleRes := <-safroleResultChan
	if safroleRes.err != nil {
		return fmt.Errorf("failed to compute safrole basic state: %w", safroleRes.err)
	}

	// Create post-state using pointer to avoid massive 50-200MB allocation
	postState := &state.State{}
	postState.AuthorizersPool = authorizersPool
	postState.RecentActivity = posteriorRecentActivity
	postState.SafroleBasicState = safroleRes.state
	postState.EntropyAccumulator = posteriorEntropyAccumulator
	postState.ValidatorKeysetsStaging = accumulationStateComponents.UpcomingValidatorKeysets
	postState.ValidatorKeysetsActive = posteriorValidatorKeysetsActive
	postState.ValidatorKeysetsPriorEpoch = posteriorValidatorKeysetsPriorEpoch
	postState.PendingReports = posteriorPendingReports
	postState.MostRecentBlockTimeslot = posteriorMostRecentBlockTimeslot
	postState.AuthorizerQueue = accumulationStateComponents.AuthorizersQueue
	postState.PrivilegedServices = accumulationStateComponents.PrivilegedServices
	postState.Disputes = posteriorDisputes
	postState.ValidatorStatistics = validatorStatistics
	postState.AccumulationQueue = posteriorAccumulationQueue
	postState.AccumulationHistory = posteriorAccumulationHistory
	postState.AccumulationOutputLog = accumulationOutputSequence

	// Post-transition validation
	if err := curBlock.VerifyPostStateTransition(priorState, postState); err != nil {
		return err
	}

	// Save state
	if err := postState.Set(tx); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

func computeAvailableReports(pendingReports [constants.NumCores]*state.PendingReport, assurances extrinsics.Assurances) ([]workreport.WorkReport, error) {
	// (11.15)
	for _, assurance := range assurances {
		for coreIndex := range constants.NumCores {
			if assurance.CoreAvailabilityContributions.BitAt(int(coreIndex)) && pendingReports[coreIndex] == nil {
				return nil, errors.ProtocolErrorf("assurance for core %d is missing", coreIndex)
			}
		}
	}
	var availableReports []workreport.WorkReport
	for coreIndex := range constants.NumCores {
		if pendingReports[coreIndex] == nil {
			continue
		}
		if !assurances.AvailabilityContributionsForCoreSupermajority(types.CoreIndex(coreIndex)) {
			continue
		}
		availableReports = append(availableReports, pendingReports[coreIndex].WorkReport)
	}
	return availableReports, nil
}

func computeAuthorizersPool(header header.Header, guarantees extrinsics.Guarantees, posteriorAuthorizerQueue [constants.NumCores][constants.AuthorizerQueueLength][32]byte, priorAuthorizersPool [constants.NumCores][][32]byte) [constants.NumCores][][32]byte {
	posteriorAuthorizersPool := [constants.NumCores][][32]byte{}
	for coreIndex, priorAuthorizersPoolForCore := range priorAuthorizersPool {
		var workReport *workreport.WorkReport
		for _, guarantee := range guarantees {
			if guarantee.WorkReport.CoreIndex == types.GenericNum(coreIndex) {
				workReport = &guarantee.WorkReport
				break
			}
		}
		if workReport != nil {
			for i, authorizerHash := range priorAuthorizersPoolForCore {
				if authorizerHash == workReport.AuthorizerHash {
					priorAuthorizersPoolForCore = append(priorAuthorizersPoolForCore[:i], priorAuthorizersPoolForCore[i+1:]...)
					break
				}
			}
		}
		posteriorAuthorizerQueueForCore := posteriorAuthorizerQueue[coreIndex]
		priorAuthorizersPoolForCore = append(priorAuthorizersPoolForCore, posteriorAuthorizerQueueForCore[int(uint32(header.TimeSlot)%uint32(len(posteriorAuthorizerQueueForCore)))])
		if len(priorAuthorizersPoolForCore) < int(constants.MaxItemsInAuthorizationsPool) {
			posteriorAuthorizersPool[coreIndex] = priorAuthorizersPoolForCore
		} else {
			posteriorAuthorizersPool[coreIndex] = priorAuthorizersPoolForCore[len(priorAuthorizersPoolForCore)-int(constants.MaxItemsInAuthorizationsPool):]
		}
	}
	return posteriorAuthorizersPool
}

func computeIntermediateRecentBlocks(header header.Header, priorRecentBlocks []state.RecentBlock) []state.RecentBlock {
	// Create a deep copy of the slice and its contents
	posteriorRecentBlocks := make([]state.RecentBlock, len(priorRecentBlocks))
	for i, block := range priorRecentBlocks {
		posteriorRecentBlocks[i] = block.DeepCopy()
	}

	// Now modify the copy, not the original
	if len(posteriorRecentBlocks) > 0 {
		posteriorRecentBlocks[len(posteriorRecentBlocks)-1].StateRoot = header.PriorStateRoot
	}
	return posteriorRecentBlocks
}

func computeAccumulationOutputLog(priorAccumulationOutputLog merklizer.MMBelt, accumulationOutputSequence []pvm.BEEFYCommitment) merklizer.MMBelt {

	blobs := make([][]byte, 0, len(accumulationOutputSequence))
	for _, commitment := range accumulationOutputSequence {
		serialized := serializer.Serialize(commitment)
		blobs = append(blobs, serialized)
	}

	return merklizer.Append(priorAccumulationOutputLog, merklizer.WellBalancedBinaryMerkle(blobs, merklizer.Keccak256Hash), merklizer.Keccak256Hash)
}

func computeRecentActivity(header header.Header, guarantees extrinsics.Guarantees, intermediateRecentBlocks []state.RecentBlock, priorAccumulationOutputLog merklizer.MMBelt, accumulationOutputSequence []pvm.BEEFYCommitment) state.RecentActivity {
	posteriorAccumulationOutputLog := computeAccumulationOutputLog(priorAccumulationOutputLog, accumulationOutputSequence)

	// Create work package hashes map
	workPackageHashesToSegmentRoots := make(map[[32]byte][32]byte)
	for _, guarantee := range guarantees {
		// Calculate the work package hash ((gw)s)h
		workPackageSpecification := guarantee.WorkReport.WorkPackageSpecification
		workPackageHashesToSegmentRoots[workPackageSpecification.WorkPackageHash] = workPackageSpecification.SegmentRoot
	}

	// Create the new recent block
	newRecentBlock := state.RecentBlock{
		HeaderHash:                      blake2b.Sum256(serializer.Serialize(header)),
		MMRSuperPeak:                    merklizer.MMRSuperPeak(posteriorAccumulationOutputLog),
		StateRoot:                       [32]byte{},
		WorkPackageHashesToSegmentRoots: workPackageHashesToSegmentRoots,
	}
	// Append the new block to the recent blocks list
	updatedRecentBlocks := append(intermediateRecentBlocks, newRecentBlock)
	// Keep only the most recent H blocks
	if len(updatedRecentBlocks) > int(constants.RecentHistorySizeBlocks) {
		// Trim the list to keep only the most recent H blocks
		updatedRecentBlocks = updatedRecentBlocks[len(updatedRecentBlocks)-int(constants.RecentHistorySizeBlocks):]
	}

	return state.RecentActivity{
		AccumulationOutputLog: posteriorAccumulationOutputLog,
		RecentBlocks:          updatedRecentBlocks,
	}
}

func computeSafroleBasicState(header header.Header, mostRecentBlockTimeslot types.Timeslot, tickets extrinsics.Tickets, priorSafroleBasicState state.SafroleBasicState, priorValidatorKeysetsStaging types.ValidatorKeysets, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorDisputes types.Disputes, posteriorEntropyAccumulator [4][32]byte) (state.SafroleBasicState, error) {
	var posteriorValidatorKeysetsPending types.ValidatorKeysets
	var posteriorEpochTicketSubmissionsRoot types.BandersnatchRingRoot
	var posteriorSealingKeySequence sealingkeysequence.SealingKeySequence
	posteriorTicketAccumulator := make([]ticket.Ticket, 0)
	for _, extrinsicTicket := range tickets {
		vrfOutput, err := bandersnatch.BandersnatchRingVRFProofOutput(extrinsicTicket.ValidityProof)
		if err != nil {
			return state.SafroleBasicState{}, err
		}
		posteriorTicketAccumulator = append(posteriorTicketAccumulator, ticket.Ticket{
			VerifiablyRandomIdentifier: vrfOutput,
			EntryIndex:                 extrinsicTicket.EntryIndex,
		})
	}
	for _, priorTicket := range priorSafroleBasicState.TicketAccumulator {
		for _, newTicket := range posteriorTicketAccumulator {
			if priorTicket.VerifiablyRandomIdentifier == newTicket.VerifiablyRandomIdentifier {
				return state.SafroleBasicState{}, errors.ProtocolErrorf("duplicate ticket: %v", priorTicket.VerifiablyRandomIdentifier)
			}
		}
	}
	sort.Slice(posteriorTicketAccumulator, func(i, j int) bool {
		return bytes.Compare(posteriorTicketAccumulator[i].VerifiablyRandomIdentifier[:], posteriorTicketAccumulator[j].VerifiablyRandomIdentifier[:]) < 0
	})
	// Remove duplicate tickets (tickets with the same VerifiablyRandomIdentifier)
	if len(posteriorTicketAccumulator) > 1 {
		uniqueTickets := make([]ticket.Ticket, 0, len(posteriorTicketAccumulator))
		uniqueTickets = append(uniqueTickets, posteriorTicketAccumulator[0])

		for i := 1; i < len(posteriorTicketAccumulator); i++ {
			// If this ticket's identifier is different from the previous one, add it
			if !bytes.Equal(posteriorTicketAccumulator[i].VerifiablyRandomIdentifier[:], posteriorTicketAccumulator[i-1].VerifiablyRandomIdentifier[:]) {
				uniqueTickets = append(uniqueTickets, posteriorTicketAccumulator[i])
			}
		}
		posteriorTicketAccumulator = uniqueTickets
	}
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		// posteriorValidatorKeysetsPending
		posteriorValidatorKeysetsPending = priorValidatorKeysetsStaging.KeyNullifier(posteriorDisputes)

		// posteriorEpochTicketSubmissionsRoot
		var posteriorBandersnatchPublicKeysPending [constants.NumValidators]types.BandersnatchPublicKey
		for index, keyset := range posteriorValidatorKeysetsPending {
			posteriorBandersnatchPublicKeysPending[index] = keyset.ToBandersnatchPublicKey()
		}
		posteriorEpochTicketSubmissionsRoot = bandersnatch.BandersnatchRingRoot(posteriorBandersnatchPublicKeysPending[:])

		// posteriorSealingKeySequence
		if header.TimeSlot.EpochIndex() == mostRecentBlockTimeslot.EpochIndex()+1 && mostRecentBlockTimeslot.SlotPhaseIndex() >= int(constants.TicketSubmissionEndingSlotPhaseNumber) && len(priorSafroleBasicState.TicketAccumulator) == int(constants.NumTimeslotsPerEpoch) {
			reorderedSlice := ticket.ReorderTicketsOutsideIn(priorSafroleBasicState.TicketAccumulator[:])
			var reorderedArray [constants.NumTimeslotsPerEpoch]ticket.Ticket
			copy(reorderedArray[:], reorderedSlice)
			posteriorSealingKeySequence = sealingkeysequence.NewSealKeyTicketSeries(reorderedArray)
		} else {
			var bandersnatchKeys [constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey
			for i := range constants.NumTimeslotsPerEpoch {
				iSerialized := serializer.EncodeLittleEndian(4, uint64(i))
				hashedEntropyValue := blake2b.Sum256(append(posteriorEntropyAccumulator[2][:], iSerialized...))
				posteriorActiveValidatorPKsIndex := binary.LittleEndian.Uint32(hashedEntropyValue[:4])
				bandersnatchKeys[i] = posteriorValidatorKeysetsActive[int(posteriorActiveValidatorPKsIndex)%len(posteriorValidatorKeysetsActive)].ToBandersnatchPublicKey()
			}
			posteriorSealingKeySequence = sealingkeysequence.NewBandersnatchKeysSeries(bandersnatchKeys)
		}
	} else {
		posteriorValidatorKeysetsPending = priorSafroleBasicState.ValidatorKeysetsPending

		posteriorEpochTicketSubmissionsRoot = priorSafroleBasicState.EpochTicketSubmissionsRoot

		posteriorSealingKeySequence = priorSafroleBasicState.SealingKeySequence

		posteriorTicketAccumulator = append(posteriorTicketAccumulator, priorSafroleBasicState.TicketAccumulator...)
		sort.Slice(posteriorTicketAccumulator, func(i, j int) bool {
			return bytes.Compare(posteriorTicketAccumulator[i].VerifiablyRandomIdentifier[:], posteriorTicketAccumulator[j].VerifiablyRandomIdentifier[:]) < 0
		})
	}

	return state.SafroleBasicState{
		ValidatorKeysetsPending:    posteriorValidatorKeysetsPending,
		EpochTicketSubmissionsRoot: posteriorEpochTicketSubmissionsRoot,
		SealingKeySequence:         posteriorSealingKeySequence,
		TicketAccumulator:          posteriorTicketAccumulator[:int(math.Min(float64(len(posteriorTicketAccumulator)), float64(constants.NumTimeslotsPerEpoch)))],
	}, nil
}

// NOTE: This function modifies postAccumulationIntermediateServiceAccounts directly
func computeServiceAccounts(tx *staterepository.TrackedTx, preimages extrinsics.Preimages, posteriorMostRecentBlockTimeslot types.Timeslot) error {
	for _, preimage := range preimages {
		hash := blake2b.Sum256(preimage.Data)
		ok, err := serviceaccount.IsNewPreimage(tx, types.ServiceIndex(preimage.ServiceIndex), hash, types.BlobLength(len(preimage.Data)))
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		serviceAccount, exists, err := serviceaccount.GetServiceAccount(tx, types.ServiceIndex(preimage.ServiceIndex))
		if err != nil {
			return err
		}
		if !exists {
			return errors.ProtocolErrorf("service account %d does not exist", types.ServiceIndex(preimage.ServiceIndex))
		}
		serviceAccount.SetPreimageForHash(tx, hash, preimage.Data)
		if err := serviceAccount.SetPreimageLookupHistoricalStatus(tx, uint32(len(preimage.Data)), hash, []types.Timeslot{posteriorMostRecentBlockTimeslot}); err != nil {
			return err
		}
	}
	return nil
}

func computeEntropyAccumulator(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorEntropyAccumulator [4][32]byte) ([4][32]byte, error) {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput(header.VRFSignature)
	if err != nil {
		return posteriorEntropyAccumulator, err
	}
	posteriorEntropyAccumulator[0] = blake2b.Sum256(append(priorEntropyAccumulator[0][:], randomVRFOutput[:]...))
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		posteriorEntropyAccumulator[1] = priorEntropyAccumulator[0]
		posteriorEntropyAccumulator[2] = priorEntropyAccumulator[1]
		posteriorEntropyAccumulator[3] = priorEntropyAccumulator[2]
	} else {
		posteriorEntropyAccumulator[1] = priorEntropyAccumulator[1]
		posteriorEntropyAccumulator[2] = priorEntropyAccumulator[2]
		posteriorEntropyAccumulator[3] = priorEntropyAccumulator[3]
	}
	return posteriorEntropyAccumulator, nil
}

func computeValidatorKeysetsActive(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorValidatorKeysetsActive types.ValidatorKeysets, priorSafroleBasicState state.SafroleBasicState) types.ValidatorKeysets {
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		return priorSafroleBasicState.ValidatorKeysetsPending
	}
	return priorValidatorKeysetsActive
}

func computeValidatorKeysetsPriorEpoch(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorKeysetsActive types.ValidatorKeysets) types.ValidatorKeysets {
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		return priorValidatorKeysetsActive
	}
	return priorValidatorKeysetsPriorEpoch
}

// destroys priorDisputes
func computePostJudgementIntermediatePendingReports(disputes extrinsics.Disputes, priorPendingReports [constants.NumCores]*state.PendingReport) [constants.NumCores]*state.PendingReport {
	posteriorPendingReports := priorPendingReports // Direct array assignment
	validJudgementsMap := disputes.ToSumOfValidJudgementsMap()
	for c, value := range posteriorPendingReports {
		if value == nil {
			continue
		}
		serializedWorkReport := serializer.Serialize(value.WorkReport)
		workReportHash := blake2b.Sum256(serializedWorkReport)
		if validJudgementsSum, exists := validJudgementsMap[workReportHash]; exists {
			if validJudgementsSum < int(constants.TwoThirdsNumValidators) {
				posteriorPendingReports[c] = nil
			}
		}
	}
	return posteriorPendingReports
}

func computePostGuaranteesExtrinsicIntermediatePendingReports(header header.Header, assurances extrinsics.Assurances, postJudgementIntermediatePendingReports [constants.NumCores]*state.PendingReport) [constants.NumCores]*state.PendingReport {
	// Create a copy of the input array
	posteriorPendingReports := postJudgementIntermediatePendingReports

	// Apply the modifications to the copy
	for coreIndex, pendingReport := range posteriorPendingReports {
		if pendingReport == nil {
			continue
		}
		nowAvailable := assurances.AvailabilityContributionsForCoreSupermajority(types.CoreIndex(coreIndex))
		timedOut := int(header.TimeSlot) >= int(pendingReport.Timeslot)+int(constants.UnavailableWorkTimeoutTimeslots)
		if nowAvailable || timedOut {
			posteriorPendingReports[coreIndex] = nil
		}
	}
	return posteriorPendingReports
}

func computePendingReports(guarantees extrinsics.Guarantees, postGuaranteesExtrinsicIntermediatePendingReports [constants.NumCores]*state.PendingReport, posteriorMostRecentBlockTimeslot types.Timeslot) [constants.NumCores]*state.PendingReport {
	for coreIndex := range postGuaranteesExtrinsicIntermediatePendingReports {
		for _, guarantee := range guarantees {
			if guarantee.WorkReport.CoreIndex == types.GenericNum(coreIndex) {
				postGuaranteesExtrinsicIntermediatePendingReports[coreIndex] = &state.PendingReport{
					WorkReport: guarantee.WorkReport,
					Timeslot:   posteriorMostRecentBlockTimeslot,
				}
				break
			}
		}
	}
	return postGuaranteesExtrinsicIntermediatePendingReports
}

func computeAccumulatableWorkReportsAndQueuedExecutionWorkReports(header header.Header, assurances extrinsics.Assurances, availableReports []workreport.WorkReport, priorAccumulationHistory state.AccumulationHistory, priorAccumulationQueue [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes) ([]workreport.WorkReport, []workreport.WorkReportWithWorkPackageHashes) {
	// 1. function utils
	var accumulationPriorityQueue func(r []workreport.WorkReportWithWorkPackageHashes) []workreport.WorkReport
	accumulationPriorityQueue = func(r []workreport.WorkReportWithWorkPackageHashes) []workreport.WorkReport {
		g := make([]workreport.WorkReport, 0)
		for _, w := range r {
			if len(w.WorkPackageHashes) == 0 {
				g = append(g, w.WorkReport)
			}
		}
		if len(g) == 0 {
			return g
		}
		return append(g, accumulationPriorityQueue(FilterWorkReportsByWorkPackageHashes(r, WorkReportsToWorkPackageHashes(g)))...)
	}

	// 2. create immediate and queued WRs
	immediatelyAccumulatableWorkReports := make([]workreport.WorkReport, 0)
	queuedExecutionWorkReports := make([]workreport.WorkReportWithWorkPackageHashes, 0)
	for _, workReport := range availableReports {
		if len(workReport.RefinementContext.PrerequisiteWorkPackageHashes) == 0 && len(workReport.SegmentRootLookup) == 0 {
			immediatelyAccumulatableWorkReports = append(immediatelyAccumulatableWorkReports, workReport)
		} else {
			workPackageHashes := make(map[[32]byte]struct{})
			for workPackageHash := range workReport.RefinementContext.PrerequisiteWorkPackageHashes {
				workPackageHashes[workPackageHash] = struct{}{}
			}
			for workPackageHash := range workReport.SegmentRootLookup {
				workPackageHashes[workPackageHash] = struct{}{}
			}
			queuedExecutionWorkReports = append(queuedExecutionWorkReports, workreport.WorkReportWithWorkPackageHashes{
				WorkReport:        workReport,
				WorkPackageHashes: workPackageHashes,
			})
		}
	}
	queuedExecutionWorkReports = FilterWorkReportsByWorkPackageHashes(queuedExecutionWorkReports, priorAccumulationHistory.ToUnionSet())

	// 3. combine everything
	m := int(header.TimeSlot) % int(constants.NumTimeslotsPerEpoch)
	var flattenedAfterM []workreport.WorkReportWithWorkPackageHashes
	for _, inner := range priorAccumulationQueue[m:] {
		flattenedAfterM = append(flattenedAfterM, inner...)
	}
	var flattenedBeforeM []workreport.WorkReportWithWorkPackageHashes
	for _, inner := range priorAccumulationQueue[:m] {
		flattenedBeforeM = append(flattenedBeforeM, inner...)
	}
	q := FilterWorkReportsByWorkPackageHashes(append(flattenedAfterM, append(flattenedBeforeM, queuedExecutionWorkReports...)...), WorkReportsToWorkPackageHashes(immediatelyAccumulatableWorkReports))
	return append(immediatelyAccumulatableWorkReports, accumulationPriorityQueue(q)...), queuedExecutionWorkReports
	// wtf did i just do^
}

func accumulateAndIntegrate(
	tx *staterepository.TrackedTx,
	priorState *state.State,
	posteriorMostRecentBlockTimeslot types.Timeslot,
	accumulatableWorkReports []workreport.WorkReport,
	queuedExecutionWorkReports []workreport.WorkReportWithWorkPackageHashes,
	posteriorEntropyAccumulator [4][32]byte,
) (pvm.AccumulationStateComponents, []pvm.BEEFYCommitment, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes, state.AccumulationHistory, validatorstatistics.TransferStatistics, validatorstatistics.AccumulationStatistics, error) {
	gas := max(types.GasValue(constants.AllAccumulationTotalGasAllocation), types.GasValue(constants.SingleAccumulationAllocatedGas*uint64(constants.NumCores))+priorState.PrivilegedServices.TotalAlwaysAccumulateGas())
	n, o, deferredTransfers, C, serviceGasUsage, err := pvm.OuterAccumulation(tx, gas, posteriorMostRecentBlockTimeslot, accumulatableWorkReports, &pvm.AccumulationStateComponents{
		UpcomingValidatorKeysets: priorState.ValidatorKeysetsStaging,
		AuthorizersQueue:         priorState.AuthorizerQueue,
		PrivilegedServices:       priorState.PrivilegedServices,
	}, priorState.PrivilegedServices.AlwaysAccumulateServicesWithGas, posteriorEntropyAccumulator)

	if err != nil {
		return pvm.AccumulationStateComponents{}, nil, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}, state.AccumulationHistory{}, validatorstatistics.TransferStatistics{}, validatorstatistics.AccumulationStatistics{}, err
	}

	var accumulationStatistics = validatorstatistics.AccumulationStatistics{}
	workDigestsForServiceIndex := map[types.ServiceIndex][]workreport.WorkDigest{}
	for _, workReport := range accumulatableWorkReports[:n] {
		for _, workDigest := range workReport.WorkDigests {
			workDigestsForServiceIndex[workDigest.ServiceIndex] = append(workDigestsForServiceIndex[workDigest.ServiceIndex], workDigest)
		}
	}
	for serviceIndex, digests := range workDigestsForServiceIndex {
		var gasUsed types.GasValue
		for _, serviceAndGasUsage := range serviceGasUsage {
			if serviceAndGasUsage.ServiceIndex != serviceIndex {
				continue
			}
			gasUsed += serviceAndGasUsage.GasUsed
		}
		accumulationStatistics[serviceIndex] = validatorstatistics.ServiceAccumulationStatistics{
			NumberOfWorkItems: types.GenericNum(len(digests)),
			GasUsed:           types.GenericNum(gasUsed),
		}
	}

	for serviceIndex, _ := range accumulationStatistics {
		serviceAccount, exists, err := serviceaccount.GetServiceAccount(tx, serviceIndex)
		if err != nil {
			return pvm.AccumulationStateComponents{}, nil, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}, state.AccumulationHistory{}, validatorstatistics.TransferStatistics{}, validatorstatistics.AccumulationStatistics{}, err
		}
		if !exists {
			return pvm.AccumulationStateComponents{}, nil, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}, state.AccumulationHistory{}, validatorstatistics.TransferStatistics{}, validatorstatistics.AccumulationStatistics{}, nil
		}
		serviceAccount.MostRecentAccumulationTimeslot = posteriorMostRecentBlockTimeslot
		serviceaccount.SetServiceAccount(tx, serviceAccount)
	}

	var deferredTransferStatistics = validatorstatistics.TransferStatistics{}

	var deferredTransfersForServiceIndex = make(map[types.ServiceIndex][]pvm.DeferredTransfer)
	for _, deferredTransfer := range deferredTransfers {
		deferredTransfersForServiceIndex[deferredTransfer.ReceiverServiceIndex] = append(deferredTransfersForServiceIndex[deferredTransfer.ReceiverServiceIndex], deferredTransfer)
	}

	for serviceIndex, deferredTransfers := range deferredTransfersForServiceIndex {
		_, gasUsed, err := pvm.OnTransfer(tx, posteriorMostRecentBlockTimeslot, serviceIndex, posteriorEntropyAccumulator, deferredTransfers)
		if err != nil {
			return pvm.AccumulationStateComponents{}, nil, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}, state.AccumulationHistory{}, validatorstatistics.TransferStatistics{}, validatorstatistics.AccumulationStatistics{}, err
		}
		deferredTransferStatistics[serviceIndex] = validatorstatistics.ServiceTransferStatistics{
			NumberOfTransfers: types.GenericNum(len(deferredTransfers)),
			GasUsed:           types.GenericNum(gasUsed),
		}
	}

	// Create a copy of the accumulation history before modifying it
	posteriorAccumulationHistory := priorState.AccumulationHistory
	posteriorAccumulationHistory.ShiftLeft(WorkReportsToWorkPackageHashes(accumulatableWorkReports[:n]))

	var posteriorAccumulationQueue [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes

	// Initialize with empty slices
	for i := range constants.NumTimeslotsPerEpoch {
		posteriorAccumulationQueue[i] = make([]workreport.WorkReportWithWorkPackageHashes, 0)
	}

	m := posteriorMostRecentBlockTimeslot.SlotPhaseIndex()
	timeslotDiff := int(posteriorMostRecentBlockTimeslot) - int(priorState.MostRecentBlockTimeslot)

	for i := range constants.NumTimeslotsPerEpoch {
		queueIndex := (m + int(constants.NumTimeslotsPerEpoch) - int(i)) % int(constants.NumTimeslotsPerEpoch)
		if i == 0 {
			posteriorAccumulationQueue[queueIndex] = FilterWorkReportsByWorkPackageHashes(
				queuedExecutionWorkReports,
				posteriorAccumulationHistory[len(posteriorAccumulationHistory)-1])
		} else if int(i) < timeslotDiff {
		} else {
			posteriorAccumulationQueue[queueIndex] = FilterWorkReportsByWorkPackageHashes(priorState.AccumulationQueue[queueIndex], posteriorAccumulationHistory[len(posteriorAccumulationHistory)-1])
		}
	}

	return o, C, posteriorAccumulationQueue, posteriorAccumulationHistory, deferredTransferStatistics, accumulationStatistics, nil
}

func computeMostRecentBlockTimeslot(blockHeader header.Header) types.Timeslot {
	return blockHeader.TimeSlot
}

// destroys priorDisputes
func computeDisputes(disputesExtrinsic extrinsics.Disputes, priorDisputes types.Disputes) types.Disputes {
	sumOfValidJudgementsMap := disputesExtrinsic.ToSumOfValidJudgementsMap()
	for r, validCount := range sumOfValidJudgementsMap {
		if validCount == int(constants.NumValidatorSafetyThreshold) {
			priorDisputes.WorkReportHashesGood[r] = struct{}{}
		} else if validCount == 0 {
			priorDisputes.WorkReportHashesBad[r] = struct{}{}
		} else if validCount == int(constants.OneThirdNumValidators) {
			priorDisputes.WorkReportHashesWonky[r] = struct{}{}
		}
	}
	for _, c := range disputesExtrinsic.Culprits {
		priorDisputes.ValidatorPunishes[c.ValidatorKey] = struct{}{}
	}
	for _, f := range disputesExtrinsic.Faults {
		priorDisputes.ValidatorPunishes[f.ValidatorKey] = struct{}{}
	}
	return priorDisputes
}

func computeValidatorStatistics(guarantees extrinsics.Guarantees, preimages extrinsics.Preimages, assurances extrinsics.Assurances, tickets extrinsics.Tickets, priorMostRecentBlockTimeslot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorStatistics validatorstatistics.ValidatorStatistics, header header.Header, availableReports []workreport.WorkReport, deferredTransferStatistics validatorstatistics.TransferStatistics, accumulationStatistics validatorstatistics.AccumulationStatistics, posteriorEntropyAccumulator [4][32]byte, posteriorDisputes types.Disputes) validatorstatistics.ValidatorStatistics {
	posteriorValidatorStatistics := priorValidatorStatistics
	var a [constants.NumValidators]validatorstatistics.SingleValidatorStatistics
	if header.TimeSlot.EpochIndex() == priorMostRecentBlockTimeslot.EpochIndex() {
		a = priorValidatorStatistics.AccumulatorStatistics
	} else {
		posteriorValidatorStatistics.PreviousEpochStatistics = priorValidatorStatistics.AccumulatorStatistics
	}
	for vIndex, vStats := range a {
		vIndex := types.ValidatorIndex(vIndex)
		vIndexIsBlockAuthor := header.BandersnatchBlockAuthorIndex == vIndex
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].BlocksProduced = vStats.BlocksProduced
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].TicketsIntroduced = vStats.TicketsIntroduced
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].PreimagesIntroduced = vStats.PreimagesIntroduced
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].OctetsIntroduced = vStats.OctetsIntroduced
		if vIndexIsBlockAuthor {
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].BlocksProduced++
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].TicketsIntroduced += uint32(len(tickets))
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].PreimagesIntroduced += uint32(len(preimages))
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].OctetsIntroduced += uint32(preimages.TotalDataSize())
		}
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].ReportsGuaranteed = vStats.ReportsGuaranteed
		r := guarantees.ReporterValidatorKeysets(posteriorEntropyAccumulator, header.TimeSlot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch, posteriorDisputes)
		if _, ok := r[posteriorValidatorKeysetsActive[vIndex].ToEd25519PublicKey()]; ok {
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].ReportsGuaranteed++
		}
		posteriorValidatorStatistics.AccumulatorStatistics[vIndex].AvailabilityAssurances = vStats.AvailabilityAssurances
		if assurances.HasValidatorIndex(vIndex) {
			posteriorValidatorStatistics.AccumulatorStatistics[vIndex].AvailabilityAssurances++
		}
	}
	for cIndex := range constants.NumCores {
		// Reset core statistics to zero (don't add to existing values)
		coreStats := validatorstatistics.CoreStatistics{} // Initialize a fresh stats object

		// Find all work reports for this core in the guarantees
		for _, guarantee := range guarantees {
			workReport := guarantee.WorkReport
			if workReport.CoreIndex != types.GenericNum(cIndex) {
				continue
			}

			// Sum statistics from each work digest in the work report
			for _, digest := range workReport.WorkDigests {
				coreStats.NumSegmentsImportedFrom += types.GenericNum(digest.NumSegmentsImportedFrom)
				coreStats.NumExtrinsicsUsed += types.GenericNum(digest.NumExtrinsicsUsed)
				coreStats.SizeInOctetsOfExtrinsicsUsed += types.GenericNum(digest.SizeInOctetsOfExtrinsicsUsed)
				coreStats.NumSegmentsExportedInto += types.GenericNum(digest.NumSegmentsExportedInto)
				coreStats.ActualRefinementGasUsed += types.GenericNum(digest.ActualRefinementGasUsed)
			}
			coreStats.WorkBundleLength += types.GenericNum(workReport.WorkPackageSpecification.WorkBundleLength)
		}

		for _, availableReport := range availableReports {
			if availableReport.CoreIndex != types.GenericNum(cIndex) {
				continue
			}

			coreStats.OctetsIntroduced += types.GenericNum(uint64(availableReport.WorkPackageSpecification.WorkBundleLength) + uint64(int(constants.SegmentSize)*int(math.Ceil(float64(availableReport.WorkPackageSpecification.SegmentCount)*65.0/64.0))))
		}

		coreStats.AvailabilityContributionsInAssurancesExtrinsic = types.GenericNum(assurances.AvailabilityContributionsForCore(types.CoreIndex(cIndex)))

		// Set the new statistics in the return value
		posteriorValidatorStatistics.CoreStatistics[cIndex] = coreStats
	}

	posteriorValidatorStatistics.ServiceStatistics = make(map[types.ServiceIndex]validatorstatistics.ServiceStatistics)

	trackedServiceIndices := map[types.ServiceIndex]struct{}{}
	for _, guarantee := range guarantees {
		for _, workDigest := range guarantee.WorkReport.WorkDigests {
			trackedServiceIndices[workDigest.ServiceIndex] = struct{}{}
		}
	}
	for _, preimage := range preimages {
		trackedServiceIndices[types.ServiceIndex(preimage.ServiceIndex)] = struct{}{}
	}
	for serviceIndex, _ := range deferredTransferStatistics {
		trackedServiceIndices[serviceIndex] = struct{}{}
	}
	for serviceIndex, _ := range accumulationStatistics {
		trackedServiceIndices[serviceIndex] = struct{}{}
	}
	for serviceIndex, _ := range trackedServiceIndices {
		serviceStatistics := validatorstatistics.ServiceStatistics{}
		for _, guarantee := range guarantees {
			for _, workDigest := range guarantee.WorkReport.WorkDigests {
				if workDigest.ServiceIndex == serviceIndex {
					serviceStatistics.NumSegmentsImportedFrom += types.GenericNum(workDigest.NumSegmentsImportedFrom)
					serviceStatistics.NumExtrinsicsUsed += types.GenericNum(workDigest.NumExtrinsicsUsed)
					serviceStatistics.SizeInOctetsOfExtrinsicsUsed += types.GenericNum(workDigest.SizeInOctetsOfExtrinsicsUsed)
					serviceStatistics.NumSegmentsExportedInto += types.GenericNum(workDigest.NumSegmentsExportedInto)
					serviceStatistics.ActualRefinementGasUsed.WorkReportCount++
					serviceStatistics.ActualRefinementGasUsed.Amount += types.GenericNum(workDigest.ActualRefinementGasUsed)
				}
			}
		}
		for _, preimage := range preimages {
			if types.ServiceIndex(preimage.ServiceIndex) == serviceIndex {
				serviceStatistics.PreimageExtrinsicSize.ExtrinsicCount++
				serviceStatistics.PreimageExtrinsicSize.TotalSizeInOctets += types.GenericNum(len(preimage.Data))
			}
		}
		if _, ok := accumulationStatistics[serviceIndex]; ok {
			serviceStatistics.AccumulationStatistics = accumulationStatistics[serviceIndex]
		}
		if _, ok := deferredTransferStatistics[serviceIndex]; ok {
			serviceStatistics.DeferredTransferStatistics = deferredTransferStatistics[serviceIndex]
		}
		posteriorValidatorStatistics.ServiceStatistics[types.ServiceIndex(serviceIndex)] = serviceStatistics
	}

	return posteriorValidatorStatistics
}

// Single reusable Safrole worker - eliminates goroutine creation overhead
var (
	safroleTaskChan   chan safroleTask
	safroleWorkerOnce sync.Once
)

type safroleTask struct {
	header                          header.Header
	mostRecentBlockTimeslot         types.Timeslot
	tickets                         []extrinsics.Ticket
	safroleBasicState               state.SafroleBasicState
	validatorKeysetsStaging         types.ValidatorKeysets
	posteriorValidatorKeysetsActive types.ValidatorKeysets
	posteriorDisputes               types.Disputes
	posteriorEntropyAccumulator     [4][32]byte
	resultChan                      chan safroleResult
}

type safroleResult struct {
	state state.SafroleBasicState
	err   error
}

func initSafroleWorker() {
	safroleTaskChan = make(chan safroleTask, 1)
	go func() {
		for task := range safroleTaskChan {
			result, err := computeSafroleBasicState(
				task.header,
				task.mostRecentBlockTimeslot,
				task.tickets,
				task.safroleBasicState,
				task.validatorKeysetsStaging,
				task.posteriorValidatorKeysetsActive,
				task.posteriorDisputes,
				task.posteriorEntropyAccumulator,
			)
			task.resultChan <- safroleResult{result, err}
		}
	}()
}
