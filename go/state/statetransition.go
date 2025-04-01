package state

import (
	"bytes"
	"encoding/binary"
	"math"
	"sort"
	"sync"

	"golang.org/x/crypto/sha3"

	"github.com/ascrivener/jam/bandersnatch"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/pvm"
	"github.com/ascrivener/jam/sealingkeysequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
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

// StateTransitionFunction computes the new state given a state state and a valid block.
// Each field in the new state is computed concurrently. Each compute function returns the
// "posterior" value (the new field) and an optional error.
func StateTransitionFunction(priorState State, block block.Block) State {

	posteriorMostRecentBlockTimeslot := computeMostRecentBlockTimeslot(block.Header)

	intermediateRecentBlocks := computeIntermediateRecentBlocks(block.Header, priorState.RecentBlocks)

	posteriorEntropyAccumulator := computeEntropyAccumulator(block.Header, priorState.MostRecentBlockTimeslot, priorState.EntropyAccumulator)

	posteriorValidatorKeysetsActive := computeValidatorKeysetsActive(block.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsActive, priorState.SafroleBasicState)

	posteriorDisputes := computeDisputes(block.Extrinsics.Disputes, priorState.Disputes)

	posteriorSafroleBasicState := computeSafroleBasicState(block.Header, priorState.MostRecentBlockTimeslot, block.Extrinsics.Tickets, priorState.SafroleBasicState, priorState.ValidatorKeysetsStaging, posteriorValidatorKeysetsActive, posteriorDisputes, posteriorEntropyAccumulator)

	posteriorValidatorKeysetsPriorEpoch := computeValidatorKeysetsPriorEpoch(block.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsPriorEpoch, priorState.ValidatorKeysetsActive)

	postJudgementIntermediatePendingReports := computePostJudgementIntermediatePendingReports(block.Extrinsics.Disputes, priorState.PendingReports)

	postguaranteesExtrinsicIntermediatePendingReports := computePostGuaranteesExtrinsicIntermediatePendingReports(block.Header, block.Extrinsics.Assurances, postJudgementIntermediatePendingReports)

	posteriorPendingReports := computePendingReports(block.Extrinsics.Guarantees, postguaranteesExtrinsicIntermediatePendingReports, posteriorMostRecentBlockTimeslot)

	workReports, queuedExecutionWorkReports := computeAccumulatableWorkReportsAndQueuedExecutionWorkReports(block.Header, block.Extrinsics.Assurances, postJudgementIntermediatePendingReports, priorState.AccumulationHistory, priorState.AccumulationQueue)

	accumulationStateComponents, BEEFYCommitments, posteriorAccumulationQueue, posteriorAccumulationHistory := accumulateAndIntegrate(
		&priorState,
		posteriorMostRecentBlockTimeslot,
		workReports,
		queuedExecutionWorkReports,
		posteriorEntropyAccumulator,
	)

	posteriorRecentBlocks := computeRecentBlocks(block.Header, block.Extrinsics.Guarantees, intermediateRecentBlocks, BEEFYCommitments)

	postAccumulationIntermediateServiceAccounts := accumulationStateComponents.ServiceAccounts
	computeServiceAccounts(block.Extrinsics.Preimages, posteriorMostRecentBlockTimeslot, &postAccumulationIntermediateServiceAccounts)

	authorizersPool := computeAuthorizersPool(block.Header, block.Extrinsics.Guarantees, priorState.AuthorizerQueue, priorState.AuthorizersPool)

	validatorStatistics := computeValidatorStatistics(block.Extrinsics.Guarantees, block.Extrinsics.Preimages, block.Extrinsics.Assurances, block.Extrinsics.Tickets, posteriorMostRecentBlockTimeslot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch, priorState.ValidatorStatistics, block.Header)

	return State{
		AuthorizersPool:            authorizersPool,
		RecentBlocks:               posteriorRecentBlocks,
		SafroleBasicState:          posteriorSafroleBasicState,
		ServiceAccounts:            postAccumulationIntermediateServiceAccounts,
		EntropyAccumulator:         posteriorEntropyAccumulator,
		ValidatorKeysetsStaging:    accumulationStateComponents.UpcomingValidatorKeysets,
		ValidatorKeysetsActive:     posteriorValidatorKeysetsActive,
		ValidatorKeysetsPriorEpoch: posteriorValidatorKeysetsPriorEpoch,
		PendingReports:             posteriorPendingReports,
		MostRecentBlockTimeslot:    posteriorMostRecentBlockTimeslot,
		AuthorizerQueue:            accumulationStateComponents.AuthorizersQueue,
		PrivilegedServices:         accumulationStateComponents.PrivilegedServices,
		Disputes:                   posteriorDisputes,
		ValidatorStatistics:        validatorStatistics,
		AccumulationQueue:          posteriorAccumulationQueue,
		AccumulationHistory:        posteriorAccumulationHistory,
	}
}

// Now, update each compute function to return (result, error).

func computeAuthorizersPool(header header.Header, guarantees extrinsics.Guarantees, posteriorAuthorizerQueue [constants.NumCores][constants.AuthorizerQueueLength][32]byte, priorAuthorizersPool [constants.NumCores][][32]byte) [constants.NumCores][][32]byte {
	posteriorAuthorizersPool := [constants.NumCores][][32]byte{}
	for coreIndex, priorAuthorizersPoolForCore := range priorAuthorizersPool {
		var workReport *workreport.WorkReport
		for _, guarantee := range guarantees {
			if guarantee.WorkReport.CoreIndex == types.CoreIndex(coreIndex) {
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
		if len(priorAuthorizersPoolForCore) < constants.MaxItemsInAuthorizationsPool {
			posteriorAuthorizersPool[coreIndex] = priorAuthorizersPoolForCore
		} else {
			posteriorAuthorizersPool[coreIndex] = priorAuthorizersPoolForCore[len(priorAuthorizersPoolForCore)-constants.MaxItemsInAuthorizationsPool:]
		}
	}
	return posteriorAuthorizersPool
}

func computeIntermediateRecentBlocks(header header.Header, priorRecentBlocks []RecentBlock) []RecentBlock {
	// Create a deep copy of the slice
	posteriorRecentBlocks := make([]RecentBlock, len(priorRecentBlocks))
	copy(posteriorRecentBlocks, priorRecentBlocks)

	// Now modify the copy, not the original
	posteriorRecentBlocks[len(posteriorRecentBlocks)-1].StateRoot = header.PriorStateRoot
	return posteriorRecentBlocks
}

func keccak256Hash(data []byte) [32]byte {
	var result [32]byte
	sum := sha3.NewLegacyKeccak256().Sum(data) // For Keccak-256
	copy(result[:], sum[:])
	return result
}

func computeRecentBlocks(header header.Header, guarantees extrinsics.Guarantees, intermediateRecentBlocks []RecentBlock, C map[pvm.BEEFYCommitment]struct{}) []RecentBlock {
	// First, collect all commitments into a slice so we can sort them
	commitments := make([]pvm.BEEFYCommitment, 0, len(C))
	for commitment := range C {
		commitments = append(commitments, commitment)
	}

	// Sort commitments by ServiceIndex
	sort.Slice(commitments, func(i, j int) bool {
		return commitments[i].ServiceIndex < commitments[j].ServiceIndex
	})

	// Create blobs in order
	blobs := make([][]byte, 0, len(commitments))
	for _, commitment := range commitments {
		var buffer bytes.Buffer
		buffer.Write(serializer.EncodeLittleEndian(4, uint64(commitment.ServiceIndex)))
		buffer.Write(serializer.Serialize(commitment.PreimageResult))
		blobs = append(blobs, buffer.Bytes())
	}
	r := merklizer.WellBalancedBinaryMerkle(blobs, keccak256Hash)
	// Get the last MMR from the intermediate blocks (or create empty if none)
	var lastMMR merklizer.MMRRange
	if len(intermediateRecentBlocks) > 0 {
		lastMMR = intermediateRecentBlocks[len(intermediateRecentBlocks)-1].AccumulationResultMMR
	}

	// Append the new root to the MMR
	b := merklizer.Append(lastMMR, &r, keccak256Hash)

	// Create work package hashes map: p = {((gw)s)h ↦ ((gw)s)e | g ∈ EG}
	workPackageHashes := make(map[[32]byte][32]byte)
	for _, guarantee := range guarantees {
		// Calculate the work package hash ((gw)s)h
		workPackageSpecification := guarantee.WorkReport.WorkPackageSpecification
		workPackageHashes[workPackageSpecification.WorkPackageHash] = workPackageSpecification.ErasureRoot
	}

	// Create the new recent block
	newRecentBlock := RecentBlock{
		HeaderHash:            blake2b.Sum256(serializer.Serialize(header)),
		AccumulationResultMMR: b,
		StateRoot:             [32]byte{},
		WorkPackageHashes:     workPackageHashes,
	}
	// Append the new block to the recent blocks list
	updatedRecentBlocks := append(intermediateRecentBlocks, newRecentBlock)

	// Keep only the most recent H blocks
	// β′ ≡ β† n where H is RecentHistorySizeBlocks
	if len(updatedRecentBlocks) > constants.RecentHistorySizeBlocks {
		// Trim the list to keep only the most recent H blocks
		updatedRecentBlocks = updatedRecentBlocks[len(updatedRecentBlocks)-constants.RecentHistorySizeBlocks:]
	}

	return updatedRecentBlocks
}

func computeSafroleBasicState(header header.Header, mostRecentBlockTimeslot types.Timeslot, tickets extrinsics.Tickets, priorSafroleBasicState SafroleBasicState, priorValidatorKeysetsStaging types.ValidatorKeysets, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorDisputes types.Disputes, posteriorEntropyAccumulator [4][32]byte) SafroleBasicState {
	var posteriorValidatorKeysetsPending types.ValidatorKeysets
	var posteriorEpochTicketSubmissionsRoot types.BandersnatchRingRoot
	var posteriorSealingKeySequence sealingkeysequence.SealingKeySequence
	var posteriorTicketAccumulator []ticket.Ticket
	// TODO: verify here if the tickets given are actually ordered by vrf output
	for _, extrinsicTicket := range tickets {
		vrfOutput, err := bandersnatch.BandersnatchRingVRFProofOutput(extrinsicTicket.ValidityProof)
		if err != nil {
			return SafroleBasicState{}
		}
		posteriorTicketAccumulator = append(posteriorTicketAccumulator, ticket.Ticket{
			VerifiablyRandomIdentifier: vrfOutput,
			EntryIndex:                 extrinsicTicket.EntryIndex,
		})
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
		if header.TimeSlot.EpochIndex() == mostRecentBlockTimeslot.EpochIndex()+1 && mostRecentBlockTimeslot.SlotPhaseIndex() >= constants.TicketSubmissionEndingSlotPhaseNumber && len(priorSafroleBasicState.TicketAccumulator) == constants.NumTimeslotsPerEpoch {
			var reorderedTickets [constants.NumTimeslotsPerEpoch]ticket.Ticket
			index := 0
			// outside-in
			for i, j := 0, constants.NumTimeslotsPerEpoch-1; i <= j; i, j = i+1, j-1 {
				if i == j {
					// When both indices meet, assign the middle element only once.
					reorderedTickets[index] = priorSafroleBasicState.TicketAccumulator[i]
					index++
				} else {
					// Assign first the element from the start then from the end.
					reorderedTickets[index] = priorSafroleBasicState.TicketAccumulator[i]
					index++
					reorderedTickets[index] = priorSafroleBasicState.TicketAccumulator[j]
					index++
				}
			}
			posteriorSealingKeySequence = sealingkeysequence.NewSealKeyTicketSeries(reorderedTickets)
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

		for _, priorTicket := range priorSafroleBasicState.TicketAccumulator {
			// if not in new tickets, then add
			alreadyInNewTickets := false
			for _, newTicket := range posteriorTicketAccumulator {
				if priorTicket.VerifiablyRandomIdentifier == newTicket.VerifiablyRandomIdentifier {
					alreadyInNewTickets = true
					break
				}
			}
			if !alreadyInNewTickets {
				posteriorTicketAccumulator = append(posteriorTicketAccumulator, priorTicket)
			}
		}
		sort.Slice(posteriorTicketAccumulator, func(i, j int) bool {
			return bytes.Compare(posteriorTicketAccumulator[i].VerifiablyRandomIdentifier[:], posteriorTicketAccumulator[j].VerifiablyRandomIdentifier[:]) < 0
		})
	}

	return SafroleBasicState{
		ValidatorKeysetsPending:    posteriorValidatorKeysetsPending,
		EpochTicketSubmissionsRoot: posteriorEpochTicketSubmissionsRoot,
		SealingKeySequence:         posteriorSealingKeySequence,
		TicketAccumulator:          posteriorTicketAccumulator[:int(math.Min(float64(len(posteriorTicketAccumulator)), float64(constants.NumTimeslotsPerEpoch)))],
	}
}

// NOTE: This function modifies postAccumulationIntermediateServiceAccounts directly
func computeServiceAccounts(preimages extrinsics.Preimages, posteriorMostRecentBlockTimeslot types.Timeslot, postAccumulationIntermediateServiceAccounts *serviceaccount.ServiceAccounts) {
	for _, preimage := range preimages {
		hashedPreimage := blake2b.Sum256(preimage.Data)
		serviceAccount := (*postAccumulationIntermediateServiceAccounts)[preimage.ServiceIndex]
		if _, exists := serviceAccount.PreimageLookup[hashedPreimage]; exists {
			continue
		}
		if availabilityTimeslots, exists := serviceAccount.PreimageLookupHistoricalStatus[serviceaccount.PreimageLookupHistoricalStatusKey{
			Preimage:   hashedPreimage,
			BlobLength: types.BlobLength(len(preimage.Data)),
		}]; !exists {
			continue
		} else if len(availabilityTimeslots) > 0 {
			continue
		}
		(*postAccumulationIntermediateServiceAccounts)[preimage.ServiceIndex].PreimageLookup[hashedPreimage] = preimage.Data
		(*postAccumulationIntermediateServiceAccounts)[preimage.ServiceIndex].PreimageLookupHistoricalStatus[serviceaccount.PreimageLookupHistoricalStatusKey{
			Preimage:   hashedPreimage,
			BlobLength: types.BlobLength(len(preimage.Data)),
		}] = []types.Timeslot{posteriorMostRecentBlockTimeslot}
	}
}

func computeEntropyAccumulator(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorEntropyAccumulator [4][32]byte) [4][32]byte {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput((header.VRFSignature))
	if err != nil {
		panic(err)
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
	return posteriorEntropyAccumulator
}

func computeValidatorKeysetsActive(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorValidatorKeysetsActive types.ValidatorKeysets, priorSafroleBasicState SafroleBasicState) types.ValidatorKeysets {
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

// destroys priorPendingReports
func computePostJudgementIntermediatePendingReports(disputes extrinsics.Disputes, priorPendingReports [constants.NumCores]*PendingReport) [constants.NumCores]*PendingReport {
	posteriorPendingReports := priorPendingReports // Direct array assignment
	validJudgementsMap := disputes.ToSumOfValidJudgementsMap()
	for c, value := range posteriorPendingReports {
		if value == nil {
			continue
		}
		serializedWorkReport := serializer.Serialize(value.WorkReport)
		workReportHash := blake2b.Sum256(serializedWorkReport)
		if validJudgementsSum, exists := validJudgementsMap[workReportHash]; exists {
			if validJudgementsSum < constants.TwoThirdsNumValidators {
				posteriorPendingReports[c] = nil
			}
		}
	}
	return posteriorPendingReports
}

func computePostGuaranteesExtrinsicIntermediatePendingReports(header header.Header, assurances extrinsics.Assurances, postJudgementIntermediatePendingReports [constants.NumCores]*PendingReport) [constants.NumCores]*PendingReport {
	// Create a copy of the input array
	posteriorPendingReports := postJudgementIntermediatePendingReports

	// Apply the modifications to the copy
	for coreIndex, pendingReport := range posteriorPendingReports {
		if pendingReport == nil {
			continue
		}
		nowAvailable := assurances.AvailabilityContributionsForCoreSupermajority(types.CoreIndex(coreIndex))
		timedOut := int(header.TimeSlot) >= int(pendingReport.Timeslot)+constants.UnavailableWorkTimeoutTimeslots
		if nowAvailable || timedOut {
			posteriorPendingReports[coreIndex] = nil
		}
	}
	return posteriorPendingReports
}

func computePendingReports(guarantees extrinsics.Guarantees, postGuaranteesExtrinsicIntermediatePendingReports [constants.NumCores]*PendingReport, posteriorMostRecentBlockTimeslot types.Timeslot) [constants.NumCores]*PendingReport {
	for coreIndex, value := range postGuaranteesExtrinsicIntermediatePendingReports {
		if value == nil {
			continue
		}
		for _, guarantee := range guarantees {
			if guarantee.WorkReport.CoreIndex == types.CoreIndex(coreIndex) {
				postGuaranteesExtrinsicIntermediatePendingReports[coreIndex] = &PendingReport{
					WorkReport: guarantee.WorkReport,
					Timeslot:   posteriorMostRecentBlockTimeslot,
				}
				break
			}
		}
	}
	return postGuaranteesExtrinsicIntermediatePendingReports
}

func computeAccumulatableWorkReportsAndQueuedExecutionWorkReports(header header.Header, assurances extrinsics.Assurances, postJudgementIntermediatePendingReports [constants.NumCores]*PendingReport, priorAccumulationHistory AccumulationHistory, priorAccumulationQueue [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes) ([]workreport.WorkReport, []workreport.WorkReportWithWorkPackageHashes) {
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
	for coreIndex, pendingReport := range postJudgementIntermediatePendingReports {
		if pendingReport == nil {
			continue
		}
		if !assurances.AvailabilityContributionsForCoreSupermajority(types.CoreIndex(coreIndex)) {
			continue
		}
		workReport := pendingReport.WorkReport
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
	m := int(header.TimeSlot) % constants.NumTimeslotsPerEpoch
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
	priorState *State,
	posteriorMostRecentBlockTimeslot types.Timeslot,
	workReports []workreport.WorkReport,
	queuedExecutionWorkReports []workreport.WorkReportWithWorkPackageHashes,
	posteriorEntropyAccumulator [4][32]byte,
) (pvm.AccumulationStateComponents, map[pvm.BEEFYCommitment]struct{}, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes, AccumulationHistory) {
	gas := max(types.GasValue(constants.TotalAccumulationAllocatedGas), types.GasValue(constants.SingleAccumulationAllocatedGas*constants.NumCores)+priorState.PrivilegedServices.TotalAlwaysAccumulateGas())
	n, o, deferredTransfers, C := pvm.OuterAccumulation(gas, posteriorMostRecentBlockTimeslot, workReports, &pvm.AccumulationStateComponents{
		ServiceAccounts:          priorState.ServiceAccounts,
		UpcomingValidatorKeysets: priorState.ValidatorKeysetsStaging,
		AuthorizersQueue:         priorState.AuthorizerQueue,
		PrivilegedServices:       priorState.PrivilegedServices,
	}, priorState.PrivilegedServices.AlwaysAccumulateServicesWithGas, posteriorEntropyAccumulator)

	var wg sync.WaitGroup
	for serviceIndex := range priorState.ServiceAccounts {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()
			selectedTransfers := pvm.SelectDeferredTransfers(deferredTransfers, sIndex)
			pvm.OnTransfer(priorState.ServiceAccounts, posteriorMostRecentBlockTimeslot, sIndex, selectedTransfers)
		}(serviceIndex)
	}
	wg.Wait()

	// Create a copy of the accumulation history before modifying it
	posteriorAccumulationHistory := priorState.AccumulationHistory
	posteriorAccumulationHistory.ShiftLeft(WorkReportsToWorkPackageHashes(workReports[:n]))

	var posteriorAccumulationQueue [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes

	// Initialize with empty slices
	for i := range constants.NumTimeslotsPerEpoch {
		posteriorAccumulationQueue[i] = make([]workreport.WorkReportWithWorkPackageHashes, 0)
	}

	m := posteriorMostRecentBlockTimeslot.SlotPhaseIndex()
	timeslotDiff := int(posteriorMostRecentBlockTimeslot) - int(priorState.MostRecentBlockTimeslot)

	for i := range constants.NumTimeslotsPerEpoch {
		queueIndex := (m + constants.NumTimeslotsPerEpoch - i) % constants.NumTimeslotsPerEpoch
		if i == 0 {
			posteriorAccumulationQueue[queueIndex] = FilterWorkReportsByWorkPackageHashes(
				queuedExecutionWorkReports,
				posteriorAccumulationHistory[len(posteriorAccumulationHistory)-1])
		} else if i < timeslotDiff {
		} else {
			posteriorAccumulationQueue[queueIndex] = FilterWorkReportsByWorkPackageHashes(priorState.AccumulationQueue[queueIndex], posteriorAccumulationHistory[len(posteriorAccumulationHistory)-1])
		}
	}

	return o, C, posteriorAccumulationQueue, posteriorAccumulationHistory
}

func computeMostRecentBlockTimeslot(blockHeader header.Header) types.Timeslot {
	return blockHeader.TimeSlot
}

// destroys priorDisputes
func computeDisputes(disputesExtrinsic extrinsics.Disputes, priorDisputes types.Disputes) types.Disputes {
	sumOfValidJudgementsMap := disputesExtrinsic.ToSumOfValidJudgementsMap()
	for r, validCount := range sumOfValidJudgementsMap {
		if validCount == constants.NumValidatorSafetyThreshold {
			priorDisputes.WorkReportHashesGood[r] = struct{}{}
		} else if validCount == 0 {
			priorDisputes.WorkReportHashesBad[r] = struct{}{}
		} else if validCount == constants.OneThirdNumValidators {
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

func computeValidatorStatistics(guarantees extrinsics.Guarantees, preimages extrinsics.Preimages, assurances extrinsics.Assurances, tickets extrinsics.Tickets, priorMostRecentBlockTimeslot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorStatistics [2][constants.NumValidators]SingleValidatorStatistics, header header.Header) [2][constants.NumValidators]SingleValidatorStatistics {
	posteriorValidatorStatistics := priorValidatorStatistics
	var a [constants.NumValidators]SingleValidatorStatistics
	if header.TimeSlot.EpochIndex() == priorMostRecentBlockTimeslot.EpochIndex() {
		a = priorValidatorStatistics[0]
	} else {
		posteriorValidatorStatistics[1] = priorValidatorStatistics[0]
	}
	for vIndex, vStats := range a {
		vIndex := types.ValidatorIndex(vIndex)
		vIndexIsBlockAuthor := header.BandersnatchBlockAuthorIndex == vIndex
		posteriorValidatorStatistics[0][vIndex].BlocksProduced = vStats.BlocksProduced
		posteriorValidatorStatistics[0][vIndex].TicketsIntroduced = vStats.TicketsIntroduced
		posteriorValidatorStatistics[0][vIndex].PreimagesIntroduced = vStats.PreimagesIntroduced
		posteriorValidatorStatistics[0][vIndex].OctetsIntroduced = vStats.OctetsIntroduced
		if vIndexIsBlockAuthor {
			posteriorValidatorStatistics[0][vIndex].BlocksProduced++
			posteriorValidatorStatistics[0][vIndex].TicketsIntroduced += uint64(len(tickets))
			posteriorValidatorStatistics[0][vIndex].PreimagesIntroduced += uint64(len(preimages))
			posteriorValidatorStatistics[0][vIndex].OctetsIntroduced += uint64(preimages.TotalDataSize())
		}
		posteriorValidatorStatistics[0][vIndex].ReportsGuaranteed = vStats.ReportsGuaranteed
		r := guarantees.ReporterValidatorKeysets(header.TimeSlot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch)
		if r.ContainsKeyset(posteriorValidatorKeysetsActive[vIndex]) {
			posteriorValidatorStatistics[0][vIndex].ReportsGuaranteed++
		}
		posteriorValidatorStatistics[0][vIndex].AvailabilityAssurances = vStats.AvailabilityAssurances
		if assurances.HasValidatorIndex(vIndex) {
			posteriorValidatorStatistics[0][vIndex].AvailabilityAssurances++
		}
	}
	return posteriorValidatorStatistics
}
