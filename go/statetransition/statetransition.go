package statetransition

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/validatorstatistics"
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

func LoadStateAndRunSTF(repo staterepository.PebbleStateRepository, block block.Block) error {
	// Begin a transaction for all repository operations
	if err := repo.BeginTransaction(); err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Declare err variable for use in the defer function
	var err error

	// Defer a function that either commits or rolls back based on error status
	defer func() {
		if err != nil {
			repo.RollbackTransaction()
		} else {
			err = repo.CommitTransaction()
		}
	}()

	// Load state
	state, err := state.GetState(repo)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Run state transition function
	postState, err := StateTransitionFunction(repo, state, block)
	if err != nil {
		return fmt.Errorf("failed to run state transition function: %w", err)
	}

	// TODO: detect service account deletion and handle (??)
	// Save state
	if err := postState.Set(repo); err != nil {
		return fmt.Errorf("failed to save state: %w", err)
	}

	return nil
}

// StateTransitionFunction computes the new state given a state state and a valid block.
// Each field in the new state is computed concurrently. Each compute function returns the
// "posterior" value (the new field) and an optional error.
func StateTransitionFunction(repo staterepository.PebbleStateRepository, priorState state.State, block block.Block) (state.State, error) {
	// Verify block
	if err := block.Verify(repo); err != nil {
		return state.State{}, fmt.Errorf("failed to verify block: %w", err)
	}

	posteriorMostRecentBlockTimeslot := computeMostRecentBlockTimeslot(block.Header)

	intermediateRecentBlocks := computeIntermediateRecentBlocks(block.Header, priorState.RecentBlocks)

	posteriorEntropyAccumulator := computeEntropyAccumulator(block.Header, priorState.MostRecentBlockTimeslot, priorState.EntropyAccumulator)

	posteriorValidatorKeysetsActive := computeValidatorKeysetsActive(block.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsActive, priorState.SafroleBasicState)

	posteriorDisputes := computeDisputes(block.Extrinsics.Disputes, priorState.Disputes)

	posteriorSafroleBasicState := computeSafroleBasicState(block.Header, priorState.MostRecentBlockTimeslot, block.Extrinsics.Tickets, priorState.SafroleBasicState, priorState.ValidatorKeysetsStaging, posteriorValidatorKeysetsActive, posteriorDisputes, posteriorEntropyAccumulator)

	posteriorValidatorKeysetsPriorEpoch := computeValidatorKeysetsPriorEpoch(block.Header, priorState.MostRecentBlockTimeslot, priorState.ValidatorKeysetsPriorEpoch, priorState.ValidatorKeysetsActive)

	postJudgementIntermediatePendingReports := computePostJudgementIntermediatePendingReports(block.Extrinsics.Disputes, priorState.PendingReports)

	availableReports := computeAvailableReports(postJudgementIntermediatePendingReports, block.Extrinsics.Assurances)

	accumulatableWorkReports, queuedExecutionWorkReports := computeAccumulatableWorkReportsAndQueuedExecutionWorkReports(block.Header, block.Extrinsics.Assurances, availableReports, priorState.AccumulationHistory, priorState.AccumulationQueue)

	accumulationStateComponents, BEEFYCommitments, posteriorAccumulationQueue, posteriorAccumulationHistory, deferredTransferStatistics, accumulationStatistics := accumulateAndIntegrate(
		repo,
		&priorState,
		posteriorMostRecentBlockTimeslot,
		accumulatableWorkReports,
		queuedExecutionWorkReports,
		posteriorEntropyAccumulator,
	)

	postguaranteesExtrinsicIntermediatePendingReports := computePostGuaranteesExtrinsicIntermediatePendingReports(block.Header, block.Extrinsics.Assurances, postJudgementIntermediatePendingReports)

	posteriorPendingReports := computePendingReports(block.Extrinsics.Guarantees, postguaranteesExtrinsicIntermediatePendingReports, posteriorMostRecentBlockTimeslot)

	posteriorRecentBlocks := computeRecentBlocks(block.Header, block.Extrinsics.Guarantees, priorState.RecentBlocks, intermediateRecentBlocks, BEEFYCommitments)

	postAccumulationIntermediateServiceAccounts := accumulationStateComponents.ServiceAccounts
	computeServiceAccounts(repo, block.Extrinsics.Preimages, posteriorMostRecentBlockTimeslot, &postAccumulationIntermediateServiceAccounts)

	authorizersPool := computeAuthorizersPool(block.Header, block.Extrinsics.Guarantees, priorState.AuthorizerQueue, priorState.AuthorizersPool)

	validatorStatistics := computeValidatorStatistics(block.Extrinsics.Guarantees, block.Extrinsics.Preimages, block.Extrinsics.Assurances, block.Extrinsics.Tickets, priorState.MostRecentBlockTimeslot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch, priorState.ValidatorStatistics, block.Header, availableReports, deferredTransferStatistics, accumulationStatistics)

	return state.State{
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
	}, nil
}

func computeAvailableReports(pendingReports [constants.NumCores]*state.PendingReport, assurances extrinsics.Assurances) []workreport.WorkReport {
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
	return availableReports
}

// Now, update each compute function to return (result, error).

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

func keccak256Hash(data []byte) [32]byte {
	var result [32]byte
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	sum := hash.Sum(nil)
	copy(result[:], sum[:])
	return result
}

func computeRecentBlocks(header header.Header, guarantees extrinsics.Guarantees, priorRecentBlocks []state.RecentBlock, intermediateRecentBlocks []state.RecentBlock, C map[pvm.BEEFYCommitment]struct{}) []state.RecentBlock {
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
		buffer.Write(serializer.Serialize(commitment.ServiceIndex))
		buffer.Write(serializer.Serialize(commitment.PreimageResult))
		blobs = append(blobs, buffer.Bytes())
	}
	r := merklizer.WellBalancedBinaryMerkle(blobs, keccak256Hash)
	// Get the last MMR from the intermediate blocks (or create empty if none)
	lastMMR := merklizer.MMRRange{}
	if len(priorRecentBlocks) > 0 {
		lastMMR = priorRecentBlocks[len(priorRecentBlocks)-1].AccumulationResultMMR.DeepCopy()
	}

	// Append the new root to the MMR
	b := merklizer.Append(lastMMR, r, keccak256Hash)

	// Create work package hashes map: p = {((gw)s)h ↦ ((gw)s)e | g ∈ EG}
	workPackageHashes := make(map[[32]byte][32]byte)
	for _, guarantee := range guarantees {
		// Calculate the work package hash ((gw)s)h
		workPackageSpecification := guarantee.WorkReport.WorkPackageSpecification
		workPackageHashes[workPackageSpecification.WorkPackageHash] = workPackageSpecification.SegmentRoot
	}

	// Create the new recent block
	newRecentBlock := state.RecentBlock{
		HeaderHash:            blake2b.Sum256(serializer.Serialize(header)),
		AccumulationResultMMR: b,
		StateRoot:             [32]byte{},
		WorkPackageHashes:     workPackageHashes,
	}
	// Append the new block to the recent blocks list
	updatedRecentBlocks := append(intermediateRecentBlocks, newRecentBlock)

	// Keep only the most recent H blocks
	// β′ ≡ β† n where H is RecentHistorySizeBlocks
	if len(updatedRecentBlocks) > int(constants.RecentHistorySizeBlocks) {
		// Trim the list to keep only the most recent H blocks
		updatedRecentBlocks = updatedRecentBlocks[len(updatedRecentBlocks)-int(constants.RecentHistorySizeBlocks):]
	}

	return updatedRecentBlocks
}

func computeSafroleBasicState(header header.Header, mostRecentBlockTimeslot types.Timeslot, tickets extrinsics.Tickets, priorSafroleBasicState state.SafroleBasicState, priorValidatorKeysetsStaging types.ValidatorKeysets, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorDisputes types.Disputes, posteriorEntropyAccumulator [4][32]byte) state.SafroleBasicState {
	var posteriorValidatorKeysetsPending types.ValidatorKeysets
	var posteriorEpochTicketSubmissionsRoot types.BandersnatchRingRoot
	var posteriorSealingKeySequence sealingkeysequence.SealingKeySequence
	posteriorTicketAccumulator := make([]ticket.Ticket, 0)
	// TODO: verify here if the tickets given are actually ordered by vrf output
	for _, extrinsicTicket := range tickets {
		vrfOutput, err := bandersnatch.BandersnatchRingVRFProofOutput(extrinsicTicket.ValidityProof)
		if err != nil {
			return state.SafroleBasicState{}
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
		if header.TimeSlot.EpochIndex() == mostRecentBlockTimeslot.EpochIndex()+1 && mostRecentBlockTimeslot.SlotPhaseIndex() >= int(constants.TicketSubmissionEndingSlotPhaseNumber) && len(priorSafroleBasicState.TicketAccumulator) == int(constants.NumTimeslotsPerEpoch) {
			var reorderedTickets [constants.NumTimeslotsPerEpoch]ticket.Ticket
			index := 0
			// outside-in
			for i, j := 0, int(constants.NumTimeslotsPerEpoch)-1; i <= j; i, j = i+1, j-1 {
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

	return state.SafroleBasicState{
		ValidatorKeysetsPending:    posteriorValidatorKeysetsPending,
		EpochTicketSubmissionsRoot: posteriorEpochTicketSubmissionsRoot,
		SealingKeySequence:         posteriorSealingKeySequence,
		TicketAccumulator:          posteriorTicketAccumulator[:int(math.Min(float64(len(posteriorTicketAccumulator)), float64(constants.NumTimeslotsPerEpoch)))],
	}
}

// NOTE: This function modifies postAccumulationIntermediateServiceAccounts directly
func computeServiceAccounts(repo staterepository.PebbleStateRepository, preimages extrinsics.Preimages, posteriorMostRecentBlockTimeslot types.Timeslot, postAccumulationIntermediateServiceAccounts *serviceaccount.ServiceAccounts) {
	for _, preimage := range preimages {
		hash := blake2b.Sum256(preimage.Data)
		serviceAccount := (*postAccumulationIntermediateServiceAccounts)[preimage.ServiceIndex]
		if _, exists := serviceAccount.GetPreimageForHash(repo, hash); exists {
			continue
		}
		if availabilityTimeslots, exists := serviceAccount.GetPreimageLookupHistoricalStatus(repo, uint32(len(preimage.Data)), hash); !exists {
			continue
		} else if len(availabilityTimeslots) > 0 {
			continue
		}
		serviceAccount.SetPreimageForHash(repo, hash, preimage.Data)
		serviceAccount.SetPreimageLookupHistoricalStatus(repo, uint32(len(preimage.Data)), hash, []types.Timeslot{posteriorMostRecentBlockTimeslot})
	}
}

func computeEntropyAccumulator(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorEntropyAccumulator [4][32]byte) [4][32]byte {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput(header.VRFSignature)
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
	repo staterepository.PebbleStateRepository,
	priorState *state.State,
	posteriorMostRecentBlockTimeslot types.Timeslot,
	accumulatableWorkReports []workreport.WorkReport,
	queuedExecutionWorkReports []workreport.WorkReportWithWorkPackageHashes,
	posteriorEntropyAccumulator [4][32]byte,
) (pvm.AccumulationStateComponents, map[pvm.BEEFYCommitment]struct{}, [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes, state.AccumulationHistory, validatorstatistics.TransferStatistics, validatorstatistics.AccumulationStatistics) {
	gas := max(types.GasValue(constants.AllAccumulationTotalGasAllocation), types.GasValue(constants.SingleAccumulationAllocatedGas*uint64(constants.NumCores))+priorState.PrivilegedServices.TotalAlwaysAccumulateGas())
	n, o, deferredTransfers, C, serviceGasUsage := pvm.OuterAccumulation(repo, gas, posteriorMostRecentBlockTimeslot, accumulatableWorkReports, &pvm.AccumulationStateComponents{
		ServiceAccounts:          priorState.ServiceAccounts,
		UpcomingValidatorKeysets: priorState.ValidatorKeysetsStaging,
		AuthorizersQueue:         priorState.AuthorizerQueue,
		PrivilegedServices:       priorState.PrivilegedServices,
	}, priorState.PrivilegedServices.AlwaysAccumulateServicesWithGas, posteriorEntropyAccumulator)

	var accumulationStatistics = validatorstatistics.AccumulationStatistics{}
	for serviceIndex := range o.ServiceAccounts {
		N := make([]workreport.WorkDigest, 0)
		for _, workReport := range accumulatableWorkReports[:n] {
			for _, workDigest := range workReport.WorkDigests {
				if workDigest.ServiceIndex == serviceIndex {
					N = append(N, workDigest)
				}
			}
		}
		if len(N) > 0 {
			var gasUsed types.GasValue
			for _, serviceAndGasUsage := range serviceGasUsage {
				if serviceAndGasUsage.ServiceIndex != serviceIndex {
					continue
				}
				gasUsed += serviceAndGasUsage.GasUsed
			}
			accumulationStatistics[serviceIndex] = validatorstatistics.ServiceAccumulationStatistics{
				NumberOfWorkItems: types.GenericNum(len(N)),
				GasUsed:           types.GenericGasValue(gasUsed),
			}
		}
	}

	var wg sync.WaitGroup
	var deferredTransferStatistics = validatorstatistics.TransferStatistics{}
	var mutex sync.Mutex // Add mutex to protect map access

	for serviceIndex := range o.ServiceAccounts {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()
			selectedTransfers := pvm.SelectDeferredTransfers(deferredTransfers, sIndex)
			_, gasUsed := pvm.OnTransfer(repo, o.ServiceAccounts, posteriorMostRecentBlockTimeslot, sIndex, posteriorEntropyAccumulator, selectedTransfers)
			if len(selectedTransfers) > 0 {
				mutex.Lock() // Lock before writing to the map
				deferredTransferStatistics[sIndex] = validatorstatistics.ServiceTransferStatistics{
					NumberOfTransfers: types.GenericNum(len(selectedTransfers)),
					GasUsed:           types.GenericGasValue(gasUsed),
				}
				mutex.Unlock() // Don't forget to unlock
			}
		}(serviceIndex)
	}
	wg.Wait()

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

	return o, C, posteriorAccumulationQueue, posteriorAccumulationHistory, deferredTransferStatistics, accumulationStatistics
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

func computeValidatorStatistics(guarantees extrinsics.Guarantees, preimages extrinsics.Preimages, assurances extrinsics.Assurances, tickets extrinsics.Tickets, priorMostRecentBlockTimeslot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorStatistics validatorstatistics.ValidatorStatistics, header header.Header, availableReports []workreport.WorkReport, deferredTransferStatistics validatorstatistics.TransferStatistics, accumulationStatistics validatorstatistics.AccumulationStatistics) validatorstatistics.ValidatorStatistics {
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
		r := guarantees.ReporterValidatorKeysets(header.TimeSlot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch)
		if r.ContainsKeyset(posteriorValidatorKeysetsActive[vIndex]) {
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
				coreStats.ActualRefinementGasUsed += types.GenericGasValue(digest.ActualRefinementGasUsed)
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
		trackedServiceIndices[preimage.ServiceIndex] = struct{}{}
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
					serviceStatistics.ActualRefinementGasUsed.Amount += types.GenericGasValue(workDigest.ActualRefinementGasUsed)
				}
			}
		}
		for _, preimage := range preimages {
			if preimage.ServiceIndex == serviceIndex {
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
