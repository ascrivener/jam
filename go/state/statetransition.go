package state

import (
	"bytes"
	"encoding/binary"
	"math"
	"sort"
	"sync"

	"github.com/ascrivener/jam/bandersnatch"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/sealingkeysequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

// runComputation launches a computation concurrently and records the first error encountered.
func runComputation(wg *sync.WaitGroup, setError func(error), fn func() error) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := fn(); err != nil {
			setError(err)
		}
	}()
}

// StateTransitionFunction computes the new state given a state state and a valid block.
// Each field in the new state is computed concurrently. Each compute function returns the
// "posterior" value (the new field) and an optional error.
func StateTransitionFunction(priorState State, block block.Block) (State, error) {
	var posteriorState State

	var wg sync.WaitGroup
	// var mu sync.Mutex
	var transitionError error

	// setError safely records the first error encountered.
	// setError := func(err error) {
	// 	mu.Lock()
	// 	if transitionError == nil {
	// 		transitionError = err
	// 	}
	// 	mu.Unlock()
	// }

	// runComputation(&wg, setError, func() error {
	// 	var err error
	// 	posteriorState.ValidatorKeysetsPriorEpoch, err = computeValidatorKeysetsPriorEpoch(block.Header, priorState.ValidatorKeysetsPriorEpoch, priorState.ValidatorKeysetsActive)
	// 	return err
	// })

	// if posteriorState.MostRecentBlockTimeslot, transitionError = computeMostRecentBlockTimeslot(block.Header); transitionError != nil {
	// 	return State{}, transitionError
	// }

	// if posteriorState.ValidatorKeysetsActive, transitionError = computeValidatorKeysetsActive(block.Header, priorState.ValidatorKeysetsActive, priorState.SafroleBasicState); transitionError != nil {
	// 	return State{}, transitionError
	// }

	// runComputation(&wg, setError, func() error {
	// 	var err error
	// 	if posteriorState.EntropyAccumulator, err = computeEntropyAccumulator(block.Header,  priorState.EntropyAccumulator); err != nil {
	// 		return err
	// 	}
	// 	return nil
	// })

	wg.Wait()

	if transitionError != nil {
		return State{}, transitionError
	}

	return posteriorState, nil
}

// Now, update each compute function to return (result, error).

func computeAuthorizersPool(header header.Header, guarantees extrinsics.Guarantees, posteriorAuthorizerQueue [constants.NumCores][constants.AuthorizerQueueLength][32]byte, priorAuthorizersPool [constants.NumCores][][32]byte) ([constants.NumCores][][32]byte, error) {
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
	return posteriorAuthorizersPool, nil
}

func computeIntermediateRecentBlocks(header header.Header, priorRecentBlocks []RecentBlock) ([]RecentBlock, error) {
	posteriorRecentBlocks := priorRecentBlocks
	posteriorRecentBlocks[len(priorRecentBlocks)-1].StateRoot = header.PriorStateRoot
	// TODO: implement
	return posteriorRecentBlocks, nil
}

func computeRecentBlocks(header header.Header, guarantees extrinsics.Guarantees, intermediateRecentBlocks []RecentBlock, C struct{}) {

}

func computeSafroleBasicState(header header.Header, mostRecentBlockTimeslot types.Timeslot, tickets extrinsics.Tickets, priorSafroleBasicState SafroleBasicState, priorValidatorKeysetsStaging types.ValidatorKeysets, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorDisputes types.Disputes, posteriorEntropyAccumulator [4][32]byte) (SafroleBasicState, error) {
	var err error
	var posteriorValidatorKeysetsPending types.ValidatorKeysets
	var posteriorEpochTicketSubmissionsRoot types.BandersnatchRingRoot
	var posteriorSealingKeySequence sealingkeysequence.SealingKeySequence
	var posteriorTicketAccumulator []ticket.Ticket
	// TODO: verify here if the tickets given are actually ordered by vrf output
	for _, extrinsicTicket := range tickets {
		vrfOutput, err := bandersnatch.BandersnatchRingVRFProofOutput(extrinsicTicket.ValidityProof)
		if err != nil {
			return SafroleBasicState{}, err
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
		if posteriorEpochTicketSubmissionsRoot, err = bandersnatch.BandersnatchRingRoot(posteriorBandersnatchPublicKeysPending[:]); err != nil {
			return SafroleBasicState{}, nil
		}

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
			for i := 0; i < constants.NumTimeslotsPerEpoch; i++ {
				iSerialized, err := serializer.Serialize(uint32(i))
				if err != nil {
					return SafroleBasicState{}, err
				}
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
	}, nil
}

// destroys postAccumulationIntermediateServiceAccounts
func computeServiceAccounts(preimages extrinsics.Preimages, posteriorMostRecentBlockTimeslot types.Timeslot, postAccumulationIntermediateServiceAccounts ServiceAccounts) (ServiceAccounts, error) {
	for _, preimage := range preimages {
		hashedPreimage := blake2b.Sum256(preimage.Data)
		serviceAccount := postAccumulationIntermediateServiceAccounts[preimage.ServiceIndex]
		if _, exists := serviceAccount.PreimageLookup[hashedPreimage]; exists {
			continue
		}
		if availabilityTimeslots, exists := serviceAccount.PreimageLookupHistoricalStatus[PreimageLookupHistoricalStatusKey{
			Preimage:   hashedPreimage,
			BlobLength: types.BlobLength(len(preimage.Data)),
		}]; !exists {
			continue
		} else if len(availabilityTimeslots) > 0 {
			continue
		}
		postAccumulationIntermediateServiceAccounts[preimage.ServiceIndex].PreimageLookup[hashedPreimage] = preimage.Data
		postAccumulationIntermediateServiceAccounts[preimage.ServiceIndex].PreimageLookupHistoricalStatus[PreimageLookupHistoricalStatusKey{
			Preimage:   hashedPreimage,
			BlobLength: types.BlobLength(len(preimage.Data)),
		}] = []types.Timeslot{posteriorMostRecentBlockTimeslot}
	}
	return postAccumulationIntermediateServiceAccounts, nil
}

func computeEntropyAccumulator(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorEntropyAccumulator [4][32]byte) ([4][32]byte, error) {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput((header.VRFSignature))
	if err != nil {
		return [4][32]byte{}, err
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

func computeValidatorKeysetsStaging() (types.ValidatorKeysets, error) {
	// TODO: Implement your logic.
	return types.ValidatorKeysets{}, nil
}

func computeValidatorKeysetsActive(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorValidatorKeysetsActive types.ValidatorKeysets, priorSafroleBasicState SafroleBasicState) (types.ValidatorKeysets, error) {
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		return priorSafroleBasicState.ValidatorKeysetsPending, nil
	}
	return priorValidatorKeysetsActive, nil
}

func computeValidatorKeysetsPriorEpoch(header header.Header, mostRecentBlockTimeslot types.Timeslot, priorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorKeysetsActive types.ValidatorKeysets) (types.ValidatorKeysets, error) {
	if header.TimeSlot.EpochIndex() > mostRecentBlockTimeslot.EpochIndex() {
		return priorValidatorKeysetsActive, nil
	}
	return priorValidatorKeysetsPriorEpoch, nil
}

// destroys priorPendingReports
func computePostJudgementIntermediatePendingReports(disputes extrinsics.Disputes, priorPendingReports [constants.NumCores]*PendingReport) ([constants.NumCores]*PendingReport, error) {
	validJudgementsMap := disputes.ToSumOfValidJudgementsMap()
	for c, value := range priorPendingReports {
		if value == nil {
			continue
		}
		serializedWorkReport, err := serializer.Serialize(value.WorkReport)
		if err != nil {
			return [constants.NumCores]*PendingReport{}, err
		}
		workReportHash := blake2b.Sum256(serializedWorkReport)
		if validJudgementsSum, exists := validJudgementsMap[workReportHash]; exists {
			if validJudgementsSum < constants.TwoThirdsNumValidators {
				priorPendingReports[c] = nil
			}
		}
	}

	return priorPendingReports, nil
}

// destroys postJudgementIntermediatePendingReports
func computePostGuaranteesExtrinsicIntermediatePendingReports(header header.Header, assurances extrinsics.Assurances, postJudgementIntermediatePendingReports [constants.NumCores]*PendingReport) ([constants.NumCores]*PendingReport, error) {
	// reusing this elsewhere?
	for coreIndex, pendingReport := range postJudgementIntermediatePendingReports {
		if pendingReport == nil {
			continue
		}
		nowAvailable := assurances.AvailabilityContributionsForCoreSupermajority(types.CoreIndex(coreIndex))
		timedOut := int(header.TimeSlot) >= int(pendingReport.Timeslot)+constants.UnavailableWorkTimeoutTimeslots
		if nowAvailable || timedOut {
			postJudgementIntermediatePendingReports[coreIndex] = nil
		}
	}
	return postJudgementIntermediatePendingReports, nil
}

func computePendingReports(guarantees extrinsics.Guarantees, postGuaranteesExtrinsicIntermediatePendingReports [constants.NumCores]*PendingReport, priorValidatorKeysetsActive types.ValidatorKeysets, posteriorMostRecentBlockTimeslot types.Timeslot) ([constants.NumCores]*PendingReport, error) {
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
	return postGuaranteesExtrinsicIntermediatePendingReports, nil
}

func computeAccumulatableWorkReports(header header.Header, assurances extrinsics.Assurances, postJudgementIntermediatePendingReports [constants.NumCores]*PendingReport, priorAccumulationHistory AccumulationHistory, priorAccumulationQueue [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes) []workreport.WorkReport {
	// 1. function utils
	queueEdit := func(r []workreport.WorkReportWithWorkPackageHashes, accumulatedWorkPackageHashes map[[32]byte]struct{}) []workreport.WorkReportWithWorkPackageHashes {
		updatedWorkReports := make([]workreport.WorkReportWithWorkPackageHashes, 0)
		for _, w := range r {
			workReport := w.WorkReport
			if _, exists := accumulatedWorkPackageHashes[workReport.WorkPackageSpecification.WorkPackageHash]; exists {
				continue
			}
			workPackageHashes := make(map[[32]byte]struct{})
			for workPackageHash, _ := range w.WorkPackageHashes {
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
	workReportsToWorkPackageHashes := func(workReports []workreport.WorkReport) map[[32]byte]struct{} {
		workPackageHashes := make(map[[32]byte]struct{})
		for _, workReport := range workReports {
			workPackageHashes[workReport.WorkPackageSpecification.WorkPackageHash] = struct{}{}
		}
		return workPackageHashes
	}
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
		return append(g, accumulationPriorityQueue(queueEdit(r, workReportsToWorkPackageHashes(g)))...)
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
			for workPackageHash, _ := range workReport.RefinementContext.PrerequisiteWorkPackageHashes {
				workPackageHashes[workPackageHash] = struct{}{}
			}
			for workPackageHash, _ := range workReport.SegmentRootLookup {
				workPackageHashes[workPackageHash] = struct{}{}
			}
			queuedExecutionWorkReports = append(queuedExecutionWorkReports, workreport.WorkReportWithWorkPackageHashes{
				WorkReport:        workReport,
				WorkPackageHashes: workPackageHashes,
			})
		}
	}
	queuedExecutionWorkReports = queueEdit(queuedExecutionWorkReports, priorAccumulationHistory.ToUnionSet())

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
	q := queueEdit(append(flattenedAfterM, append(flattenedBeforeM, queuedExecutionWorkReports...)...), workReportsToWorkPackageHashes(immediatelyAccumulatableWorkReports))
	return append(immediatelyAccumulatableWorkReports, accumulationPriorityQueue(q)...)
	// wtf did i just do^
}

func computeMostRecentBlockTimeslot(blockHeader header.Header) (types.Timeslot, error) {
	return blockHeader.TimeSlot, nil
}

func computeAuthorizerQueue() ([constants.NumCores][constants.AuthorizerQueueLength][32]byte, error) {
	// TODO: Implement your logic.
	return [constants.NumCores][constants.AuthorizerQueueLength][32]byte{}, nil
}

func computePrivilegedServices() (struct {
	ManagerServiceIndex             types.ServiceIndex
	AssignServiceIndex              types.ServiceIndex
	DesignateServiceIndex           types.ServiceIndex
	AlwaysAccumulateServicesWithGas map[types.ServiceIndex]types.GasValue
}, error) {
	// TODO: Implement your logic.
	return struct {
		ManagerServiceIndex             types.ServiceIndex
		AssignServiceIndex              types.ServiceIndex
		DesignateServiceIndex           types.ServiceIndex
		AlwaysAccumulateServicesWithGas map[types.ServiceIndex]types.GasValue
	}{}, nil
}

// destroys priorDisputes
func computeDisputes(disputesExtrinsic extrinsics.Disputes, priorDisputes types.Disputes) (types.Disputes, error) {
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
	return priorDisputes, nil
}

func computeValidatorStatistics(guarantees extrinsics.Guarantees, preimages extrinsics.Preimages, assurances extrinsics.Assurances, tickets extrinsics.Tickets, priorMostRecentBlockTimeslot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, priorValidatorStatistics [2][constants.NumValidators]SingleValidatorStatistics, header header.Header) ([2][constants.NumValidators]SingleValidatorStatistics, error) {
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
	return posteriorValidatorStatistics, nil
}

func computeAccumulationQueue() ([constants.NumTimeslotsPerEpoch][]struct {
	WorkReport        workreport.WorkReport
	WorkPackageHashes map[[32]byte]struct{}
}, error) {
	// TODO: Implement your logic.
	return [constants.NumTimeslotsPerEpoch][]struct {
		WorkReport        workreport.WorkReport
		WorkPackageHashes map[[32]byte]struct{}
	}{}, nil
}

func computeAccumulationHistory() ([constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}, error) {
	// TODO: Implement your logic.
	return [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}{}, nil
}
