package block

import (
	"bytes"
	"fmt"
	"time"

	"maps"

	"github.com/ascrivener/jam/bandersnatch"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

type Block struct {
	Header     header.Header
	Extrinsics extrinsics.Extrinsics
}

func (b Block) Verify(repo staterepository.PebbleStateRepository, priorState state.State) error {

	parentBlock, err := Get(repo, b.Header.ParentHash)
	// (5.2) implicitly, there is no block whose header hash is equal to b.Header.ParentHash
	if err != nil {
		return fmt.Errorf("failed to get parent block: %w", err)
	}

	// (5.4)
	if b.Header.ExtrinsicHash != b.Extrinsics.MerkleCommitment() {
		return fmt.Errorf("extrinsic hash does not match actual extrinsic hash")
	}

	// (5.7)
	if b.Header.TimeSlot <= parentBlock.Block.Header.TimeSlot {
		return fmt.Errorf("time slot is not greater than parent block time slot")
	}

	if b.Header.TimeSlot*types.Timeslot(constants.SlotPeriodInSeconds) > types.Timeslot(time.Now().Unix()-constants.JamCommonEraStartUnixTime) {
		return fmt.Errorf("block timestamp is in the future relative to current time")
	}

	// (5.8)
	merklizedState := merklizer.MerklizeState(repo)

	if parentBlock.Info.PosteriorStateRoot != merklizedState {
		return fmt.Errorf("parent block state root does not match merklized state")
	}

	// (10.7)
	for i := 1; i < len(b.Extrinsics.Disputes.Verdicts); i++ {
		comparison := bytes.Compare(b.Extrinsics.Disputes.Verdicts[i].WorkReportHash[:],
			b.Extrinsics.Disputes.Verdicts[i-1].WorkReportHash[:])
		if comparison <= 0 {
			return fmt.Errorf("verdicts must be strictly ordered by WorkReportHash")
		}
		// (10.10)
		for j := 1; j < len(b.Extrinsics.Disputes.Verdicts[i].Judgements); j++ {
			if b.Extrinsics.Disputes.Verdicts[i].Judgements[j].ValidatorIndex <= b.Extrinsics.Disputes.Verdicts[i].Judgements[j-1].ValidatorIndex {
				return fmt.Errorf("judgements must be strictly ordered by ValidatorIndex")
			}
		}
	}

	// (10.8)
	for i := 1; i < len(b.Extrinsics.Disputes.Culprits); i++ {
		comparison := bytes.Compare(b.Extrinsics.Disputes.Culprits[i].ValidatorKey[:],
			b.Extrinsics.Disputes.Culprits[i-1].ValidatorKey[:])
		if comparison <= 0 {
			return fmt.Errorf("culprits must be strictly ordered by ValidatorKey")
		}
	}

	for i := 1; i < len(b.Extrinsics.Disputes.Faults); i++ {
		comparison := bytes.Compare(b.Extrinsics.Disputes.Faults[i].ValidatorKey[:],
			b.Extrinsics.Disputes.Faults[i-1].ValidatorKey[:])
		if comparison <= 0 {
			return fmt.Errorf("faults must be strictly ordered by ValidatorKey")
		}
	}

	for _, verdict := range b.Extrinsics.Disputes.Verdicts {
		// (10.9)
		if _, ok := priorState.Disputes.WorkReportHashesGood[verdict.WorkReportHash]; ok {
			return fmt.Errorf("work report hash %x is already in good disputes", verdict.WorkReportHash)
		}
		if _, ok := priorState.Disputes.WorkReportHashesBad[verdict.WorkReportHash]; ok {
			return fmt.Errorf("work report hash %x is already in bad disputes", verdict.WorkReportHash)
		}
		if _, ok := priorState.Disputes.WorkReportHashesWonky[verdict.WorkReportHash]; ok {
			return fmt.Errorf("work report hash %x is already in wonky disputes", verdict.WorkReportHash)
		}
		// (10.3)
		var validatorKeysets types.ValidatorKeysets
		if verdict.EpochIndex == uint32(priorState.MostRecentBlockTimeslot.EpochIndex()) {
			validatorKeysets = priorState.ValidatorKeysetsActive
		} else if verdict.EpochIndex == uint32(priorState.MostRecentBlockTimeslot.EpochIndex()-1) {
			validatorKeysets = priorState.ValidatorKeysetsPriorEpoch
		} else { // (10.2)
			return fmt.Errorf("verdict epoch index does not match prior state most recent block timeslot epoch index or previous")
		}
		for _, judgement := range verdict.Judgements {
			key := validatorKeysets[judgement.ValidatorIndex].ToEd25519PublicKey()
			var message []byte
			if judgement.Valid {
				message = append(message, []byte("jam_valid")...)
			} else {
				message = append(message, []byte("jam_invalid")...)
			}
			message = append(message, verdict.WorkReportHash[:]...)
			if !ed25519.Verify(key[:], message, judgement.Signature[:]) {
				return fmt.Errorf("invalid signature from validator %d", judgement.ValidatorIndex)
			}
		}
	}

	for verdict, positiveJudgments := range b.Extrinsics.Disputes.ToSumOfValidJudgementsMap() {
		// (10.13)
		if positiveJudgments == int(constants.NumValidatorSafetyThreshold) {
			foundCorrespondingFault := false
			for _, fault := range b.Extrinsics.Disputes.Faults {
				if fault.WorkReportHash == verdict {
					foundCorrespondingFault = true
					break
				}
			}
			if !foundCorrespondingFault {
				return fmt.Errorf("no corresponding fault for verdict %x", verdict)
			}
		} else if positiveJudgments == 0 {
			culpritCount := 0
			for _, culprit := range b.Extrinsics.Disputes.Culprits {
				if culprit.InvalidWorkReportHash == verdict {
					culpritCount++
				}
			}
			if culpritCount < 2 {
				return fmt.Errorf("culprit count for verdict %x is less than 2: %d", verdict, culpritCount)
			}
		} else if positiveJudgments == int(constants.OneThirdNumValidators) {
		} else { // (10.11)
			return fmt.Errorf("sum of valid judgements for verdict %x is invalid: %d", verdict, positiveJudgments)
		}
	}

	// (10.20)
	concatCulpritAndFaultKeys := make([]types.Ed25519PublicKey, 0)
	for _, culprit := range b.Extrinsics.Disputes.Culprits {
		concatCulpritAndFaultKeys = append(concatCulpritAndFaultKeys, culprit.ValidatorKey)
	}
	for _, fault := range b.Extrinsics.Disputes.Faults {
		concatCulpritAndFaultKeys = append(concatCulpritAndFaultKeys, fault.ValidatorKey)
	}
	for index, key := range b.Header.UnsignedHeader.OffendersMarker {
		if key != concatCulpritAndFaultKeys[index] {
			return fmt.Errorf("offender key %d does not match expected key", index)
		}
	}

	for _, guarantee := range b.Extrinsics.Guarantees {
		workReport := guarantee.WorkReport
		// (11.2)
		if len(workReport.WorkDigests) == 0 {
			return fmt.Errorf("work report has no work digests")
		}
		if len(workReport.WorkDigests) > int(constants.MaxWorkItemsInPackage) {
			return fmt.Errorf("work report has too many work digests")
		}
		// (11.3)
		if len(workReport.SegmentRootLookup)+len(workReport.RefinementContext.PrerequisiteWorkPackageHashes) > int(constants.MaxSumDependencyItemsInReport) {
			return fmt.Errorf("sum of segment root lookup and prerequisite work package hashes is greater than max sum dependency items in report")
		}

		// (11.8)
		totalOutputBlobSize := 0
		for _, workDigest := range workReport.WorkDigests {
			workResult := workDigest.WorkResult
			if workResult.IsError() {
				continue
			}
			totalOutputBlobSize += len(*workResult.Blob)
		}
		if totalOutputBlobSize+len(workReport.Output) > int(constants.MaxTotalSizeWorkReportBlobs) {
			return fmt.Errorf("total output blob size is greater than max total size work report blobs")
		}
	}

	// (11.10)
	if len(b.Extrinsics.Assurances) > int(constants.NumValidators) {
		return fmt.Errorf("too many assurances. Expected at most %d, got %d", constants.NumValidators, len(b.Extrinsics.Assurances))
	}

	for idx, assurance := range b.Extrinsics.Assurances {
		// (11.11)
		if assurance.ParentHash != b.Header.ParentHash {
			return fmt.Errorf("assurance parent hash does not match block parent hash: %x != %x", assurance.ParentHash, b.Header.ParentHash)
		}
		// (11.12)
		if idx > 0 {
			if b.Extrinsics.Assurances[idx-1].ValidatorIndex >= assurance.ValidatorIndex {
				return fmt.Errorf("assurance validator index is not strictly ordered: %d >= %d", b.Extrinsics.Assurances[idx-1].ValidatorIndex, assurance.ValidatorIndex)
			}
		}
		// (11.13)
		messageHash := blake2b.Sum256(append(b.Header.ParentHash[:], serializer.Serialize(assurance.CoreAvailabilityContributions)...))
		message := append([]byte("jam_available"), messageHash[:]...)
		key := priorState.ValidatorKeysetsActive[assurance.ValidatorIndex].ToEd25519PublicKey()
		if !ed25519.Verify(key[:], message, assurance.Signature[:]) {
			return fmt.Errorf("invalid signature from validator %d", assurance.ValidatorIndex)
		}
	}

	// (11.23)
	if len(b.Extrinsics.Guarantees) > int(constants.NumCores) {
		return fmt.Errorf("too many assurances. Expected at most %d, got %d", constants.NumCores, len(b.Extrinsics.Guarantees))
	}

	for i := 1; i < len(b.Extrinsics.Guarantees); i++ {
		if b.Extrinsics.Guarantees[i].WorkReport.CoreIndex <= b.Extrinsics.Guarantees[i-1].WorkReport.CoreIndex {
			return fmt.Errorf("guarantees must be strictly ordered by CoreIndex")
		}
	}

	for _, guarantee := range b.Extrinsics.Guarantees {
		for i := 1; i < len(guarantee.Credentials); i++ {
			if guarantee.Credentials[i].ValidatorIndex <= guarantee.Credentials[i-1].ValidatorIndex {
				return fmt.Errorf("credentials must be strictly ordered by ValidatorIndex")
			}
		}

		// (11.30)
		totalAccumulateGasLimit := types.GasValue(0)
		for _, workDigest := range guarantee.WorkReport.WorkDigests {
			totalAccumulateGasLimit += workDigest.AccumulateGasLimit
			if workDigest.AccumulateGasLimit < priorState.ServiceAccounts[workDigest.ServiceIndex].MinimumGasForAccumulate {
				return fmt.Errorf("accumulate gas limit %d less than minimum gas for accumulate %d", workDigest.AccumulateGasLimit, priorState.ServiceAccounts[workDigest.ServiceIndex].MinimumGasForAccumulate)
			}
		}
		if totalAccumulateGasLimit > types.GasValue(constants.SingleAccumulationAllocatedGas) {
			return fmt.Errorf("total accumulate gas limit %d greater than single accumulation allocated gas %d", totalAccumulateGasLimit, constants.SingleAccumulationAllocatedGas)
		}
	}

	// (11.32)
	if len(b.Extrinsics.Guarantees.WorkPackageHashes()) != len(b.Extrinsics.Guarantees) {
		return fmt.Errorf("number of work package hashes does not match number of guarantees")
	}

	for _, refinementContext := range b.Extrinsics.Guarantees.RefinementContexts() {
		// (11.34)
		var minAcceptableTimeslot types.Timeslot
		if priorState.MostRecentBlockTimeslot >= types.Timeslot(constants.LookupAnchorMaxAgeTimeslots) {
			minAcceptableTimeslot = priorState.MostRecentBlockTimeslot - types.Timeslot(constants.LookupAnchorMaxAgeTimeslots)
		} else {
			minAcceptableTimeslot = 0
		}
		if refinementContext.Timeslot < minAcceptableTimeslot {
			return fmt.Errorf("refinement context timeslot is too old")
		}

		anchorBlock, err := GetAnchorBlock(repo, b.Header, refinementContext.AnchorHeaderHash)
		if err != nil {
			return fmt.Errorf("failed to get anchor block: %w", err)
		}
		if anchorBlock.Block.Header.TimeSlot != refinementContext.Timeslot {
			return fmt.Errorf("refinement context timeslot does not match anchor block timeslot")
		}
	}

	// (11.38)
	existingWorkPackageHashes := make(map[[32]byte]struct{})
	for _, q := range priorState.AccumulationQueue {
		for _, wr := range q {
			for wph := range wr.WorkReport.RefinementContext.PrerequisiteWorkPackageHashes {
				existingWorkPackageHashes[wph] = struct{}{}
			}
		}
	}

	for _, pendingReport := range priorState.PendingReports {
		if pendingReport == nil {
			continue
		}
		for wph := range pendingReport.WorkReport.RefinementContext.PrerequisiteWorkPackageHashes {
			existingWorkPackageHashes[wph] = struct{}{}
		}
	}

	for _, recentBlock := range priorState.RecentBlocks {
		for wph := range recentBlock.WorkPackageHashes {
			existingWorkPackageHashes[wph] = struct{}{}
		}
	}

	for wph := range priorState.AccumulationHistory.ToUnionSet() {
		existingWorkPackageHashes[wph] = struct{}{}
	}

	for wph := range b.Extrinsics.Guarantees.WorkPackageHashes() {
		if _, ok := existingWorkPackageHashes[wph]; ok {
			return fmt.Errorf("work package hash %x already exists", wph)
		}
	}

	// (11.39)
	recentBlockWorkPackageHashes := make(map[[32]byte]struct{})
	for _, recentBlock := range priorState.RecentBlocks {
		for _, wph := range recentBlock.WorkPackageHashes {
			recentBlockWorkPackageHashes[wph] = struct{}{}
		}
	}
	for _, guarantee := range b.Extrinsics.Guarantees {
		wphs := make(map[[32]byte]struct{})
		for wph := range guarantee.WorkReport.RefinementContext.PrerequisiteWorkPackageHashes {
			wphs[wph] = struct{}{}
		}
		for wph := range guarantee.WorkReport.SegmentRootLookup {
			wphs[wph] = struct{}{}
		}
		for wph := range wphs {
			if _, ok := b.Extrinsics.Guarantees.WorkPackageHashes()[wph]; ok {
				continue
			}
			if _, ok := recentBlockWorkPackageHashes[wph]; ok {
				continue
			}
			return fmt.Errorf("work package hash %x does not exist in extrinsic or recent history", wph)
		}
	}

	// (11.41)
	correctSegmentRootLookup := make(map[[32]byte][32]byte)
	for _, guarantee := range b.Extrinsics.Guarantees {
		correctSegmentRootLookup[guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash] = guarantee.WorkReport.WorkPackageSpecification.SegmentRoot
	}
	for _, recentBlock := range priorState.RecentBlocks {
		maps.Copy(correctSegmentRootLookup, recentBlock.WorkPackageHashes)
	}
	for _, guarantee := range b.Extrinsics.Guarantees {
		for key, value := range guarantee.WorkReport.SegmentRootLookup {
			if _, ok := correctSegmentRootLookup[key]; !ok {
				return fmt.Errorf("segment root %x does not exist in recent history", key)
			}
			if correctSegmentRootLookup[key] != value {
				return fmt.Errorf("segment root %x does not match recent history", key)
			}
		}
	}

	// (11.42)
	for _, guarantee := range b.Extrinsics.Guarantees {
		for _, workDigest := range guarantee.WorkReport.WorkDigests {
			if workDigest.ServiceCodeHash != priorState.ServiceAccounts[workDigest.ServiceIndex].CodeHash {
				return fmt.Errorf("service code hash %x does not match service account code hash %x", workDigest.ServiceCodeHash, priorState.ServiceAccounts[workDigest.ServiceIndex].CodeHash)
			}
		}
	}

	// (12.36)
	for i := 1; i < len(b.Extrinsics.Preimages); i++ {
		// First check if ordered by ServiceIndex
		if b.Extrinsics.Preimages[i].ServiceIndex < b.Extrinsics.Preimages[i-1].ServiceIndex {
			return fmt.Errorf("preimages must be ordered by ServiceIndex")
		}

		// If ServiceIndex is equal, check that Data is lexicographically greater
		if b.Extrinsics.Preimages[i].ServiceIndex == b.Extrinsics.Preimages[i-1].ServiceIndex {
			// Compare Data bytes lexicographically
			result := bytes.Compare(b.Extrinsics.Preimages[i].Data, b.Extrinsics.Preimages[i-1].Data)
			if result <= 0 {
				return fmt.Errorf("preimages must be strictly ordered lexicographically when ServiceIndex is equal")
			}
		}
	}

	// (12.38)
	for _, preimage := range b.Extrinsics.Preimages {
		hash := blake2b.Sum256(preimage.Data)
		if !priorState.ServiceAccounts.IsNewPreimage(repo, types.ServiceIndex(preimage.ServiceIndex), hash, types.BlobLength(len(preimage.Data))) {
			return fmt.Errorf("preimage %x already exists", hash)
		}
	}
	return nil
}

func (b Block) VerifyPostStateTransition(priorState state.State, postState state.State) error {
	// Calculate time slot position within epoch (shared between both verification paths)
	slotIndexInEpoch := b.Header.TimeSlot % types.Timeslot(constants.NumTimeslotsPerEpoch)
	authorKey := postState.ValidatorKeysetsActive[b.Header.BandersnatchBlockAuthorIndex].ToBandersnatchPublicKey()
	actualVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput(b.Header.BlockSeal)

	if postState.SafroleBasicState.SealingKeySequence.IsSealKeyTickets() {
		// (6.15)
		// Verify block seal matches the expected ticket's VRF output
		expectedTicket := postState.SafroleBasicState.SealingKeySequence.SealKeyTickets[slotIndexInEpoch]
		if err != nil {
			return fmt.Errorf("failed to extract VRF output from block seal: %w", err)
		}

		if expectedTicket.VerifiablyRandomIdentifier != actualVRFOutput {
			return fmt.Errorf("block seal VRF output does not match the expected ticket's identifier in sealing key sequence")
		}

		verified, err := bandersnatch.VerifySignature(authorKey, append(append([]byte("jam_ticket_seal"), postState.EntropyAccumulator[3][:]...), byte(expectedTicket.EntryIndex)), serializer.Serialize(b.Header.UnsignedHeader), b.Header.BlockSeal)
		if err != nil {
			return fmt.Errorf("failed to verify block seal: %w", err)
		}
		if !verified {
			return fmt.Errorf("block seal verification failed")
		}
	} else {
		// (6.16)
		// Verify block author matches the expected Bandersnatch key
		expectedKey := postState.SafroleBasicState.SealingKeySequence.BandersnatchKeys[slotIndexInEpoch]

		if expectedKey != authorKey {
			return fmt.Errorf("block author's Bandersnatch key does not match the expected key in sealing key sequence")
		}

		verified, err := bandersnatch.VerifySignature(authorKey, append([]byte("jam_fallback_seal"), postState.EntropyAccumulator[3][:]...), serializer.Serialize(b.Header.UnsignedHeader), b.Header.BlockSeal)
		if err != nil {
			return fmt.Errorf("failed to verify block seal: %w", err)
		}
		if !verified {
			return fmt.Errorf("block seal verification failed")
		}
	}

	// (6.17)
	verified, err := bandersnatch.VerifySignature(authorKey, append([]byte("jam_entropy"), actualVRFOutput[:]...), []byte{}, b.Header.VRFSignature)
	if err != nil {
		return fmt.Errorf("failed to verify block VRF signature: %w", err)
	}
	if !verified {
		return fmt.Errorf("block VRF signature verification failed")
	}

	// (6.27)
	if b.Header.TimeSlot.EpochIndex() > priorState.MostRecentBlockTimeslot.EpochIndex() {
		if b.Header.EpochMarker == nil {
			return fmt.Errorf("epoch marker should not be nil")
		}
		if b.Header.EpochMarker.CurrentEpochRandomness != priorState.EntropyAccumulator[0] {
			return fmt.Errorf("epoch marker current epoch randomness does not match post state current epoch randomness")
		}
		if b.Header.EpochMarker.TicketsRandomness != priorState.EntropyAccumulator[1] {
			return fmt.Errorf("epoch marker tickets randomness does not match post state tickets randomness")
		}
		for idx, validatorKey := range b.Header.EpochMarker.ValidatorKeys {
			if validatorKey.BandersnatchPublicKey != postState.ValidatorKeysetsActive[idx].ToBandersnatchPublicKey() {
				return fmt.Errorf("epoch marker validator key does not match post state validator key")
			}
			if validatorKey.Ed25519PublicKey != postState.ValidatorKeysetsActive[idx].ToEd25519PublicKey() {
				return fmt.Errorf("epoch marker validator key does not match post state validator key")
			}
		}
	} else {
		if b.Header.EpochMarker != nil {
			return fmt.Errorf("epoch marker should be nil")
		}
	}
	// (6.28)
	if b.Header.TimeSlot.EpochIndex() == priorState.MostRecentBlockTimeslot.EpochIndex() && uint32(priorState.MostRecentBlockTimeslot.SlotPhaseIndex()) < constants.TicketSubmissionEndingSlotPhaseNumber && uint32(postState.MostRecentBlockTimeslot.SlotPhaseIndex()) >= constants.TicketSubmissionEndingSlotPhaseNumber && uint32(len(priorState.SafroleBasicState.TicketAccumulator)) == constants.NumTimeslotsPerEpoch {
		if b.Header.WinningTicketsMarker == nil {
			return fmt.Errorf("winning tickets marker should not be nil")
		}
		if len(b.Header.WinningTicketsMarker) != len(priorState.SafroleBasicState.TicketAccumulator) {
			return fmt.Errorf("winning tickets marker should have %d tickets", len(priorState.SafroleBasicState.TicketAccumulator))
		}
		for idx, ticket := range ticket.ReorderTicketsOutsideIn(priorState.SafroleBasicState.TicketAccumulator) {
			if ticket.VerifiablyRandomIdentifier != b.Header.WinningTicketsMarker[idx].VerifiablyRandomIdentifier {
				return fmt.Errorf("winning tickets marker ticket does not match post state ticket")
			}
			if ticket.EntryIndex != b.Header.WinningTicketsMarker[idx].EntryIndex {
				return fmt.Errorf("winning tickets marker ticket does not match post state ticket")
			}
		}
	} else {
		if b.Header.WinningTicketsMarker != nil {
			return fmt.Errorf("winning tickets marker should be nil")
		}
	}
	// (6.29)
	for _, ticket := range b.Extrinsics.Tickets {
		if ticket.EntryIndex >= types.GenericNum(constants.NumTicketEntries) {
			return fmt.Errorf("ticket entry index should be less than %d", constants.NumTicketEntries)
		}
		verified, err := bandersnatch.VerifyRingSignature(postState.SafroleBasicState.EpochTicketSubmissionsRoot, append(append([]byte("jam_ticket_seal"), postState.EntropyAccumulator[2][:]...), byte(ticket.EntryIndex)), []byte{}, ticket.ValidityProof)
		if err != nil {
			return fmt.Errorf("failed to verify ticket signature: %w", err)
		}
		if !verified {
			return fmt.Errorf("ticket signature verification failed")
		}
	}
	// (6.30)
	if uint32(postState.MostRecentBlockTimeslot.SlotPhaseIndex()) < constants.TicketSubmissionEndingSlotPhaseNumber {
		if len(b.Extrinsics.Tickets) > int(constants.MaxTicketsPerExtrinsic) {
			return fmt.Errorf("extrinsics should have at most %d tickets", constants.MaxTicketsPerExtrinsic)
		}
	} else {
		if len(b.Extrinsics.Tickets) != 0 {
			return fmt.Errorf("extrinsics should have no tickets")
		}
	}

	reportableKeys := make(map[types.Ed25519PublicKey]struct{})
	for _, keyset := range priorState.ValidatorKeysetsActive {
		reportableKeys[keyset.ToEd25519PublicKey()] = struct{}{}
	}
	for _, keyset := range priorState.ValidatorKeysetsPriorEpoch {
		reportableKeys[keyset.ToEd25519PublicKey()] = struct{}{}
	}
	for key := range reportableKeys {
		if _, ok := priorState.Disputes.ValidatorPunishes[key]; ok {
			delete(reportableKeys, key)
		}
	}
	// (10.5)
	for _, culprit := range b.Extrinsics.Disputes.Culprits {
		if _, ok := postState.Disputes.WorkReportHashesBad[culprit.InvalidWorkReportHash]; !ok {
			return fmt.Errorf("culprit invalid work report hash is not in bad set")
		}
		if _, ok := reportableKeys[culprit.ValidatorKey]; !ok {
			return fmt.Errorf("culprit validator key is not in reportable keyset")
		}
		var message = append([]byte("jam_guarantee"), culprit.InvalidWorkReportHash[:]...)
		if !ed25519.Verify(culprit.ValidatorKey[:], message, culprit.Signature[:]) {
			return fmt.Errorf("invalid signature from validator %d", culprit.ValidatorKey)
		}
	}
	// (10.6)
	for _, fault := range b.Extrinsics.Disputes.Faults {
		_, reportIsBad := postState.Disputes.WorkReportHashesBad[fault.WorkReportHash]
		_, reportIsGood := postState.Disputes.WorkReportHashesGood[fault.WorkReportHash]
		if (reportIsBad == reportIsGood) || (reportIsBad != fault.CorrectValidity) {
			return fmt.Errorf("inconsistent work report hash")
		}
		if _, ok := reportableKeys[fault.ValidatorKey]; !ok {
			return fmt.Errorf("fault validator key is not in reportable keyset")
		}
		var message []byte
		if fault.CorrectValidity {
			message = append(message, []byte("jam_valid")...)
		} else {
			message = append(message, []byte("jam_invalid")...)
		}
		message = append(message, fault.WorkReportHash[:]...)
		if !ed25519.Verify(fault.ValidatorKey[:], message, fault.Signature[:]) {
			return fmt.Errorf("invalid signature from validator %d", fault.ValidatorKey)
		}
	}

	// (11.26)
	for _, guarantee := range b.Extrinsics.Guarantees {
		guarantorAssignments := guarantee.GuarantorAssignments(postState.EntropyAccumulator, postState.MostRecentBlockTimeslot, postState.ValidatorKeysetsActive, postState.ValidatorKeysetsPriorEpoch, postState.Disputes)
		for _, credential := range guarantee.Credentials {
			hashedWorkReport := blake2b.Sum256(serializer.Serialize(guarantee.WorkReport))
			publicKey := guarantorAssignments.ValidatorKeysets[credential.ValidatorIndex].ToEd25519PublicKey()
			if !ed25519.Verify(publicKey[:], append([]byte("jam_guarantee"), hashedWorkReport[:]...), credential.Signature[:]) {
				return fmt.Errorf("invalid signature from validator %d", credential.ValidatorIndex)
			}
			var k uint16
			rotationIndex := uint16(postState.MostRecentBlockTimeslot.CoreAssignmentRotationIndex())
			if rotationIndex > 0 {
				k = constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots * (rotationIndex - 1)
			} else {
				k = 0 // If we're in the first rotation period, accept all guarantees
			}
			if guarantorAssignments.CoreIndices[credential.ValidatorIndex] != types.CoreIndex(guarantee.WorkReport.CoreIndex) {
				return fmt.Errorf("guarantee core index does not match work report core index")
			}
			if k > uint16(guarantee.Timeslot) {
				return fmt.Errorf("guarantee timeslot is too old")
			}
			if guarantee.Timeslot > postState.MostRecentBlockTimeslot {
				return fmt.Errorf("guarantee timeslot is too new")
			}
		}
	}
	return nil
}

type BlockWithInfo struct {
	Block Block
	Info  BlockInfo
}

type BlockInfo struct {
	PosteriorStateRoot [32]byte
}

func Get(repo staterepository.PebbleStateRepository, headerHash [32]byte) (*BlockWithInfo, error) {
	// Create a key with a prefix to separate block data from state data
	key := makeBlockKey(headerHash)

	// Retrieve the serialized block from the repository
	data, closer, err := repo.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get block %x: %w", headerHash, err)
	}
	defer closer.Close()

	// Make a copy of the data since it's only valid until closer.Close()
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	var blockWithInfo BlockWithInfo
	if err := serializer.Deserialize(dataCopy, &blockWithInfo); err != nil {
		return nil, fmt.Errorf("failed to deserialize block %x: %w", headerHash, err)
	}

	return &blockWithInfo, nil
}

func GetAnchorBlock(repo staterepository.PebbleStateRepository, header header.Header, targetAnchorHeaderHash [32]byte) (*BlockWithInfo, error) {
	currentHeaderHash := header.ParentHash
	for {
		// Get the current block
		blockWithInfo, err := Get(repo, currentHeaderHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get block in chain with hash %x: %w", currentHeaderHash, err)
		}

		// Check if the block is too old (more than 24 hours)
		if header.TimeSlot > blockWithInfo.Block.Header.TimeSlot+types.Timeslot(constants.LookupAnchorMaxAgeTimeslots) {
			return nil, fmt.Errorf("anchor block is too old (more than 24 hours before current block)")
		}

		if currentHeaderHash == targetAnchorHeaderHash {
			return blockWithInfo, nil
		}

		currentHeaderHash = blockWithInfo.Block.Header.ParentHash
	}
}

func (block BlockWithInfo) Set(repo staterepository.PebbleStateRepository) error {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Calculate the header hash
	headerBytes := serializer.Serialize(block.Block.Header)
	headerHash := blake2b.Sum256(headerBytes)

	// Create a key with a prefix
	key := makeBlockKey(headerHash)

	// Serialize the block
	data := serializer.Serialize(block)

	// Store the serialized block in the repository
	if err := batch.Set(key, data, nil); err != nil { // Use batch instead of repo
		return fmt.Errorf("failed to store block %x: %w", headerHash, err)
	}

	// Commit the batch if we created it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch: %w", err)
		}
	}

	return nil
}

// Helper functions for key construction
func makeBlockKey(headerHash [32]byte) []byte {
	return append([]byte("block:"), headerHash[:]...)
}
