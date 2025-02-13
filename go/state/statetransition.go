package state

import (
	"sync"

	"github.com/ascrivener/jam/bandersnatch"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
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
	var mu sync.Mutex
	var transitionError error

	// setError safely records the first error encountered.
	setError := func(err error) {
		mu.Lock()
		if transitionError == nil {
			transitionError = err
		}
		mu.Unlock()
	}

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.ValidatorKeysetsPriorEpoch, err = computeValidatorKeysetsPriorEpoch(block.Header, priorState.ValidatorKeysetsPriorEpoch, priorState.ValidatorKeysetsActive)
		return err
	})

	if posteriorState.MostRecentBlockTimeslot, transitionError = computeMostRecentBlockTimeslot(block.Header); transitionError != nil {
		return State{}, transitionError
	}

	if posteriorState.ValidatorKeysetsActive, transitionError = computeValidatorKeysetsActive(block.Header, priorState.ValidatorKeysetsActive, priorState.SafroleBasicState); transitionError != nil {
		return State{}, transitionError
	}

	runComputation(&wg, setError, func() error {
		var err error
		if posteriorState.EntropyAccumulator, err = computeEntropyAccumulator(block.Header, priorState.EntropyAccumulator); err != nil {
			return err
		}
		return nil
	})

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

func computeSafroleBasicState(header header.Header, tickets extrinsics.Tickets, priorSafroleBasicState SafroleBasicState, priorValidatorKeysetsStaging [constants.NumValidators]types.ValidatorKeyset, priorValidatorKeysetsActive [constants.NumValidators]types.ValidatorKeyset, posteriorDisputes Disputes) (SafroleBasicState, error) {
	var posteriorValidatorKeysetsPending [constants.NumValidators]types.ValidatorKeyset
	var posteriorEpochTicketSubmissionsRoot types.BandersnatchRingRoot
	if header.TimeSlot%constants.NumTimeslotsPerEpoch == 0 {
		// posteriorValidatorKeysetsPending
		for index, _ := range posteriorValidatorKeysetsPending {
			if posteriorDisputes.PunishEd25519Key(priorValidatorKeysetsStaging[index].ToEd25519PublicKey()) {
				posteriorValidatorKeysetsPending[index] = [336]byte{}
			} else {
				posteriorValidatorKeysetsPending[index] = priorValidatorKeysetsStaging[index]
			}
		}

		// posteriorEpochTicketSubmissionsRoot
		var posteriorBandersnatchPublicKeysPending [constants.NumValidators]types.BandersnatchPublicKey
		for index, keyset := range posteriorValidatorKeysetsPending {
			posteriorBandersnatchPublicKeysPending[index] = keyset.ToBandersnatchPublicKey()
		}
		posteriorEpochTicketSubmissionsRoot = BandersnatchRingRoot(posteriorBandersnatchPublicKeysPending)
	} else {
		posteriorValidatorKeysetsPending = priorSafroleBasicState.ValidatorKeysetsPending

		posteriorEpochTicketSubmissionsRoot = priorSafroleBasicState.EpochTicketSubmissionsRoot
	}
	return SafroleBasicState{
		ValidatorKeysetsPending:    posteriorValidatorKeysetsPending,
		EpochTicketSubmissionsRoot: posteriorEpochTicketSubmissionsRoot,
	}, nil
}

func computePriorServiceAccountState() (map[types.ServiceIndex]ServiceAccount, error) {
	// TODO: Implement your logic.
	return map[types.ServiceIndex]ServiceAccount{}, nil
}

func computeEntropyAccumulator(header header.Header, priorEntropyAccumulator [4][32]byte) ([4][32]byte, error) {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput, err := bandersnatch.VRFOutput((header.VRFSignature[:]))
	if err != nil {
		return [4][32]byte{}, err
	}
	posteriorEntropyAccumulator[0] = blake2b.Sum256(append(priorEntropyAccumulator[0][:], randomVRFOutput[:]...))
	if header.TimeSlot%constants.NumTimeslotsPerEpoch == 0 { // new epoch
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

func computeValidatorKeysetsStaging() ([constants.NumValidators]types.ValidatorKeyset, error) {
	// TODO: Implement your logic.
	return [constants.NumValidators]types.ValidatorKeyset{}, nil
}

func computeValidatorKeysetsActive(header header.Header, priorValidatorKeysetsActive [constants.NumValidators]types.ValidatorKeyset, priorSafroleBasicState SafroleBasicState) ([constants.NumValidators]types.ValidatorKeyset, error) {
	if header.TimeSlot%constants.NumTimeslotsPerEpoch == 0 {
		return priorSafroleBasicState.ValidatorKeysetsPending, nil
	}
	return priorValidatorKeysetsActive, nil
}

func computeValidatorKeysetsPriorEpoch(header header.Header, priorValidatorKeysetsPriorEpoch [constants.NumValidators]types.ValidatorKeyset, priorValidatorKeysetsActive [constants.NumValidators]types.ValidatorKeyset) ([constants.NumValidators]types.ValidatorKeyset, error) {
	if header.TimeSlot%constants.NumTimeslotsPerEpoch == 0 {
		return priorValidatorKeysetsActive, nil
	}
	return priorValidatorKeysetsPriorEpoch, nil
}

func computePendingReports() ([constants.NumCores]*struct {
	WorkReport workreport.WorkReport
	Timeslot   types.Timeslot
}, error) {
	// TODO: Implement your logic.
	return [constants.NumCores]*struct {
		WorkReport workreport.WorkReport
		Timeslot   types.Timeslot
	}{}, nil
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

func computeDisputes() (struct {
	WorkReportHashesGood  [][32]byte
	WorkReportHashesBad   [][32]byte
	WorkReportHashesWonky [][32]byte
	ValidatorPunishes     []types.Ed25519PublicKey
}, error) {
	// TODO: Implement your logic.
	return struct {
		WorkReportHashesGood  [][32]byte
		WorkReportHashesBad   [][32]byte
		WorkReportHashesWonky [][32]byte
		ValidatorPunishes     []types.Ed25519PublicKey
	}{}, nil
}

func computeValidatorStatistics() ([2][constants.NumValidators]struct {
	BlocksProduced         uint64
	TicketsIntroduced      uint64
	PreimagesIntroduced    uint64
	OctetsIntroduced       uint64
	ReportsGuaranteed      uint64
	AvailabilityAssurances uint64
}, error) {
	// TODO: Implement your logic.
	return [2][constants.NumValidators]struct {
		BlocksProduced         uint64
		TicketsIntroduced      uint64
		PreimagesIntroduced    uint64
		OctetsIntroduced       uint64
		ReportsGuaranteed      uint64
		AvailabilityAssurances uint64
	}{}, nil
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
