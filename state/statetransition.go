package state

import (
	"sync"

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

	if posteriorState.MostRecentBlockTimeslot, transitionError = computeMostRecentBlockTimeslot(block.Header); transitionError != nil {
		return State{}, transitionError
	}

	runComputation(&wg, setError, func() error {
		var err error
		if posteriorState.EntropyAccumulator, err = computeEntropyAccumulator(block.Header, priorState.EntropyAccumulator); err != nil {
			return err
		}
		if posteriorState.SafroleBasicState, err = computeSafroleBasicState(); err != nil {
			return err
		}
		return nil
	})

	runComputation(&wg, setError, func() error {
		var err error
		accumulationCommitmentMap := make(map[struct {
			ServiceIndex       types.ServiceIndex
			AccumulationOutput [32]byte
		}]struct{}) // 12.21
		posteriorState.RecentBlocks, err = computeRecentBlocks(block.Header, block.Extrinsics.Guarantees, priorState.RecentBlocks, accumulationCommitmentMap)
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		accumulationCommitmentMap := make(map[struct {
			ServiceIndex       types.ServiceIndex
			AccumulationOutput [32]byte
		}]struct{}) // 12.21
		posteriorState.RecentBlocks, err = computeRecentBlocks(block.Header, block.Extrinsics.Guarantees, priorState.RecentBlocks, accumulationCommitmentMap)
		return err
	})

	// Compute each field concurrently.
	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.AuthorizersPool, err = computeAuthorizersPool()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.PriorServiceAccountState, err = computePriorServiceAccountState()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.ValidatorKeysetsStaging, err = computeValidatorKeysetsStaging()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.ValidatorKeysetsActive, err = computeValidatorKeysetsActive()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.ValidatorKeysetsPriorEpoch, err = computeValidatorKeysetsPriorEpoch()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.PendingReports, err = computePendingReports()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.AuthorizerQueue, err = computeAuthorizerQueue()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.Disputes, err = computeDisputes()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.PrivilegedServices, err = computePrivilegedServices()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.ValidatorStatistics, err = computeValidatorStatistics()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.AccumulationQueue, err = computeAccumulationQueue()
		return err
	})

	runComputation(&wg, setError, func() error {
		var err error
		posteriorState.AccumulationHistory, err = computeAccumulationHistory()
		return err
	})

	wg.Wait()

	if transitionError != nil {
		return State{}, transitionError
	}

	return posteriorState, nil
}

// Now, update each compute function to return (result, error).

func computeMostRecentBlockTimeslot(blockHeader header.Header) (types.Timeslot, error) {
	return blockHeader.TimeSlot, nil
}

func computeAuthorizersPool() ([constants.NumCores][][32]byte, error) {
	// TODO: Implement your logic.
	return [constants.NumCores][][32]byte{}, nil
}

func computeRecentBlocks(blockHeader header.Header, guarantees extrinsics.Guarantees, priorRecentBlocks []RecentBlock, accumulationCommitmentMap map[struct {
	ServiceIndex       types.ServiceIndex
	AccumulationOutput [32]byte
}]struct{}) ([]RecentBlock, error) {
	// TODO: implement
	return []RecentBlock{}, nil
}

func computeSafroleBasicState() (SafroleBasicState, error) {
	// TODO: Implement your logic.
	return SafroleBasicState{}, nil
}

func computePriorServiceAccountState() (map[types.ServiceIndex]ServiceAccount, error) {
	// TODO: Implement your logic.
	return map[types.ServiceIndex]ServiceAccount{}, nil
}

func computeEntropyAccumulator(blockHeader header.Header, entropyAccumulator [4][32]byte) ([4][32]byte, error) {
	posteriorEntropyAccumulator := [4][32]byte{}
	randomVRFOutput := blake2b.Sum256(blockHeader.VRFSignature[:])
	posteriorEntropyAccumulator[0] = blake2b.Sum256(append(entropyAccumulator[0][:], randomVRFOutput[:]...))
	if blockHeader.TimeSlot%constants.NumTimeslotsPerEpoch == 0 { // new epoch
		posteriorEntropyAccumulator[1] = entropyAccumulator[0]
		posteriorEntropyAccumulator[2] = entropyAccumulator[1]
		posteriorEntropyAccumulator[3] = entropyAccumulator[2]
	} else {
		posteriorEntropyAccumulator[1] = entropyAccumulator[1]
		posteriorEntropyAccumulator[2] = entropyAccumulator[2]
		posteriorEntropyAccumulator[3] = entropyAccumulator[3]
	}
	return posteriorEntropyAccumulator, nil
}

func computeValidatorKeysetsStaging() ([constants.NumValidators]types.ValidatorKeyset, error) {
	// TODO: Implement your logic.
	return [constants.NumValidators]types.ValidatorKeyset{}, nil
}

func computeValidatorKeysetsActive() ([constants.NumValidators]types.ValidatorKeyset, error) {
	// TODO: Implement your logic.
	return [constants.NumValidators]types.ValidatorKeyset{}, nil
}

func computeValidatorKeysetsPriorEpoch() ([constants.NumValidators]types.ValidatorKeyset, error) {
	// TODO: Implement your logic.
	return [constants.NumValidators]types.ValidatorKeyset{}, nil
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

func computeAuthorizerQueue() ([constants.NumCores][constants.AuthorizerQueueLength][32]byte, error) {
	// TODO: Implement your logic.
	return [constants.NumCores][constants.AuthorizerQueueLength][32]byte{}, nil
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
