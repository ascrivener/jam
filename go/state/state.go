package state

import (
	"bytes"
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/validatorstatistics"
	"github.com/ascrivener/jam/workreport"
	"github.com/cockroachdb/pebble"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                                               // α
	RecentBlocks               []RecentBlock                                                                // β
	SafroleBasicState          SafroleBasicState                                                            // γ
	ServiceAccounts            serviceaccount.ServiceAccounts                                               // δ
	EntropyAccumulator         [4][32]byte                                                                  // η
	ValidatorKeysetsStaging    types.ValidatorKeysets                                                       // ι
	ValidatorKeysetsActive     types.ValidatorKeysets                                                       // κ
	ValidatorKeysetsPriorEpoch types.ValidatorKeysets                                                       // λ
	PendingReports             [constants.NumCores]*PendingReport                                           // ρ
	MostRecentBlockTimeslot    types.Timeslot                                                               // τ
	AuthorizerQueue            [constants.NumCores][constants.AuthorizerQueueLength][32]byte                // φ
	PrivilegedServices         types.PrivilegedServices                                                     // χ
	Disputes                   types.Disputes                                                               // ψ
	ValidatorStatistics        validatorstatistics.ValidatorStatistics                                      // π
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes // ϑ
	AccumulationHistory        AccumulationHistory                                                          // ξ
}

type PendingReport struct {
	WorkReport workreport.WorkReport
	Timeslot   types.Timeslot
}

type AccumulationHistory [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}

func (a AccumulationHistory) ToUnionSet() map[[32]byte]struct{} {
	set := make(map[[32]byte]struct{})
	for _, accumulationSet := range a {
		for key := range accumulationSet {
			set[key] = struct{}{}
		}
	}
	return set
}

// ShiftLeft shifts all elements so that a[i] = a[i+1] and fills the last element with the provided map.
// If newLast is nil, an empty map will be created.
func (a *AccumulationHistory) ShiftLeft(newLast map[[32]byte]struct{}) {
	for i := range (*a)[:len(*a)-1] {
		(*a)[i] = (*a)[i+1]
	}

	// Set the last element to the provided map or create an empty one
	if newLast == nil {
		(*a)[len(*a)-1] = make(map[[32]byte]struct{})
	} else {
		(*a)[len(*a)-1] = newLast
	}
}

func GetState(repo staterepository.PebbleStateRepository) (State, error) {
	state := State{
		ServiceAccounts: make(map[types.ServiceIndex]*serviceaccount.ServiceAccount),
	}

	// Deserialize static state components
	components := []struct {
		key    [31]byte
		target interface{}
	}{
		{staterepository.MakeComponentKey(1), &state.AuthorizersPool},
		{staterepository.MakeComponentKey(2), &state.AuthorizerQueue},
		{staterepository.MakeComponentKey(3), &state.RecentBlocks},
		{staterepository.MakeComponentKey(4), &state.SafroleBasicState},
		{staterepository.MakeComponentKey(5), &state.Disputes},
		{staterepository.MakeComponentKey(6), &state.EntropyAccumulator},
		{staterepository.MakeComponentKey(7), &state.ValidatorKeysetsStaging},
		{staterepository.MakeComponentKey(8), &state.ValidatorKeysetsActive},
		{staterepository.MakeComponentKey(9), &state.ValidatorKeysetsPriorEpoch},
		{staterepository.MakeComponentKey(10), &state.PendingReports},
		{staterepository.MakeComponentKey(11), &state.MostRecentBlockTimeslot},
		{staterepository.MakeComponentKey(12), &state.PrivilegedServices},
		{staterepository.MakeComponentKey(13), &state.ValidatorStatistics},
		{staterepository.MakeComponentKey(14), &state.AccumulationQueue},
		{staterepository.MakeComponentKey(15), &state.AccumulationHistory},
	}

	// Deserialize each basic component
	for _, component := range components {
		prefixedKey := append([]byte("state:"), component.key[:]...)
		value, closer, err := repo.Get(prefixedKey)
		if err != nil {
			return State{}, fmt.Errorf("failed to get component: %w", err)
		}

		// Make a copy of the value since it's only valid until closer.Close()
		dataCopy := make([]byte, len(value))
		copy(dataCopy, value)
		closer.Close()

		if err := serializer.Deserialize(dataCopy, component.target); err != nil {
			return State{}, fmt.Errorf("failed to deserialize component: %w", err)
		}
	}

	// Load service accounts (just metadata, not storage)
	if err := state.loadServiceAccounts(repo); err != nil {
		return State{}, err
	}

	return state, nil
}

// loadServiceAccounts loads all service account metadata (not storage)
func (state *State) loadServiceAccounts(repo staterepository.PebbleStateRepository) error {
	// Service accounts have keys starting with state: prefix and 255
	serviceAccountPrefix := append([]byte("state:"), 255)
	iter, err := repo.NewIter(&pebble.IterOptions{
		LowerBound: serviceAccountPrefix,
		UpperBound: append(append([]byte{}, serviceAccountPrefix...), 0xFF),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()

		// Make sure key starts with our prefix
		if len(key) < 7 || !bytes.HasPrefix(key, serviceAccountPrefix) {
			continue
		}

		// Skip the prefix for pattern checking (after "state:" + 255 byte)
		unprefixedKey := key[len(serviceAccountPrefix):]

		// Check the pattern [n_0, 0, n_1, 0, n_2, 0, n_3, 0, 0...]
		// Only proceed if the zero bytes are in the right places
		if len(unprefixedKey) < 8 || unprefixedKey[1] != 0 || unprefixedKey[3] != 0 || unprefixedKey[5] != 0 || unprefixedKey[7] != 0 {
			continue
		}

		// Check that all remaining bytes are zeros
		validKey := true
		for i := 8; i < len(unprefixedKey); i++ {
			if unprefixedKey[i] != 0 {
				validKey = false
				break
			}
		}

		if !validKey {
			continue
		}

		// Extract service index from key using little endian [n0,n1,n2,n3]
		serviceIndex := uint64(unprefixedKey[0]) |
			uint64(unprefixedKey[2])<<8 |
			uint64(unprefixedKey[4])<<16 |
			uint64(unprefixedKey[6])<<24

		// Copy the value since it's only valid until iter is closed
		value := make([]byte, len(iter.Value()))
		copy(value, iter.Value())

		var serviceAccountData struct {
			CodeHash                 [32]byte       // c
			Balance                  types.Balance  // b
			MinimumGasForAccumulate  types.GasValue // g
			MinimumGasForOnTransfer  types.GasValue // m
			TotalOctetsUsedInStorage uint64         // o
			TotalItemsUsedInStorage  uint32         // i
		}

		// Deserialize account
		if err := serializer.Deserialize(value, &serviceAccountData); err != nil {
			return fmt.Errorf("failed to deserialize service account %d: %w", serviceIndex, err)
		}

		// Add to state
		state.ServiceAccounts[types.ServiceIndex(serviceIndex)] = &serviceaccount.ServiceAccount{
			ServiceIndex:             types.ServiceIndex(serviceIndex),
			CodeHash:                 serviceAccountData.CodeHash,
			Balance:                  serviceAccountData.Balance,
			MinimumGasForAccumulate:  serviceAccountData.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:  serviceAccountData.MinimumGasForOnTransfer,
			TotalOctetsUsedInStorage: serviceAccountData.TotalOctetsUsedInStorage,
			TotalItemsUsedInStorage:  serviceAccountData.TotalItemsUsedInStorage,
		}
	}

	return nil
}

// SetState stores the entire blockchain state
func (state *State) Set(repo staterepository.PebbleStateRepository) error {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Store static state components
	components := []struct {
		key    [31]byte
		source interface{}
	}{
		{staterepository.MakeComponentKey(1), state.AuthorizersPool},
		{staterepository.MakeComponentKey(2), state.AuthorizerQueue},
		{staterepository.MakeComponentKey(3), state.RecentBlocks},
		{staterepository.MakeComponentKey(4), state.SafroleBasicState},
		{staterepository.MakeComponentKey(5), state.Disputes},
		{staterepository.MakeComponentKey(6), state.EntropyAccumulator},
		{staterepository.MakeComponentKey(7), state.ValidatorKeysetsStaging},
		{staterepository.MakeComponentKey(8), state.ValidatorKeysetsActive},
		{staterepository.MakeComponentKey(9), state.ValidatorKeysetsPriorEpoch},
		{staterepository.MakeComponentKey(10), state.PendingReports},
		{staterepository.MakeComponentKey(11), state.MostRecentBlockTimeslot},
		{staterepository.MakeComponentKey(12), state.PrivilegedServices},
		{staterepository.MakeComponentKey(13), state.ValidatorStatistics},
		{staterepository.MakeComponentKey(14), state.AccumulationQueue},
		{staterepository.MakeComponentKey(15), state.AccumulationHistory},
	}

	// Serialize and store each basic component
	for _, component := range components {
		data := serializer.Serialize(component.source)
		// Add state: prefix to component key
		prefixedKey := append([]byte("state:"), component.key[:]...)
		if err := batch.Set(prefixedKey, data, nil); err != nil {
			return fmt.Errorf("failed to store component: %w", err)
		}
	}

	// Store service accounts
	for serviceIndex, account := range state.ServiceAccounts {
		// Create the raw key
		rawKey := staterepository.StateKeyConstructor(255, serviceIndex)

		// Add state: prefix
		prefixedKey := append([]byte("state:"), rawKey[:]...)

		var serviceAccountData = struct {
			CodeHash                 [32]byte       // c
			Balance                  types.Balance  // b
			MinimumGasForAccumulate  types.GasValue // g
			MinimumGasForOnTransfer  types.GasValue // m
			TotalOctetsUsedInStorage uint64         // o
			TotalItemsUsedInStorage  uint32         // i
		}{
			CodeHash:                 account.CodeHash,
			Balance:                  account.Balance,
			MinimumGasForAccumulate:  account.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:  account.MinimumGasForOnTransfer,
			TotalOctetsUsedInStorage: account.TotalOctetsUsedInStorage,
			TotalItemsUsedInStorage:  account.TotalItemsUsedInStorage,
		}
		data := serializer.Serialize(serviceAccountData)
		if err := batch.Set(prefixedKey, data, nil); err != nil {
			return fmt.Errorf("failed to store service account %d: %w", serviceIndex, err)
		}
	}

	// If we created our own batch, commit it
	if ownBatch {
		return batch.Commit(pebble.Sync)
	}

	return nil
}
