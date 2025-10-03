package state

import (
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/merklizer"
	"jam/pkg/pvm"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/validatorstatistics"
	"jam/pkg/workreport"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte
	RecentActivity             RecentActivity
	SafroleBasicState          SafroleBasicState
	EntropyAccumulator         [4][32]byte
	ValidatorKeysetsStaging    types.ValidatorKeysets
	ValidatorKeysetsActive     types.ValidatorKeysets
	ValidatorKeysetsPriorEpoch types.ValidatorKeysets
	PendingReports             [constants.NumCores]*PendingReport
	MostRecentBlockTimeslot    types.Timeslot
	AuthorizerQueue            [constants.NumCores][constants.AuthorizerQueueLength][32]byte
	PrivilegedServices         types.PrivilegedServices
	Disputes                   types.Disputes
	ValidatorStatistics        validatorstatistics.ValidatorStatistics
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes
	AccumulationHistory        AccumulationHistory
	AccumulationOutputLog      []pvm.BEEFYCommitment
}

type PendingReport struct {
	WorkReport workreport.WorkReport // w
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

func GetState(tx *staterepository.TrackedTx) (*State, error) {
	// Create a data source that reads from repository
	dataSource := &repositoryDataSource{tx: tx}
	return getStateFromDataSource(dataSource)
}

// GetStateFromKVs reconstructs a State object from a merklizer.State (list of key-value pairs)
// This is useful for testing and reconstructing states from test vectors
func GetStateFromKVs(kvs merklizer.State) (*State, error) {
	// Create a data source that reads from KV map
	dataSource := &kvDataSource{kvMap: createKVMap(kvs)}
	return getStateFromDataSource(dataSource)
}

// dataSource interface abstracts where we get state data from
type dataSource interface {
	getValue(key [31]byte) ([]byte, bool, error)
}

// repositoryDataSource reads from the repository or batch
type repositoryDataSource struct {
	tx *staterepository.TrackedTx // nil means read from repository directly
}

func (ds *repositoryDataSource) getValue(key [31]byte) ([]byte, bool, error) {
	return staterepository.GetStateKV(ds.tx, key)
}

// kvDataSource reads from a key-value map
type kvDataSource struct {
	kvMap map[[31]byte][]byte
}

func (ds *kvDataSource) getValue(key [31]byte) ([]byte, bool, error) {
	if value, exists := ds.kvMap[key]; exists {
		return value, true, nil
	}
	// Return nil for missing keys (this is fine for test vectors)
	return nil, false, nil
}

func getStateFromDataSource(ds dataSource) (*State, error) {
	state := State{}

	// Define static state components
	components := []struct {
		key    [31]byte
		target interface{}
		name   string // for debugging
	}{
		{staterepository.MakeComponentKey(1), &state.AuthorizersPool, "AuthorizersPool"},
		{staterepository.MakeComponentKey(2), &state.AuthorizerQueue, "AuthorizerQueue"},
		{staterepository.MakeComponentKey(3), &state.RecentActivity, "RecentActivity"},
		{staterepository.MakeComponentKey(4), &state.SafroleBasicState, "SafroleBasicState"},
		{staterepository.MakeComponentKey(5), &state.Disputes, "Disputes"},
		{staterepository.MakeComponentKey(6), &state.EntropyAccumulator, "EntropyAccumulator"},
		{staterepository.MakeComponentKey(7), &state.ValidatorKeysetsStaging, "ValidatorKeysetsStaging"},
		{staterepository.MakeComponentKey(8), &state.ValidatorKeysetsActive, "ValidatorKeysetsActive"},
		{staterepository.MakeComponentKey(9), &state.ValidatorKeysetsPriorEpoch, "ValidatorKeysetsPriorEpoch"},
		{staterepository.MakeComponentKey(10), &state.PendingReports, "PendingReports"},
		{staterepository.MakeComponentKey(11), &state.MostRecentBlockTimeslot, "MostRecentBlockTimeslot"},
		{staterepository.MakeComponentKey(12), &state.PrivilegedServices, "PrivilegedServices"},
		{staterepository.MakeComponentKey(13), &state.ValidatorStatistics, "ValidatorStatistics"},
		{staterepository.MakeComponentKey(14), &state.AccumulationQueue, "AccumulationQueue"},
		{staterepository.MakeComponentKey(15), &state.AccumulationHistory, "AccumulationHistory"},
		{staterepository.MakeComponentKey(16), &state.AccumulationOutputLog, "AccumulationOutputLog"},
	}

	// Deserialize each basic component
	for _, component := range components {
		value, exists, err := ds.getValue(component.key)
		if err != nil {
			return nil, err
		}

		// Skip missing components (fine for test vectors)
		if !exists {
			continue
		}

		if err := serializer.Deserialize(value, component.target); err != nil {
			return nil, fmt.Errorf("failed to deserialize component %s: %w", component.name, err)
		}
	}

	return &state, nil
}

func createKVMap(kvs merklizer.State) map[[31]byte][]byte {
	kvMap := make(map[[31]byte][]byte)
	for _, kv := range kvs {
		kvMap[kv.OriginalKey] = kv.Value
	}
	return kvMap
}

func (state *State) Set(tx *staterepository.TrackedTx) error {
	// Store static state components
	componentData := []struct {
		key  [31]byte
		data []byte
	}{
		{staterepository.MakeComponentKey(1), serializer.Serialize(&state.AuthorizersPool)},
		{staterepository.MakeComponentKey(2), serializer.Serialize(&state.AuthorizerQueue)},
		{staterepository.MakeComponentKey(3), serializer.Serialize(&state.RecentActivity)},
		{staterepository.MakeComponentKey(4), serializer.Serialize(&state.SafroleBasicState)},
		{staterepository.MakeComponentKey(5), serializer.Serialize(&state.Disputes)},
		{staterepository.MakeComponentKey(6), serializer.Serialize(&state.EntropyAccumulator)},
		{staterepository.MakeComponentKey(7), serializer.Serialize(&state.ValidatorKeysetsStaging)},
		{staterepository.MakeComponentKey(8), serializer.Serialize(&state.ValidatorKeysetsActive)},
		{staterepository.MakeComponentKey(9), serializer.Serialize(&state.ValidatorKeysetsPriorEpoch)},
		{staterepository.MakeComponentKey(10), serializer.Serialize(&state.PendingReports)},
		{staterepository.MakeComponentKey(11), serializer.Serialize(&state.MostRecentBlockTimeslot)},
		{staterepository.MakeComponentKey(12), serializer.Serialize(&state.PrivilegedServices)},
		{staterepository.MakeComponentKey(13), serializer.Serialize(&state.ValidatorStatistics)},
		{staterepository.MakeComponentKey(14), serializer.Serialize(&state.AccumulationQueue)},
		{staterepository.MakeComponentKey(15), serializer.Serialize(&state.AccumulationHistory)},
		{staterepository.MakeComponentKey(16), serializer.Serialize(&state.AccumulationOutputLog)},
	}

	// Store each component
	for _, component := range componentData {
		staterepository.SetStateKV(tx, component.key, component.data)
	}

	return nil
}
