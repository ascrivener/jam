package state

import (
	"bytes"
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/merklizer"
	"jam/pkg/pvm"
	"jam/pkg/serializer"
	"jam/pkg/serviceaccount"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/validatorstatistics"
	"jam/pkg/workreport"

	"github.com/cockroachdb/pebble"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte
	RecentActivity             RecentActivity
	SafroleBasicState          SafroleBasicState
	ServiceAccounts            serviceaccount.ServiceAccounts
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

func GetState() (State, error) {
	// Create a data source that reads from repository
	dataSource := &repositoryDataSource{}
	return getStateFromDataSource(dataSource)
}

// GetStateFromKVs reconstructs a State object from a merklizer.State (list of key-value pairs)
// This is useful for testing and reconstructing states from test vectors
func GetStateFromKVs(kvs merklizer.State) (State, error) {
	// Create a data source that reads from KV map
	dataSource := &kvDataSource{kvMap: createKVMap(kvs)}
	return getStateFromDataSource(dataSource)
}

// dataSource interface abstracts where we get state data from
type dataSource interface {
	getValue(key [31]byte) ([]byte, error)
	iterateServiceAccounts() (serviceAccountIterator, error)
}

// serviceAccountIterator abstracts iteration over service account keys
type serviceAccountIterator interface {
	// First positions the iterator at the first key
	First() bool
	// Valid returns true if the iterator is positioned at a valid key
	Valid() bool
	// Next advances the iterator to the next key
	Next() bool
	// Key returns the current key
	Key() []byte
	// Value returns the current value
	Value() []byte
	// Close releases iterator resources
	Close() error
}

// repositoryDataSource reads from the repository
type repositoryDataSource struct {
}

func (ds *repositoryDataSource) getValue(key [31]byte) ([]byte, error) {
	prefixedKey := append([]byte("state:"), key[:]...)
	value, closer, err := staterepository.Get(nil, prefixedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get component: %w", err)
	}

	// Make a copy of the value since it's only valid until closer.Close()
	dataCopy := make([]byte, len(value))
	copy(dataCopy, value)
	closer.Close()

	return dataCopy, nil
}

func (ds *repositoryDataSource) iterateServiceAccounts() (serviceAccountIterator, error) {
	serviceAccountPrefix := append([]byte("state:"), 255)
	iter, err := staterepository.NewIter(nil, &pebble.IterOptions{
		LowerBound: serviceAccountPrefix,
		UpperBound: append(append([]byte{}, serviceAccountPrefix...), 0xFF),
	})
	if err != nil {
		return nil, err
	}
	return &repositoryIterator{iter: iter}, nil
}

// repositoryIterator wraps pebble iterator
type repositoryIterator struct {
	iter *pebble.Iterator
}

func (ri *repositoryIterator) First() bool {
	return ri.iter.First()
}

func (ri *repositoryIterator) Valid() bool {
	return ri.iter.Valid()
}

func (ri *repositoryIterator) Next() bool {
	return ri.iter.Next()
}

func (ri *repositoryIterator) Key() []byte {
	return ri.iter.Key()
}

func (ri *repositoryIterator) Value() []byte {
	// Copy the value since it's only valid until iter is closed
	value := make([]byte, len(ri.iter.Value()))
	copy(value, ri.iter.Value())
	return value
}

func (ri *repositoryIterator) Close() error {
	return ri.iter.Close()
}

// kvDataSource reads from a key-value map
type kvDataSource struct {
	kvMap map[[31]byte][]byte
}

func (ds *kvDataSource) getValue(key [31]byte) ([]byte, error) {
	if value, exists := ds.kvMap[key]; exists {
		return value, nil
	}
	// Return nil for missing keys (this is fine for test vectors)
	return nil, nil
}

func (ds *kvDataSource) iterateServiceAccounts() (serviceAccountIterator, error) {
	return &kvIterator{
		kvMap: ds.kvMap,
		keys:  nil, // will be populated on first call
		index: -1,
	}, nil
}

// kvIterator iterates over service account keys in a KV map
type kvIterator struct {
	kvMap map[[31]byte][]byte
	keys  [][31]byte // all keys
	index int
}

func (ki *kvIterator) First() bool {
	if ki.keys == nil {
		// Build all keys list on first access
		ki.keys = make([][31]byte, 0)
		for key := range ki.kvMap {
			ki.keys = append(ki.keys, key)
		}
	}

	ki.index = 0
	return len(ki.keys) > 0
}

func (ki *kvIterator) Valid() bool {
	return ki.index >= 0 && ki.index < len(ki.keys)
}

func (ki *kvIterator) Next() bool {
	ki.index++
	return ki.Valid()
}

func (ki *kvIterator) Key() []byte {
	if !ki.Valid() {
		return nil
	}
	// Add "state:" prefix to match repository format
	return append([]byte("state:"), ki.keys[ki.index][:]...)
}

func (ki *kvIterator) Value() []byte {
	if !ki.Valid() {
		return nil
	}
	return ki.kvMap[ki.keys[ki.index]]
}

func (ki *kvIterator) Close() error {
	// No resources to clean up for in-memory iterator
	return nil
}

func (s *State) loadServiceAccounts(ds dataSource) error {
	iter, err := ds.iterateServiceAccounts()
	if err != nil {
		return err
	}
	defer iter.Close()
	serviceAccountPrefix := append([]byte("state:"), 255)

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()

		// Make sure key starts with our prefix
		if len(key) < 7 || !bytes.HasPrefix(key, serviceAccountPrefix) {
			continue
		}

		// Skip the prefix for pattern checking (after "state:" + 255 byte)
		unprefixedKey := key[len(serviceAccountPrefix):]

		// Validate and extract service index
		serviceIndex, valid := extractServiceIndexFromKey(unprefixedKey)
		if !valid {
			continue
		}

		// Process the service account
		if err := s.processServiceAccount(serviceIndex, iter.Value()); err != nil {
			return err
		}
	}

	return nil
}

func getStateFromDataSource(ds dataSource) (State, error) {
	state := State{
		ServiceAccounts: make(map[types.ServiceIndex]*serviceaccount.ServiceAccount),
	}

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
		value, err := ds.getValue(component.key)
		if err != nil {
			return State{}, err
		}

		// Skip missing components (fine for test vectors)
		if value == nil {
			continue
		}

		if err := serializer.Deserialize(value, component.target); err != nil {
			return State{}, fmt.Errorf("failed to deserialize component %s: %w", component.name, err)
		}
	}

	// Load service accounts using the appropriate method
	if err := state.loadServiceAccounts(ds); err != nil {
		return State{}, err
	}

	return state, nil
}

func createKVMap(kvs merklizer.State) map[[31]byte][]byte {
	kvMap := make(map[[31]byte][]byte)
	for _, kv := range kvs {
		kvMap[kv.OriginalKey] = kv.Value
	}
	return kvMap
}

func extractServiceIndexFromKey(unprefixedKey []byte) (uint64, bool) {
	// Check the pattern [n_0, 0, n_1, 0, n_2, 0, n_3, 0, 0...]
	// Only proceed if the zero bytes are in the right places
	if len(unprefixedKey) < 8 || unprefixedKey[1] != 0 || unprefixedKey[3] != 0 || unprefixedKey[5] != 0 || unprefixedKey[7] != 0 {
		return 0, false
	}

	// Check that all remaining bytes are zeros
	for i := 8; i < len(unprefixedKey); i++ {
		if unprefixedKey[i] != 0 {
			return 0, false
		}
	}

	// Extract service index from key using little endian [n0,n1,n2,n3]
	serviceIndex := uint64(unprefixedKey[0]) |
		uint64(unprefixedKey[2])<<8 |
		uint64(unprefixedKey[4])<<16 |
		uint64(unprefixedKey[6])<<24

	return serviceIndex, true
}

func (state *State) processServiceAccount(serviceIndex uint64, value []byte) error {
	var serviceAccountData struct {
		CodeHash                       [32]byte           // c
		Balance                        types.Balance      // b
		MinimumGasForAccumulate        types.GasValue     // g
		MinimumGasForOnTransfer        types.GasValue     // m
		TotalOctetsUsedInStorage       uint64             // o
		GratisStorageOffset            types.Balance      // f
		TotalItemsUsedInStorage        uint32             // i
		CreatedTimeSlot                types.Timeslot     // r
		MostRecentAccumulationTimeslot types.Timeslot     // a
		ParentServiceIndex             types.ServiceIndex // p
	}

	// Deserialize account
	if err := serializer.Deserialize(value, &serviceAccountData); err != nil {
		return fmt.Errorf("failed to deserialize service account %d: %w", serviceIndex, err)
	}

	// Add to state
	state.ServiceAccounts[types.ServiceIndex(serviceIndex)] = &serviceaccount.ServiceAccount{
		ServiceIndex:                   types.ServiceIndex(serviceIndex),
		CodeHash:                       serviceAccountData.CodeHash,
		Balance:                        serviceAccountData.Balance,
		MinimumGasForAccumulate:        serviceAccountData.MinimumGasForAccumulate,
		MinimumGasForOnTransfer:        serviceAccountData.MinimumGasForOnTransfer,
		TotalOctetsUsedInStorage:       serviceAccountData.TotalOctetsUsedInStorage,
		GratisStorageOffset:            serviceAccountData.GratisStorageOffset,
		TotalItemsUsedInStorage:        serviceAccountData.TotalItemsUsedInStorage,
		CreatedTimeSlot:                serviceAccountData.CreatedTimeSlot,
		MostRecentAccumulationTimeslot: serviceAccountData.MostRecentAccumulationTimeslot,
		ParentServiceIndex:             serviceAccountData.ParentServiceIndex,
	}

	return nil
}

func (state *State) Set(batch *pebble.Batch) error {
	// Store static state components
	components := []struct {
		key    [31]byte
		source interface{}
	}{
		{staterepository.MakeComponentKey(1), state.AuthorizersPool},
		{staterepository.MakeComponentKey(2), state.AuthorizerQueue},
		{staterepository.MakeComponentKey(3), state.RecentActivity},
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
		{staterepository.MakeComponentKey(16), state.AccumulationOutputLog},
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
		rawKey := staterepository.StateKeyConstructorFromServiceIndex(serviceIndex)

		// Add state: prefix
		prefixedKey := append([]byte("state:"), rawKey[:]...)

		var serviceAccountData = struct {
			CodeHash                       [32]byte           // c
			Balance                        types.Balance      // b
			MinimumGasForAccumulate        types.GasValue     // g
			MinimumGasForOnTransfer        types.GasValue     // m
			TotalOctetsUsedInStorage       uint64             // o
			GratisStorageOffset            types.Balance      // f
			TotalItemsUsedInStorage        uint32             // i
			CreatedTimeSlot                types.Timeslot     // r
			MostRecentAccumulationTimeslot types.Timeslot     // a
			ParentServiceIndex             types.ServiceIndex // p
		}{
			CodeHash:                       account.CodeHash,
			Balance:                        account.Balance,
			MinimumGasForAccumulate:        account.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:        account.MinimumGasForOnTransfer,
			TotalOctetsUsedInStorage:       account.TotalOctetsUsedInStorage,
			GratisStorageOffset:            account.GratisStorageOffset,
			TotalItemsUsedInStorage:        account.TotalItemsUsedInStorage,
			CreatedTimeSlot:                account.CreatedTimeSlot,
			MostRecentAccumulationTimeslot: account.MostRecentAccumulationTimeslot,
			ParentServiceIndex:             account.ParentServiceIndex,
		}
		data := serializer.Serialize(serviceAccountData)
		if err := batch.Set(prefixedKey, data, nil); err != nil {
			return fmt.Errorf("failed to store service account %d: %w", serviceIndex, err)
		}
	}

	return nil
}
