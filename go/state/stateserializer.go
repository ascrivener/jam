package state

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/util"
)

// --- Key Constructors ---

func stateKeyConstructorFromStateComponentIndex(i uint8) [31]byte {
	return stateKeyConstructor(i, types.ServiceIndex(0))
}

func stateKeyConstructor(i uint8, s types.ServiceIndex) [31]byte {
	var key [31]byte

	key[0] = i             // First byte is i.
	key[1] = byte(s)       // Least-significant byte (n0).
	key[3] = byte(s >> 8)  // Next byte (n1).
	key[5] = byte(s >> 16) // Next byte (n2).
	key[7] = byte(s >> 24) // Most-significant byte (n3).

	// The rest of the key is already zeroed by default.
	return key
}

// invertStateKeyConstructor extracts the component ID and service index from a key
// created with stateKeyConstructor, also returning if the key matches the expected pattern
func invertStateKeyConstructor(key [31]byte) (uint8, types.ServiceIndex, bool) {
	i := key[0] // Component ID is first byte

	// Extract the service index from bytes 1, 3, 5, 7
	s := uint32(key[1]) | // Least-significant byte (n0)
		(uint32(key[3]) << 8) | // Next byte (n1)
		(uint32(key[5]) << 16) | // Next byte (n2)
		(uint32(key[7]) << 24) // Most-significant byte (n3)

	// Validate: all bytes at even positions (except 0) and positions beyond 7 should be zero
	valid := true
	for idx := range key {
		if idx > 7 || (idx > 0 && idx%2 == 0) {
			if key[idx] != 0 {
				valid = false
				break
			}
		}
	}

	return i, types.ServiceIndex(s), valid
}

// invertStateKeyConstructorFromHash extracts the service index and hash from a key
// created with stateKeyConstructorFromHash
func invertStateKeyConstructorFromHash(key [31]byte) (types.ServiceIndex, [27]byte) {
	// Extract service index from interleaved positions 0, 2, 4, 6
	s := uint32(key[0]) |
		(uint32(key[2]) << 8) |
		(uint32(key[4]) << 16) |
		(uint32(key[6]) << 24)

	// Reconstruct the original hash
	var h [27]byte

	// First 4 bytes were interleaved at positions 1, 3, 5, 7
	h[0] = key[1]
	h[1] = key[3]
	h[2] = key[5]
	h[3] = key[7]

	// Remaining bytes were copied starting at position 8
	copy(h[4:], key[8:])

	return types.ServiceIndex(s), h
}

// --- State Serializer ---

func StateSerializer(state State) map[[31]byte][]byte {
	serialized := make(map[[31]byte][]byte)

	type StateComponent struct {
		keyFunc func() [31]byte
		data    interface{}
	}

	// Define static state components.
	stateComponents := []StateComponent{
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(1) }, state.AuthorizersPool},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(2) }, state.AuthorizerQueue},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(3) }, state.RecentBlocks},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(4) }, state.SafroleBasicState},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(5) }, state.Disputes},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(6) }, state.EntropyAccumulator},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(7) }, state.ValidatorKeysetsStaging},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(8) }, state.ValidatorKeysetsActive},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(9) }, state.ValidatorKeysetsPriorEpoch},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(10) }, state.PendingReports},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(11) }, state.MostRecentBlockTimeslot},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(12) }, state.PrivilegedServices},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(13) }, state.ValidatorStatistics},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(14) }, state.AccumulationQueue},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(15) }, state.AccumulationHistory},
	}

	// Process ServiceAccounts
	for serviceIndex, serviceAccount := range state.ServiceAccounts {
		// Capture loop variables
		sIndex := serviceIndex
		sAccount := serviceAccount

		// Account state component.
		stateComponents = append(stateComponents, StateComponent{
			keyFunc: func() [31]byte {
				return stateKeyConstructor(255, sIndex)
			},
			data: struct {
				CodeHash                 [32]byte
				Balance                  types.Balance
				MinimumGasForAccumulate  types.GasValue
				MinimumGasForOnTransfer  types.GasValue
				TotalOctetsUsedInStorage uint64
				GratisStorageOffset      types.Balance
				TotalItemsUsedInStorage  uint32
			}{
				sAccount.CodeHash,
				sAccount.Balance,
				sAccount.MinimumGasForAccumulate,
				sAccount.MinimumGasForOnTransfer,
				sAccount.TotalOctetsUsedInStorage(),
				sAccount.GratisStorageOffset,
				sAccount.TotalItemsUsedInStorage(),
			},
		})

		// Process StorageDictionary.
		ones := serializer.EncodeLittleEndian(4, ^uint64(0))
		for k, v := range sAccount.StorageDictionary {
			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [31]byte {
					combined := append(ones, k[:]...)
					return serializer.StateKeyConstructorFromHash(sIndex, util.SliceToArray32(combined))
				},
				data: v,
			})
		}

		// Process PreimageLookup.
		onesMinusOne := serializer.EncodeLittleEndian(4, uint64(1<<32-2))
		for h, p := range sAccount.PreimageLookup {
			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [31]byte {
					combined := append(onesMinusOne, h[:]...)
					return serializer.StateKeyConstructorFromHash(sIndex, util.SliceToArray32(combined))
				},
				data: p,
			})
		}

		// Process PreimageLookupLengthToTimeslots.
		for k, t := range sAccount.PreimageLookupHistoricalStatus {
			blobLengthBytes := serializer.EncodeLittleEndian(4, uint64(k.BlobLength))
			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [31]byte {
					combined := append(blobLengthBytes, k.HashedPreimage[:]...)
					return serializer.StateKeyConstructorFromHash(sIndex, util.SliceToArray32(combined))
				},
				data: t,
			})
		}
	}

	// Serialize each state component.
	for _, comp := range stateComponents {
		serializedData := serializer.Serialize(comp.data)
		serialized[comp.keyFunc()] = serializedData
	}

	return serialized
}

// findStorageDictionaryEntries finds all storage dictionary entries for a specific service
func findStorageDictionaryEntries(serialized map[[31]byte][]byte, sIndex types.ServiceIndex, processedKeys map[[31]byte]bool) (map[serviceaccount.StorageDictionaryKey][]byte, error) {
	result := make(map[serviceaccount.StorageDictionaryKey][]byte)
	ones := serializer.EncodeLittleEndian(4, uint64(1<<32-1))

	for key, data := range serialized {
		// Extract service index and hash using our inverse function
		extractedSIndex, hash := invertStateKeyConstructorFromHash(key)

		// Check if this matches our service and has the "ones" prefix
		if extractedSIndex == sIndex && len(hash) >= 4 && bytes.Equal(hash[:4], ones) {

			result[serviceaccount.StorageDictionaryKey(hash[4:])] = data

			// Check if key already processed
			if alreadyProcessed := processedKeys[key]; alreadyProcessed {
				return nil, fmt.Errorf("duplicate key processing detected: storage dictionary key %x already processed", key)
			}

			// Mark key as processed
			processedKeys[key] = true
		}
	}

	return result, nil
}

// findPreimageLookupEntries finds all preimage lookup entries for a specific service
// Returns a map of hash keys to preimage bytes
func findPreimageLookupEntries(serialized map[[31]byte][]byte, sIndex types.ServiceIndex, processedKeys map[[31]byte]bool) (map[serviceaccount.PreimageLookupKey][]byte, error) {
	result := make(map[serviceaccount.PreimageLookupKey][]byte)
	onesMinusOne := serializer.EncodeLittleEndian(4, uint64(1<<32-2))

	for key, data := range serialized {
		// Extract service index and hash using our inverse function
		extractedSIndex, hash := invertStateKeyConstructorFromHash(key)

		// Check if this matches our service and has the "onesMinusOne" prefix
		if extractedSIndex == sIndex && len(hash) >= 4 && bytes.Equal(hash[:4], onesMinusOne) {
			// Store the preimage with the reconstructed key
			result[serviceaccount.PreimageLookupKey(hash[4:])] = data

			// Check if key already processed
			if alreadyProcessed := processedKeys[key]; alreadyProcessed {
				return nil, fmt.Errorf("duplicate key processing detected: preimage lookup key %x already processed", key)
			}

			// Mark key as processed
			processedKeys[key] = true
		}
	}

	return result, nil
}

// findPreimageHistoricalStatusEntries finds all preimage historical status entries for a specific service
// It requires the already populated PreimageLookup to correctly identify the historical status entries
// Returns a map of historical status keys to deserialized timeslots
func findPreimageHistoricalStatusEntries(serialized map[[31]byte][]byte, sIndex types.ServiceIndex, account *serviceaccount.ServiceAccount, processedKeys map[[31]byte]bool) (map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot, error) {
	result := make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot)

	// We need to identify keys that:
	// 1. Are constructed with stateKeyConstructorFromHash
	// 2. Have the correct service index
	// 3. The first 4 bytes are NOT ones or onesMinusOne (i.e., not storage dictionary or preimage lookup)
	// 4. The hash part matches one of our preimage's hashes

	for key, data := range serialized {
		// Extract service index and hash
		extractedSIndex, hash := invertStateKeyConstructorFromHash(key)

		// Skip if not for our service or hash too short
		if extractedSIndex != sIndex || len(hash) < 4 {
			continue
		}

		// Skip if this key has already been processed
		// This replaces the previous check for storage dictionary and preimage lookup entries,
		// since those would already be marked as processed in their respective functions
		if processedKeys[key] {
			continue
		}

		// This is a potential historical status entry - extract the blob length
		blobLength := binary.LittleEndian.Uint32(hash[:4])

		// Create the key
		lookupKey := serviceaccount.PreimageLookupHistoricalStatusKey{
			HashedPreimage: [23]byte(hash[4:]),
			BlobLength:     types.BlobLength(blobLength),
		}

		// Deserialize the timeslots here instead of in the main function
		var timeslots []types.Timeslot
		if err := serializer.Deserialize(data, &timeslots); err != nil {
			return nil, fmt.Errorf("failed to deserialize preimage historical status for service %d: %w", sIndex, err)
		}

		result[lookupKey] = timeslots

		// Check if key already processed
		if alreadyProcessed := processedKeys[key]; alreadyProcessed {
			return nil, fmt.Errorf("duplicate key processing detected: historical status key %x already processed", key)
		}

		// Mark key as processed
		processedKeys[key] = true

	}

	return result, nil
}

// StateDeserializer reconstructs a State object from its serialized form
func StateDeserializer(serialized map[[31]byte][]byte) (State, error) {
	// Create a map to track which keys have been processed
	processedKeys := make(map[[31]byte]bool)

	state := State{
		ServiceAccounts: make(map[types.ServiceIndex]*serviceaccount.ServiceAccount),
	}

	// --- Handle basic state components ---

	// Deserialize static state components
	components := []struct {
		keyFunc func() [31]byte
		target  interface{}
	}{
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(1) }, &state.AuthorizersPool},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(2) }, &state.AuthorizerQueue},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(3) }, &state.RecentBlocks},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(4) }, &state.SafroleBasicState},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(5) }, &state.Disputes},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(6) }, &state.EntropyAccumulator},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(7) }, &state.ValidatorKeysetsStaging},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(8) }, &state.ValidatorKeysetsActive},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(9) }, &state.ValidatorKeysetsPriorEpoch},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(10) }, &state.PendingReports},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(11) }, &state.MostRecentBlockTimeslot},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(12) }, &state.PrivilegedServices},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(13) }, &state.ValidatorStatistics},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(14) }, &state.AccumulationQueue},
		{func() [31]byte { return stateKeyConstructorFromStateComponentIndex(15) }, &state.AccumulationHistory},
	}

	// Deserialize each basic component
	for _, component := range components {
		key := component.keyFunc()
		if data, exists := serialized[key]; !exists {
			panic("missing key")
		} else {
			if err := serializer.Deserialize(data, component.target); err != nil {
				return State{}, fmt.Errorf("failed to deserialize component with key %x: %w", key, err)
			}
			// Mark key as processed
			processedKeys[key] = true
		}
	}

	// --- Handle ServiceAccounts ---

	// First, identify service account indexes by looking for the pattern of keys
	serviceIndexes := make(map[uint32][]byte)
	for key, data := range serialized {
		// Try to extract service index from any key
		// We ignore the error since not all keys are related to services
		if sIndex, _, err := extractServiceIndexFromKey(key); err == nil {
			serviceIndexes[sIndex] = data
			// Mark the service account base key as processed
			if i, _, validStandard := invertStateKeyConstructor(key); validStandard && i == 255 {
				processedKeys[key] = true
			}
		}
	}

	for sIndex, data := range serviceIndexes {
		// Deserialize account state
		var accountData struct {
			CodeHash                 [32]byte
			Balance                  types.Balance
			MinimumGasForAccumulate  types.GasValue
			MinimumGasForOnTransfer  types.GasValue
			TotalOctetsUsedInStorage uint64
			TotalItemsUsedInStorage  uint32
		}

		if err := serializer.Deserialize(data, &accountData); err != nil {
			return State{}, fmt.Errorf("failed to deserialize service account %d: %w", sIndex, err)
		}

		// Create and populate service account
		account := &serviceaccount.ServiceAccount{
			CodeHash:                       accountData.CodeHash,
			Balance:                        accountData.Balance,
			MinimumGasForAccumulate:        accountData.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:        accountData.MinimumGasForOnTransfer,
			StorageDictionary:              make(map[serviceaccount.StorageDictionaryKey]types.Blob),
			PreimageLookup:                 make(map[serviceaccount.PreimageLookupKey]types.Blob),
			PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
		}

		// Now look for storage dictionary entries
		storageEntries, err := findStorageDictionaryEntries(serialized, types.ServiceIndex(sIndex), processedKeys)
		if err != nil {
			return State{}, fmt.Errorf("failed to find storage dictionary entries: %w", err)
		}

		// Return an error if any storage dictionary entries are found
		for k, v := range storageEntries {
			account.StorageDictionary[k] = v
		}

		// Look for preimage lookup entries - already deserialized
		preimageEntries, err := findPreimageLookupEntries(serialized, types.ServiceIndex(sIndex), processedKeys)
		if err != nil {
			return State{}, fmt.Errorf("failed to find preimage lookup entries: %w", err)
		}
		for lookupKey, preimage := range preimageEntries {
			// The preimage is already deserialized, just store it
			account.PreimageLookup[lookupKey] = preimage
		}

		// Look for preimage historical status entries (requires PreimageLookup to be populated first)
		// Already deserialized by the function
		historicalEntries, err := findPreimageHistoricalStatusEntries(serialized, types.ServiceIndex(sIndex), account, processedKeys)
		if err != nil {
			return State{}, fmt.Errorf("failed to find preimage historical status entries: %w", err)
		}

		// Simply copy the entries to the account's map - no need to deserialize again
		for lookupKey, timeslots := range historicalEntries {
			account.PreimageLookupHistoricalStatus[lookupKey] = timeslots
		}

		// Add to state after all data has been populated
		state.ServiceAccounts[types.ServiceIndex(sIndex)] = account
	}

	// Check for unprocessed keys
	for key := range serialized {
		if !processedKeys[key] {
			return State{}, fmt.Errorf("unprocessed key found in serialized data: %x", key)
		}
	}

	return state, nil
}

func extractServiceIndexFromKey(key [31]byte) (uint32, []byte, error) {
	// Only look for standard keys with component ID 255
	i, sIndex, validStandard := invertStateKeyConstructor(key)

	if validStandard && i == 255 {
		return uint32(sIndex), nil, nil
	}

	return 0, nil, fmt.Errorf("not a service index key")
}
