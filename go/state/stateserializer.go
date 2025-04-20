package state

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
)

// --- Key Constructors ---

func stateKeyConstructorFromStateComponentIndex(i uint8) [32]byte {
	return stateKeyConstructor(i, types.ServiceIndex(0))
}

func stateKeyConstructor(i uint8, s types.ServiceIndex) [32]byte {
	var key [32]byte

	key[0] = i             // First byte is i.
	key[1] = byte(s)       // Least-significant byte (n0).
	key[3] = byte(s >> 8)  // Next byte (n1).
	key[5] = byte(s >> 16) // Next byte (n2).
	key[7] = byte(s >> 24) // Most-significant byte (n3).

	// The rest of the key is already zeroed by default.
	return key
}

func stateKeyConstructorFromHash(s types.ServiceIndex, h [32]byte) [32]byte {
	var key [32]byte

	// Extract little-endian bytes of the ServiceIndex (s)
	n0 := byte(s)
	n1 := byte(s >> 8)
	n2 := byte(s >> 16)
	n3 := byte(s >> 24)

	// Interleave n0, n1, n2, n3 with the first 4 bytes of h
	key[0] = n0
	key[1] = h[0]
	key[2] = n1
	key[3] = h[1]
	key[4] = n2
	key[5] = h[2]
	key[6] = n3
	key[7] = h[3]

	// Copy the remaining bytes of h from index 4 onward
	copy(key[8:], h[4:])

	return key
}

// --- Helper: Convert []byte to [32]byte ---

func sliceToArray32(b []byte) [32]byte {
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

// --- State Serializer ---

func StateSerializer(state State) map[[32]byte][]byte {
	serialized := make(map[[32]byte][]byte)

	type StateComponent struct {
		keyFunc func() [32]byte
		data    interface{}
	}

	// Define static state components.
	stateComponents := []StateComponent{
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(1) }, state.AuthorizersPool},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(2) }, state.AuthorizerQueue},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(3) }, state.RecentBlocks},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(4) }, state.SafroleBasicState},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(5) }, state.Disputes},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(6) }, state.EntropyAccumulator},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(7) }, state.ValidatorKeysetsStaging},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(8) }, state.ValidatorKeysetsActive},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(9) }, state.ValidatorKeysetsPriorEpoch},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(10) }, state.PendingReports},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(11) }, state.MostRecentBlockTimeslot},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(12) }, state.PrivilegedServices},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(13) }, state.ValidatorStatistics},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(14) }, state.AccumulationQueue},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(15) }, state.AccumulationHistory},
	}

	// Process ServiceAccounts
	for serviceIndex, serviceAccount := range state.ServiceAccounts {
		// Capture loop variables
		sIndex := serviceIndex
		sAccount := serviceAccount

		// Account state component.
		stateComponents = append(stateComponents, StateComponent{
			keyFunc: func() [32]byte {
				return stateKeyConstructor(255, sIndex)
			},
			data: struct {
				CodeHash                 [32]byte
				Balance                  types.Balance
				MinimumGasForAccumulate  types.GasValue
				MinimumGasForOnTransfer  types.GasValue
				TotalOctetsUsedInStorage uint64
				TotalItemsUsedInStorage  uint32
			}{
				sAccount.CodeHash,
				sAccount.Balance,
				sAccount.MinimumGasForAccumulate,
				sAccount.MinimumGasForOnTransfer,
				sAccount.TotalOctetsUsedInStorage(),
				sAccount.TotalItemsUsedInStorage(),
			},
		})

		// Process StorageDictionary.
		ones := serializer.EncodeLittleEndian(4, uint64(1<<32-1))
		for k, v := range sAccount.StorageDictionary {
			// Capture k and v.
			keyK := k
			valV := v

			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [32]byte {
					combined := append(ones, keyK[:28]...)
					return stateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
				},
				data: valV,
			})
		}

		// Process PreimageLookup.
		onesMinusOne := serializer.EncodeLittleEndian(4, uint64(1<<32-2))
		for h, p := range sAccount.PreimageLookup {
			// Capture h and p.
			hashH := h
			preimageP := p

			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [32]byte {
					combined := append(onesMinusOne, hashH[1:29]...) // 4 + 28 = 32 bytes
					return stateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
				},
				data: preimageP,
			})
		}

		// Process PreimageLookupLengthToTimeslots.
		for k, t := range sAccount.PreimageLookupHistoricalStatus {
			// Capture k and t.
			lookupKey := k
			timeslots := t

			blobLengthBytes := serializer.EncodeLittleEndian(4, uint64(lookupKey.BlobLength))
			preimageHash := blake2b.Sum256(lookupKey.Preimage[:])
			stateComponents = append(stateComponents, StateComponent{
				keyFunc: func() [32]byte {
					combined := append(blobLengthBytes, preimageHash[2:30]...)
					return stateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
				},
				data: timeslots,
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

// StateDeserializer reconstructs a State object from its serialized form
func StateDeserializer(serialized map[[32]byte][]byte) (State, error) {
	state := State{}

	// --- Handle basic state components ---

	// Deserialize static state components
	components := []struct {
		keyFunc func() [32]byte
		target  interface{}
	}{
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(1) }, &state.AuthorizersPool},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(2) }, &state.AuthorizerQueue},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(3) }, &state.RecentBlocks},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(4) }, &state.SafroleBasicState},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(5) }, &state.Disputes},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(6) }, &state.EntropyAccumulator},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(7) }, &state.ValidatorKeysetsStaging},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(8) }, &state.ValidatorKeysetsActive},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(9) }, &state.ValidatorKeysetsPriorEpoch},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(10) }, &state.PendingReports},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(11) }, &state.MostRecentBlockTimeslot},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(12) }, &state.PrivilegedServices},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(13) }, &state.ValidatorStatistics},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(14) }, &state.AccumulationQueue},
		{func() [32]byte { return stateKeyConstructorFromStateComponentIndex(15) }, &state.AccumulationHistory},
	}

	// Deserialize each basic component
	for _, component := range components {
		key := component.keyFunc()
		if data, exists := serialized[key]; exists {
			if err := serializer.Deserialize(data, component.target); err != nil {
				return State{}, fmt.Errorf("failed to deserialize component with key %x: %w", key, err)
			}
		}
	}

	// --- Handle ServiceAccounts ---

	// First, identify service account indexes by looking for the pattern of keys
	serviceIndexes := make(map[uint32]bool)
	for key := range serialized {
		// Try to extract service index from any key
		// We ignore the error since not all keys are related to services
		if sIndex, _, err := extractServiceIndexFromKey(key); err == nil {
			serviceIndexes[sIndex] = true
		}
	}

	// Process each service account
	for sIndex := range serviceIndexes {
		// Deserialize account state
		accountKey := stateKeyConstructor(255, types.ServiceIndex(sIndex))
		if data, exists := serialized[accountKey]; exists {
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
			account := serviceaccount.ServiceAccount{}
			account.CodeHash = accountData.CodeHash
			account.Balance = accountData.Balance
			account.MinimumGasForAccumulate = accountData.MinimumGasForAccumulate
			account.MinimumGasForOnTransfer = accountData.MinimumGasForOnTransfer

			// Add to state
			state.ServiceAccounts[types.ServiceIndex(sIndex)] = &account

			// Process StorageDictionary
			ones := serializer.EncodeLittleEndian(4, uint64(1<<32-1))

			// Process PreimageLookup
			onesMinusOne := serializer.EncodeLittleEndian(4, uint64(1<<32-2))

			// Deserialize all entries related to this service account
			for key, data := range serialized {
				if keyIndex, keyHash, err := extractServiceIndexFromKey(key); err == nil && keyIndex == sIndex {
					prefix := keyHash[:4]

					// StorageDictionary entry
					if bytes.Equal(prefix, ones) {
						var storageValue []byte
						var storageKey [32]byte

						// Extract the storage key
						copy(storageKey[:], append(make([]byte, 4), keyHash[4:32]...))

						if err := serializer.Deserialize(data, &storageValue); err != nil {
							return State{}, fmt.Errorf("failed to deserialize storage dictionary entry: %w", err)
						}

						account.StorageDictionary[storageKey] = storageValue
					} else if bytes.Equal(prefix, onesMinusOne) {
						// PreimageLookup entry
						var preimage []byte
						var lookupKey [32]byte

						// Extract the lookup hash (prepend 0x00 to match original hash format)
						lookupKey[0] = 0
						copy(lookupKey[1:], append(make([]byte, 0), keyHash[4:32]...))

						if err := serializer.Deserialize(data, &preimage); err != nil {
							return State{}, fmt.Errorf("failed to deserialize preimage lookup entry: %w", err)
						}

						account.PreimageLookup[lookupKey] = preimage
					} else {
						// PreimageLookupHistoricalStatus entry - extract blob length
						blobLength := binary.LittleEndian.Uint32(prefix)
						if blobLength != 0 && blobLength != 1<<32-1 && blobLength != 1<<32-2 {
							// This is likely a PreimageLookupHistoricalStatus entry
							var timeslots []types.Timeslot

							if err := serializer.Deserialize(data, &timeslots); err != nil {
								return State{}, fmt.Errorf("failed to deserialize preimage historical status: %w", err)
							}

							// Find corresponding preimage
							for _, preimage := range account.PreimageLookup {
								preimageHash := blake2b.Sum256(preimage)
								if bytes.Equal(preimageHash[2:30], keyHash[4:32]) {
									lookupKey := serviceaccount.PreimageLookupHistoricalStatusKey{
										Preimage:   sliceToArray32(preimage),
										BlobLength: types.BlobLength(blobLength),
									}
									account.PreimageLookupHistoricalStatus[lookupKey] = timeslots
									break
								}
							}
						}
					}
				}
			}
		}
	}

	return state, nil
}

// extractServiceIndexFromKey attempts to extract the service index and the hash part from a key
// It returns the service index, the hash portion, and an error if extraction fails
func extractServiceIndexFromKey(key [32]byte) (uint32, []byte, error) {
	// All service-related keys are constructed with stateKeyConstructor or stateKeyConstructorFromHash
	// The service index is in the first 4 bytes (though mixed with other data)
	// For simplicity, we just try to extract what might be a service index

	// This is a simplified approach and may need refinement based on the actual key construction
	sIndex := binary.LittleEndian.Uint32(key[:4])

	// We consider it a valid service index if it's in a reasonable range
	// Adjust these bounds based on your application's requirements
	if sIndex > 1<<24 {
		// Probably not a service index
		return 0, nil, fmt.Errorf("not a service index key")
	}

	return sIndex, key[4:], nil
}
