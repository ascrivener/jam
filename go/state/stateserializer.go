package state

import (
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/serializer"
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

// invertStateKeyConstructor extracts the component ID and service index from a key
// created with stateKeyConstructor, also returning if the key matches the expected pattern
func invertStateKeyConstructor(key [32]byte) (uint8, types.ServiceIndex, bool) {
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

// invertStateKeyConstructorFromHash extracts the service index and hash from a key
// created with stateKeyConstructorFromHash
func invertStateKeyConstructorFromHash(key [32]byte) (types.ServiceIndex, [32]byte) {
	// Extract service index from interleaved positions 0, 2, 4, 6
	s := uint32(key[0]) |
		(uint32(key[2]) << 8) |
		(uint32(key[4]) << 16) |
		(uint32(key[6]) << 24)

	// Reconstruct the original hash
	var h [32]byte

	// First 4 bytes were interleaved at positions 1, 3, 5, 7
	h[0] = key[1]
	h[1] = key[3]
	h[2] = key[5]
	h[3] = key[7]

	// Remaining bytes were copied starting at position 8
	copy(h[4:], key[8:])

	return types.ServiceIndex(s), h
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

	return state, nil
}

func extractServiceIndexFromKey(key [32]byte) (uint32, []byte, error) {
	// Only look for standard keys with component ID 255
	i, sIndex, validStandard := invertStateKeyConstructor(key)

	if validStandard && i == 255 {
		return uint32(sIndex), nil, nil
	}

	return 0, nil, fmt.Errorf("not a service index key")
}
