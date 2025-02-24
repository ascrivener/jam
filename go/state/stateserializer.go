package state

import (
	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

// --- Key Constructors ---

func StateKeyConstructorFromStateComponentIndex(i uint8) [32]byte {
	return StateKeyConstructor(i, types.ServiceIndex(0))
}

func StateKeyConstructor(i uint8, s types.ServiceIndex) [32]byte {
	var key [32]byte

	key[0] = i             // First byte is i.
	key[1] = byte(s)       // Least-significant byte (n0).
	key[3] = byte(s >> 8)  // Next byte (n1).
	key[5] = byte(s >> 16) // Next byte (n2).
	key[7] = byte(s >> 24) // Most-significant byte (n3).

	// The rest of the key is already zeroed by default.
	return key
}

func StateKeyConstructorFromHash(s types.ServiceIndex, h [32]byte) [32]byte {
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
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(1) }, state.AuthorizersPool},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(2) }, state.AuthorizerQueue},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(3) }, state.RecentBlocks},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(4) }, state.SafroleBasicState},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(5) }, state.Disputes},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(6) }, state.EntropyAccumulator},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(7) }, state.ValidatorKeysetsStaging},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(8) }, state.ValidatorKeysetsActive},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(9) }, state.ValidatorKeysetsPriorEpoch},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(10) }, state.PendingReports},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(11) }, state.MostRecentBlockTimeslot},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(12) }, state.PrivilegedServices},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(13) }, state.ValidatorStatistics},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(14) }, state.AccumulationQueue},
		{func() [32]byte { return StateKeyConstructorFromStateComponentIndex(15) }, state.AccumulationHistory},
	}

	// Process ServiceAccounts
	for serviceIndex, serviceAccount := range state.ServiceAccounts {
		// Capture loop variables
		sIndex := serviceIndex
		sAccount := serviceAccount

		// Account state component.
		stateComponents = append(stateComponents, StateComponent{
			keyFunc: func() [32]byte {
				return StateKeyConstructor(255, sIndex)
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
					return StateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
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
					return StateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
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
					return StateKeyConstructorFromHash(sIndex, sliceToArray32(combined))
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
