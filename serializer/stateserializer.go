package serializer

import (
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
)

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

func StateSerializer(state state.State) (map[[32]byte][]byte, error) {
	serialized := make(map[[32]byte][]byte)
	stateComponents := []struct {
		data    interface{}
		keyFunc func() [32]byte
	}{
		{state.AuthorizersPool, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(1) }},
		{state.AuthorizerQueue, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(2) }},
		{state.RecentBlocks, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(3) }},
		{state.SafroleBasicState, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(4) }},
		{state.Disputes, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(5) }},
		{state.EntropyAccumulator, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(6) }},
		{state.ValidatorKeysetsStaging, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(7) }},
		{state.ValidatorKeysetsActive, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(8) }},
		{state.ValidatorKeysetsPriorEpoch, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(9) }},
		{state.PendingReports, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(10) }},
		{state.MostRecentBlockTimeslot, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(11) }},
		{state.PrivilegedServices, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(12) }},
		{state.ValidatorStatistics, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(13) }},
		{state.AccumulationQueue, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(14) }},
		{state.AccumulationHistory, func() [32]byte { return StateKeyConstructorFromStateComponentIndex(15) }},
		// Add other components dynamically
	}
	for _, comp := range stateComponents {
		if err := serializeAndStore(serialized, comp.keyFunc, comp.data); err != nil {
			return nil, err
		}
	}
	return serialized, nil
}

func serializeAndStore(
	serialized map[[32]byte][]byte,
	keyFunc func() [32]byte,
	data interface{},
) error {
	serializedData, err := Serialize(data)
	if err != nil {
		return err
	}
	serialized[keyFunc()] = serializedData
	return nil
}
