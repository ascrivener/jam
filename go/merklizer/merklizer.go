package merklizer

import (
	"bytes"

	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/staterepository"
	"github.com/cockroachdb/pebble"
)

type StateKV struct {
	OriginalKey [31]byte
	Value       []byte
}

func merklizeStateRecurser(bitSeqKeyMap map[bitsequence.BitSeqKey]StateKV) [32]byte {
	if len(bitSeqKeyMap) == 0 {
		return [32]byte{}
	}
	if len(bitSeqKeyMap) == 1 {
		bs := bitsequence.New()
		for _, stateKV := range bitSeqKeyMap {
			if len(stateKV.Value) <= 32 {
				serializedEmbeddedValueSize := serializer.Serialize(uint8(len(stateKV.Value)))
				bs.AppendBits([]bool{true, false})
				bs.Concat(bitsequence.FromBytes(serializedEmbeddedValueSize).SubsequenceFrom(2))
				bs.Concat(bitsequence.FromBytes(stateKV.OriginalKey[:]))
				bs.Concat(bitsequence.FromBytes(stateKV.Value))
				for bs.Len() < 64*8 {
					bs.AppendBit(false)
				}
			} else {
				valueHash := blake2b.Sum256(stateKV.Value)
				bs.AppendBits([]bool{true, true, false, false, false, false, false, false})
				bs.Concat(bitsequence.FromBytes(stateKV.OriginalKey[:]))
				bs.Concat(bitsequence.FromBytes(valueHash[:]))
			}
			break
		}
		return blake2b.Sum256(bs.Bytes())
	}

	leftMap := make(map[bitsequence.BitSeqKey]StateKV)
	rightMap := make(map[bitsequence.BitSeqKey]StateKV)

	// Process each key-value pair in the original map.
	for k, stateKV := range bitSeqKeyMap {
		// Convert the key to a BitSequence.
		bs := k.ToBitSequence()

		// Get the first bit.
		firstBit := bs.BitAt(0)

		// Get a new BitSequence containing all bits after the first one.
		newKeyBS := bs.SubsequenceFrom(1)

		// Insert into the appropriate map.
		if !firstBit {
			leftMap[newKeyBS.Key()] = stateKV
		} else {
			rightMap[newKeyBS.Key()] = stateKV
		}
	}

	leftSubtrieHash := merklizeStateRecurser(leftMap)
	rightSubtrieHash := merklizeStateRecurser(rightMap)
	bs := bitsequence.New()
	bs.AppendBit(false)
	bs.Concat(bitsequence.FromBytes(leftSubtrieHash[:]).SubsequenceFrom(1))
	bs.Concat(bitsequence.FromBytes(rightSubtrieHash[:]))

	return blake2b.Sum256(bs.Bytes())
}

func MerklizeState(repo staterepository.PebbleStateRepository) [32]byte {
	// Initialize the map that will hold our leaves
	bitSeqKeyMap := make(map[bitsequence.BitSeqKey]StateKV)

	// Create iterator bounds for keys with "state:" prefix
	// The upper bound uses semicolon (the next ASCII character after colon)
	// to ensure we only get keys starting with "state:"
	lowerBound := []byte("state:")
	upperBound := []byte("state;") // semicolon is the next ASCII character after colon

	// Create a new iterator
	iter, err := repo.NewIter(&pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		// Return empty hash if we can't create the iterator
		return [32]byte{}
	}
	defer iter.Close()

	// Iterate through all matching keys
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Skip if not a state key
		if !bytes.HasPrefix(key, lowerBound) {
			continue
		}

		// Remove "state:" prefix
		unprefixedKey := key[len(lowerBound):]

		// Only process keys that can fit in a [31]byte array
		if len(unprefixedKey) != 31 {
			panic("key is not 31 bytes long")
		}

		// Convert to [31]byte
		var keyBytes [31]byte
		copy(keyBytes[:], unprefixedKey)

		// Copy value
		valueBytes := make([]byte, len(value))
		copy(valueBytes, value)

		// Add to the map
		bitSeqKeyMap[bitsequence.FromBytes(keyBytes[:]).Key()] = StateKV{
			OriginalKey: keyBytes,
			Value:       valueBytes,
		}
	}

	return merklizeStateRecurser(bitSeqKeyMap)
}
