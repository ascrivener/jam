package merklizer

import (
	"bytes"

	"golang.org/x/crypto/blake2b"

	"fmt"

	"jam/pkg/staterepository"

	"github.com/cockroachdb/pebble"
)

type State []StateKV

type StateKV struct {
	OriginalKey [31]byte
	Value       []byte
}

func GetState(batch *pebble.Batch) *State {
	// Create iterator bounds for keys with "state:" prefix
	// The upper bound uses semicolon (the next ASCII character after colon)
	// to ensure we only get keys starting with "state:"
	lowerBound := []byte("state:")
	upperBound := []byte("state;") // semicolon is the next ASCII character after colon

	// Create a new iterator
	iter, err := staterepository.NewIter(batch, &pebble.IterOptions{
		LowerBound: lowerBound,
		UpperBound: upperBound,
	})
	if err != nil {
		// Return empty hash if we can't create the iterator
		return nil
	}
	defer iter.Close()

	state := &State{}
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

		// Add to the state
		*state = append(*state, StateKV{
			OriginalKey: keyBytes,
			Value:       valueBytes,
		})
	}

	return state
}

func (s *State) OverwriteCurrentState(batch *pebble.Batch) error {
	// Delete all existing state entries by iterating through all keys with "state:" prefix
	prefix := []byte("state:")
	iter, err := staterepository.NewIter(batch, &pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: []byte("state;"), // semicolon is the next character after colon in ASCII
	})
	if err != nil {
		return fmt.Errorf("failed to create iterator: %w", err)
	}
	defer iter.Close()

	// Delete all existing state entries
	for iter.First(); iter.Valid(); iter.Next() {
		key := append([]byte{}, iter.Key()...) // Make a copy of the key
		if err := staterepository.DeleteRaw(batch, key); err != nil {
			return fmt.Errorf("failed to delete existing state key: %w", err)
		}
	}

	// Check for iterator error
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	// Insert all state KVs from this state
	for _, kv := range *s {
		if err := staterepository.SetStateKV(batch, kv.OriginalKey, kv.Value); err != nil {
			return fmt.Errorf("failed to insert state key-value: %w", err)
		}
	}

	return nil
}

func MerklizeState(state *State) [32]byte {
	if len(*state) == 0 {
		return [32]byte{}
	}

	keyMap := make(map[[31]byte]StateKV)
	for _, stateKV := range *state {
		keyMap[stateKV.OriginalKey] = stateKV
	}

	return merklizeStateRecurserBytes(keyMap, 0)
}

func merklizeStateRecurserBytes(keyMap map[[31]byte]StateKV, bitDepth int) [32]byte {
	if len(keyMap) == 0 {
		return [32]byte{}
	}

	if len(keyMap) == 1 {
		// Leaf node - only use BitSequence here for formatting
		for _, stateKV := range keyMap {
			return hashLeafBytes(stateKV)
		}
	}

	leftMap := make(map[[31]byte]StateKV)
	rightMap := make(map[[31]byte]StateKV)

	// Split based on bit at current depth
	for key, stateKV := range keyMap {
		// Direct bit extraction: (key[bitDepth/8] >> (7-bitDepth%8)) & 1
		byteIndex := bitDepth / 8
		bitPos := 7 - (bitDepth % 8)

		if byteIndex < len(key) {
			bit := (key[byteIndex] >> bitPos) & 1

			if bit == 0 {
				leftMap[key] = stateKV
			} else {
				rightMap[key] = stateKV
			}
		}
	}

	leftHash := merklizeStateRecurserBytes(leftMap, bitDepth+1)
	rightHash := merklizeStateRecurserBytes(rightMap, bitDepth+1)

	// Internal node hash - flip first bit of leftHash to 0, then concat
	var nodeData [64]byte
	leftHash[0] &= 0x7F // Clear first bit (set to 0)
	copy(nodeData[:32], leftHash[:])
	copy(nodeData[32:], rightHash[:])

	return blake2b.Sum256(nodeData[:])
}

func hashLeafBytes(stateKV StateKV) [32]byte {
	buf := make([]byte, 64)
	if len(stateKV.Value) <= 32 {
		maskedSize := uint8(len(stateKV.Value)) & 0x3F // Keep only lower 6 bits (skip upper 2)
		buf[0] = 0x80 | maskedSize
		copy(buf[1:32], stateKV.OriginalKey[:])
		copy(buf[32:], stateKV.Value)
	} else {
		buf[0] = 0xC0
		copy(buf[1:32], stateKV.OriginalKey[:])
		valueHash := blake2b.Sum256(stateKV.Value)
		copy(buf[32:], valueHash[:])
	}
	return blake2b.Sum256(buf)
}
