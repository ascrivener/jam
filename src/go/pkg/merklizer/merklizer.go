package merklizer

import (
	"bytes"

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

	// delete tree too
	treeIter, err := staterepository.NewIter(batch, &pebble.IterOptions{
		LowerBound: []byte("tree:"),
		UpperBound: []byte("tree;"), // Next ASCII character after ':'
	})
	if err != nil {
		return fmt.Errorf("failed to create tree iterator: %w", err)
	}
	defer treeIter.Close()

	// Delete all existing tree entries
	for treeIter.First(); treeIter.Valid(); treeIter.Next() {
		key := append([]byte{}, treeIter.Key()...) // Make a copy of the key
		if err := staterepository.DeleteRaw(batch, key); err != nil {
			return fmt.Errorf("failed to delete existing tree key: %w", err)
		}
	}

	// Check for tree iterator error
	if err := treeIter.Error(); err != nil {
		return fmt.Errorf("tree iterator error: %w", err)
	}

	// Insert all state KVs from this state
	for _, kv := range *s {
		if err := staterepository.SetStateKV(batch, kv.OriginalKey, kv.Value); err != nil {
			return fmt.Errorf("failed to insert state key-value: %w", err)
		}
	}

	if err := staterepository.ApplyMerkleTreeUpdates(batch); err != nil {
		return fmt.Errorf("failed to apply Merkle tree updates: %w", err)
	}

	return nil
}
