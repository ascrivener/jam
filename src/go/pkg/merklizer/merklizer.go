package merklizer

import (
	"fmt"

	"jam/pkg/staterepository"
)

type State []StateKV

type StateKV struct {
	OriginalKey [31]byte
	Value       []byte
}

func GetState(tx *staterepository.TrackedTx) *State {
	// Create a new iterator
	iter, err := staterepository.NewIter(tx, "state", &staterepository.IterOptions{})
	if err != nil {
		// Return empty hash if we can't create the iterator
		return nil
	}
	defer iter.Close()

	state := &State{}
	// Iterate through all matching keys
	for key, value := iter.First(); iter.Valid(); key, value = iter.Next() {

		// Convert to [31]byte
		var keyBytes [31]byte
		copy(keyBytes[:], key)

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

func (s *State) OverwriteCurrentState(tx *staterepository.TrackedTx) error {
	// Delete all existing state entries by iterating through all keys with "state:" prefix
	iter, err := staterepository.NewIter(tx, "state", &staterepository.IterOptions{})
	if err != nil {
		return fmt.Errorf("failed to create iterator: %w", err)
	}
	defer iter.Close()

	// Delete all existing state entries
	for key, _ := iter.First(); iter.Valid(); key, _ = iter.Next() {
		var keyBytes [31]byte
		copy(keyBytes[:], key)
		if err := staterepository.DeleteStateKV(tx, keyBytes); err != nil {
			return fmt.Errorf("failed to delete existing state key: %w", err)
		}
	}

	// delete tree too
	treeIter, err := staterepository.NewIter(tx, "tree", &staterepository.IterOptions{})
	if err != nil {
		return fmt.Errorf("failed to create tree iterator: %w", err)
	}
	defer treeIter.Close()

	// Delete all existing tree entries
	for key, _ := treeIter.First(); treeIter.Valid(); key, _ = treeIter.Next() {
		if err := staterepository.DeleteTreeNodeData(tx, key); err != nil {
			return fmt.Errorf("failed to delete existing tree key: %w", err)
		}
	}

	// Insert all state KVs from this state
	for _, kv := range *s {
		if err := staterepository.SetStateKV(tx, kv.OriginalKey, kv.Value); err != nil {
			return fmt.Errorf("failed to insert state key-value: %w", err)
		}
	}

	if err := staterepository.ApplyMerkleTreeUpdates(tx); err != nil {
		return fmt.Errorf("failed to apply Merkle tree updates: %w", err)
	}

	return nil
}
