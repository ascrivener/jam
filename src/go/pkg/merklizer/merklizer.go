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

func GetState(tx *staterepository.TrackedTx) (*State, error) {
	state := &State{}

	// Start traversal from root
	err := collectLeaves(tx, tx.GetStateRoot(), state)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func collectLeaves(tx *staterepository.TrackedTx, nodeHash [32]byte, state *State) error {
	// Get node from database using "tree:node:<hash>" key
	node, exists, err := staterepository.GetTreeNode(tx, nodeHash)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("node %x does not exist", nodeHash)
	}

	if node.IsLeaf() {
		// This is a leaf - add to state
		*state = append(*state, StateKV{
			OriginalKey: node.OriginalKey,
			Value:       node.OriginalValue,
		})
	} else {
		// This is an internal node - recurse on children
		if node.LeftHash != [32]byte{} {
			err = collectLeaves(tx, node.LeftHash, state)
			if err != nil {
				return err
			}
		}
		if node.RightHash != [32]byte{} {
			err = collectLeaves(tx, node.RightHash, state)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *State) OverwriteCurrentState(tx *staterepository.TrackedTx) error {
	// Insert all state KVs from this state
	for _, kv := range *s {
		if err := staterepository.SetStateKV(tx, kv.OriginalKey, kv.Value); err != nil {
			return fmt.Errorf("failed to insert state key-value: %w", err)
		}
	}

	return nil
}
