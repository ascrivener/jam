package merklizer

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/blake2b"

	"fmt"

	"jam/pkg/bitsequence"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"

	"github.com/cockroachdb/pebble"
)

type State []StateKV

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

func GetState() State {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		panic("global repository not initialized")
	}
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
		return State{}
	}
	defer iter.Close()

	state := State{}
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
		state = append(state, StateKV{
			OriginalKey: keyBytes,
			Value:       valueBytes,
		})
	}

	return state
}

func (s State) OverwriteCurrentState() error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Delete all existing state entries by iterating through all keys with "state:" prefix
	prefix := []byte("state:")
	iter, err := repo.NewIter(&pebble.IterOptions{
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
		if err := batch.Delete(key, nil); err != nil {
			return fmt.Errorf("failed to delete existing state key: %w", err)
		}
	}

	// Check for iterator error
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	// Insert all state KVs from this state
	for _, kv := range s {
		key := append([]byte("state:"), kv.OriginalKey[:]...)
		if err := batch.Set(key, kv.Value, nil); err != nil {
			return fmt.Errorf("failed to insert state key-value: %w", err)
		}
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch: %w", err)
		}
	}

	return nil
}

func MerklizeState(state State) [32]byte {
	// Initialize the map that will hold our leaves
	bitSeqKeyMap := make(map[bitsequence.BitSeqKey]StateKV)

	for _, stateKV := range state {
		bitSeqKeyMap[bitsequence.FromBytes(stateKV.OriginalKey[:]).Key()] = stateKV
	}

	return merklizeStateRecurser(bitSeqKeyMap)
}
