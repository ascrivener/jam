package preimages

import (
	"fmt"

	"jam/pkg/staterepository"

	"github.com/cockroachdb/pebble"
)

type Preimage []byte

// Set stores a preimage in the repository using its hash as the key
// The hash must be a 32-byte array
func (p Preimage) Set(repo staterepository.PebbleStateRepository, hash [32]byte) error {
	// Create a batch for atomic operations
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Store the preimage with "preimage:" prefix
	key := append([]byte("preimage:"), hash[:]...)
	if err := batch.Set(key, p, nil); err != nil {
		return fmt.Errorf("failed to store preimage for hash %x: %w", hash, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		return batch.Commit(pebble.Sync)
	}

	return nil
}

// GetPreimage retrieves a preimage from the repository by its hash
func GetPreimage(repo staterepository.PebbleStateRepository, hash [32]byte) (Preimage, error) {
	// Construct the key with the "preimage:" prefix
	key := append([]byte("preimage:"), hash[:]...)

	// Get the value from the repository
	value, closer, err := repo.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get preimage for hash %x: %w", hash, err)
	}

	// Copy the value before closing
	preimage := make(Preimage, len(value))
	copy(preimage, value)
	closer.Close()

	return preimage, nil
}

// HasPreimage checks if a preimage exists in the repository
func HasPreimage(repo staterepository.PebbleStateRepository, hash [32]byte) bool {
	key := append([]byte("preimage:"), hash[:]...)
	value, closer, err := repo.Get(key)
	if err != nil {
		return false
	}
	closer.Close()
	return len(value) > 0
}
