package preimages

import (
	"errors"
	"fmt"

	"jam/pkg/staterepository"

	"github.com/cockroachdb/pebble"
)

type Preimage []byte

// Set stores a preimage in the repository using its hash as the key
// The hash must be a 32-byte array
func (p Preimage) Set(batch *pebble.Batch, hash [32]byte) error {

	// Store the preimage with "preimage:" prefix
	key := append([]byte("preimage:"), hash[:]...)
	if err := staterepository.Set(batch, key, p); err != nil {
		return fmt.Errorf("failed to store preimage for hash %x: %w", hash, err)
	}

	return nil
}

// GetPreimage retrieves a preimage from the repository by its hash
func GetPreimage(batch *pebble.Batch, hash [32]byte) (Preimage, error) {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return nil, errors.New("global repository not initialized")
	}
	// Construct the key with the "preimage:" prefix
	key := append([]byte("preimage:"), hash[:]...)

	// Get the value from the repository
	value, closer, err := staterepository.Get(batch, key)
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
func HasPreimage(batch *pebble.Batch, hash [32]byte) bool {
	key := append([]byte("preimage:"), hash[:]...)
	value, closer, err := staterepository.Get(batch, key)
	if err != nil {
		return false
	}
	closer.Close()
	return len(value) > 0
}
