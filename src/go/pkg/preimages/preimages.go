package preimages

import (
	"fmt"

	"jam/pkg/staterepository"

	"github.com/cockroachdb/pebble"
)

type Preimage []byte

// Set stores a preimage in the repository using its hash as the key
// The hash must be a 32-byte array
func (p Preimage) Set(batch *pebble.Batch, hash [32]byte) error {
	if err := staterepository.SetPreimageByHash(batch, hash, p); err != nil {
		return fmt.Errorf("failed to store preimage for hash %x: %w", hash, err)
	}
	return nil
}

// GetPreimage retrieves a preimage from the repository by its hash
func GetPreimage(batch *pebble.Batch, hash [32]byte) (Preimage, error) {
	value, exists, err := staterepository.GetPreimageByHash(batch, hash)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("preimage not found for hash %x", hash)
	}
	return Preimage(value), nil // No need to copy again since GetPreimageByHash already copied
}

// HasPreimage checks if a preimage exists in the repository
func HasPreimage(batch *pebble.Batch, hash [32]byte) bool {
	_, exists, err := staterepository.GetPreimageByHash(batch, hash)
	if err != nil {
		return false
	}
	return exists
}
