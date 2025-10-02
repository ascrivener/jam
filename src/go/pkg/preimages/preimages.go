package preimages

import (
	"fmt"

	"jam/pkg/staterepository"
)

type Preimage []byte

// Set stores a preimage in the repository using its hash as the key
// The hash must be a 32-byte array
func (p Preimage) Set(tx *staterepository.TrackedTx, hash [32]byte) error {
	if err := staterepository.SetPreimage(tx, hash, p); err != nil {
		return fmt.Errorf("failed to store preimage for hash %x: %w", hash, err)
	}
	return nil
}

// GetPreimage retrieves a preimage from the repository by its hash
func GetPreimage(tx *staterepository.TrackedTx, hash [32]byte) (Preimage, error) {
	value, exists, err := staterepository.GetPreimage(tx, hash)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("preimage not found for hash %x", hash)
	}
	return Preimage(value), nil // No need to copy again since GetPreimageByHash already copied
}

// HasPreimage checks if a preimage exists in the repository
func HasPreimage(tx *staterepository.TrackedTx, hash [32]byte) bool {
	_, exists, err := staterepository.GetPreimage(tx, hash)
	if err != nil {
		return false
	}
	return exists
}
