package staterepository

import (
	"fmt"
	"io"

	"github.com/ascrivener/jam/types"
	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

// PebbleStateRepository implements StateRepository using PebbleDB
type PebbleStateRepository struct {
	db    *pebble.DB
	batch *pebble.Batch // For transaction support
}

// NewPebbleStateRepository creates a new PebbleDB-backed repository
func NewPebbleStateRepository(dbPath string) (*PebbleStateRepository, error) {
	db, err := pebble.Open(dbPath, &pebble.Options{})
	if err != nil {
		return nil, err
	}

	return &PebbleStateRepository{
		db: db,
	}, nil
}

func MakeComponentKey(i uint8) [31]byte {
	return StateKeyConstructor(i, types.ServiceIndex(0))
}

func StateKeyConstructor(i uint8, s types.ServiceIndex) [31]byte {
	var key [31]byte

	key[0] = i             // First byte is i.
	key[1] = byte(s)       // Least-significant byte (n0).
	key[3] = byte(s >> 8)  // Next byte (n1).
	key[5] = byte(s >> 16) // Next byte (n2).
	key[7] = byte(s >> 24) // Most-significant byte (n3).

	// The rest of the key is already zeroed by default.
	return key
}

func StateKeyConstructorFromHash(s types.ServiceIndex, h [32]byte) [31]byte {
	var key [31]byte

	// Extract little-endian bytes of the ServiceIndex (s)
	n0 := byte(s)
	n1 := byte(s >> 8)
	n2 := byte(s >> 16)
	n3 := byte(s >> 24)

	// Interleave n0, n1, n2, n3 with the first 4 bytes of h
	key[0] = n0
	key[1] = h[0]
	key[2] = n1
	key[3] = h[1]
	key[4] = n2
	key[5] = h[2]
	key[6] = n3
	key[7] = h[3]

	// Copy the remaining bytes of h from index 4 onward
	copy(key[8:], h[4:])

	return key
}

// Helper to encode uint32 to little-endian bytes
func encodeLittleEndian(v uint32) [4]byte {
	var b [4]byte
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}

// Helper to create a storage key for service account's storage dictionary
// Format: stateKeyConstructorFromHash(serviceIndex, E4(2^32-1) + key[0...28])
func MakeServiceStorageKey(serviceIndex types.ServiceIndex, key [32]byte) [31]byte {
	var combinedHash [32]byte
	// E4(2^32-1)
	maxUint32Minus1 := uint32(0xFFFFFFFF)
	le := encodeLittleEndian(maxUint32Minus1)
	copy(combinedHash[:4], le[:])
	// Copy the first 28 bytes of the key
	copy(combinedHash[4:], key[:28])
	return StateKeyConstructorFromHash(serviceIndex, combinedHash)
}

// Helper to create a preimage lookup key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(2^32-2) + hash[1...29])
func MakePreimageKey(serviceIndex types.ServiceIndex, hash [32]byte) [31]byte {
	var combinedHash [32]byte
	// E4(2^32-2)
	maxUint32Minus2 := uint32(0xFFFFFFFF - 1)
	le := encodeLittleEndian(maxUint32Minus2)
	copy(combinedHash[:4], le[:])
	// Copy bytes 1-29 of the hash1
	copy(combinedHash[4:], hash[1:29])
	return StateKeyConstructorFromHash(serviceIndex, combinedHash)
}

// Helper to create a preimage lookup historical status key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(blobLength) + hashedPreimage[2...30])
func MakeHistoricalStatusKey(serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) [31]byte {
	var combinedHash [32]byte
	// E4(blobLength)
	le := encodeLittleEndian(blobLength)
	copy(combinedHash[:4], le[:])
	// Copy bytes 2-30 of the hashedPreimage
	hashOfHash := blake2b.Sum256(hashedPreimage[:])
	copy(combinedHash[4:], hashOfHash[2:30])
	return StateKeyConstructorFromHash(serviceIndex, combinedHash)
}

// Get retrieves a value from the database
func (r *PebbleStateRepository) Get(key []byte) ([]byte, io.Closer, error) {
	// If there's an active batch, use it exclusively
	if r.batch != nil {
		// Use the indexed batch for ALL reads when it's active
		// This will show deletions correctly as NotFound
		return r.batch.Get(key)
	}
	return r.db.Get(key)
}

// NewIter creates a new iterator with the given options
func (r *PebbleStateRepository) NewIter(opts *pebble.IterOptions) (*pebble.Iterator, error) {
	if r.batch != nil {
		// When a transaction is in progress, create an iterator that merges pending changes with DB state
		return r.batch.NewIter(opts)
	}
	return r.db.NewIter(opts)
}

// GetBatch returns the current batch or creates a new one
func (r *PebbleStateRepository) GetBatch() *pebble.Batch {
	return r.batch
}

func (r *PebbleStateRepository) NewBatch() *pebble.Batch {
	return r.db.NewIndexedBatch()
}

// BeginTransaction starts a new transaction
func (r *PebbleStateRepository) BeginTransaction() error {
	if r.batch != nil {
		return fmt.Errorf("transaction already in progress")
	}
	r.batch = r.db.NewIndexedBatch()
	return nil
}

// CommitTransaction commits the current transaction
func (r *PebbleStateRepository) CommitTransaction() error {
	if r.batch == nil {
		return fmt.Errorf("no transaction in progress")
	}
	err := r.batch.Commit(pebble.Sync)
	r.batch = nil
	return err
}

// RollbackTransaction aborts the current transaction
func (r *PebbleStateRepository) RollbackTransaction() error {
	if r.batch == nil {
		return fmt.Errorf("no transaction in progress")
	}
	r.batch.Close()
	r.batch = nil
	return nil
}

// DeleteServiceAccount removes a service account and all its associated data
func (r *PebbleStateRepository) DeleteServiceAccount(serviceIndex types.ServiceIndex) error {
	// Create a new batch if one isn't already in progress
	batch := r.batch
	ownBatch := batch == nil
	if ownBatch {
		batch = r.db.NewIndexedBatch()
		defer batch.Close()
	}

	// Delete the service account itself
	// Service account key format: [255, n_0, 0, n_1, 0, n_2, 0, n_3, 0, 0...]
	sIndex := uint32(serviceIndex)
	key := make([]byte, 9)
	key[0] = 255                // Prefix
	key[1] = byte(sIndex)       // n_0
	key[2] = 0                  // Separator
	key[3] = byte(sIndex >> 8)  // n_1
	key[4] = 0                  // Separator
	key[5] = byte(sIndex >> 16) // n_2
	key[6] = 0                  // Separator
	key[7] = byte(sIndex >> 24) // n_3
	key[8] = 0                  // Trailing zero

	if err := batch.Delete(key, nil); err != nil {
		return fmt.Errorf("failed to delete service account %d: %w", serviceIndex, err)
	}

	// Delete all storage items for this service account
	// To do this, we need to iterate through all keys with a specific pattern
	// This would be easier with prefix scanning, but would require a more complete implementation
	// For now, we'll rely on the state data structure

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the database
func (r *PebbleStateRepository) Close() error {
	if r.batch != nil {
		r.batch.Close()
	}
	return r.db.Close()
}
