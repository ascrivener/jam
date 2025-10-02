package staterepository

import (
	"jam/pkg/serializer"
	"jam/pkg/types"
	"os"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/blake2b"
)

// BoltStateRepository implements StateRepository using BoltDB
type BoltStateRepository struct {
	db *bolt.DB
}

// newBoltStateRepository creates a new BoltDB-backed repository
func newBoltStateRepository(dbPath string) (*BoltStateRepository, error) {
	var db *bolt.DB
	var err error

	if dbPath == "" {
		// Create a temporary file for in-memory-like database
		tmpFile, err := os.CreateTemp("", "jam_temp_*.db")
		if err != nil {
			return nil, err
		}
		tmpFile.Close() // Close the file handle, BoltDB will open it
		dbPath = tmpFile.Name()

		// Optionally, schedule cleanup
		defer os.Remove(dbPath) // Remove when done
	}

	db, err = bolt.Open(dbPath, 0600, &bolt.Options{
		NoSync: true,
	})

	if err != nil {
		return nil, err
	}

	// Create required buckets
	err = db.Update(func(tx *bolt.Tx) error {
		// Create state bucket for key-value storage
		if _, err := tx.CreateBucketIfNotExists([]byte("state")); err != nil {
			return err
		}
		// Create tree bucket for Merkle tree nodes
		if _, err := tx.CreateBucketIfNotExists([]byte("tree")); err != nil {
			return err
		}
		// Create blocks bucket for block storage
		if _, err := tx.CreateBucketIfNotExists([]byte("blocks")); err != nil {
			return err
		}
		// Create meta bucket for metadata (chain tip, etc.)
		if _, err := tx.CreateBucketIfNotExists([]byte("meta")); err != nil {
			return err
		}
		// Create preimage bucket for preimage storage
		if _, err := tx.CreateBucketIfNotExists([]byte("preimage")); err != nil {
			return err
		}
		// Create workreport bucket for work report storage
		if _, err := tx.CreateBucketIfNotExists([]byte("workreport")); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		db.Close()
		return nil, err
	}

	return &BoltStateRepository{
		db: db,
	}, nil
}

func MakeComponentKey(i uint8) [31]byte {
	return stateKeyConstructor(i, types.ServiceIndex(0))
}

func stateKeyConstructorFromServiceIndex(s types.ServiceIndex) [31]byte {
	return stateKeyConstructor(255, s)
}

func stateKeyConstructor(i uint8, s types.ServiceIndex) [31]byte {
	var key [31]byte

	key[0] = i             // First byte is i.
	key[1] = byte(s)       // Least-significant byte (n0).
	key[3] = byte(s >> 8)  // Next byte (n1).
	key[5] = byte(s >> 16) // Next byte (n2).
	key[7] = byte(s >> 24) // Most-significant byte (n3).

	// The rest of the key is already zeroed by default.
	return key
}

func stateKeyConstructorFromData(s types.ServiceIndex, data []byte) [31]byte {
	var key [31]byte

	h := blake2b.Sum256(data)

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

// Helper to create a storage key for service account's storage dictionary
// Format: stateKeyConstructorFromHash(serviceIndex, E4(2^32-1) + key[0...28])
func makeServiceStorageKey(serviceIndex types.ServiceIndex, key []byte) [31]byte {
	// E4(2^32-1)
	maxUint32Minus1 := uint32(0xFFFFFFFF)
	le := serializer.EncodeLittleEndian(4, uint64(maxUint32Minus1))
	return stateKeyConstructorFromData(serviceIndex, append(le, key...))
}

// Helper to create a preimage lookup key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(2^32-2) + hash[1...29])
func makePreimageKey(serviceIndex types.ServiceIndex, hash [32]byte) [31]byte {
	// E4(2^32-2)
	maxUint32Minus2 := uint32(0xFFFFFFFF - 1)
	le := serializer.EncodeLittleEndian(4, uint64(maxUint32Minus2))
	return stateKeyConstructorFromData(serviceIndex, append(le, hash[:]...))
}

// Helper to create a preimage lookup historical status key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(blobLength) + hashedPreimage[2...30])
func makeHistoricalStatusKey(serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) [31]byte {
	// E4(blobLength)
	le := serializer.EncodeLittleEndian(4, uint64(blobLength))
	return stateKeyConstructorFromData(serviceIndex, append(le, hashedPreimage[:]...))
}

// Close closes the database
func (r *BoltStateRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}
