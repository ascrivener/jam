package staterepository

import (
	"jam/pkg/serializer"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

// PebbleStateRepository implements StateRepository using PebbleDB
type PebbleStateRepository struct {
	db *pebble.DB
}

// newPebbleStateRepository creates a new PebbleDB-backed repository
func newPebbleStateRepository(dbPath string) (*PebbleStateRepository, error) {
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

func StateKeyConstructorFromServiceIndex(s types.ServiceIndex) [31]byte {
	return StateKeyConstructor(255, s)
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

func StateKeyConstructorFromData(s types.ServiceIndex, data []byte) [31]byte {
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
func MakeServiceStorageKey(serviceIndex types.ServiceIndex, key []byte) [31]byte {
	// E4(2^32-1)
	maxUint32Minus1 := uint32(0xFFFFFFFF)
	le := serializer.EncodeLittleEndian(4, uint64(maxUint32Minus1))
	return StateKeyConstructorFromData(serviceIndex, append(le, key...))
}

// Helper to create a preimage lookup key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(2^32-2) + hash[1...29])
func MakePreimageKey(serviceIndex types.ServiceIndex, hash [32]byte) [31]byte {
	// E4(2^32-2)
	maxUint32Minus2 := uint32(0xFFFFFFFF - 1)
	le := serializer.EncodeLittleEndian(4, uint64(maxUint32Minus2))
	return StateKeyConstructorFromData(serviceIndex, append(le, hash[:]...))
}

// Helper to create a preimage lookup historical status key
// Format: stateKeyConstructorFromHash(serviceIndex, E4(blobLength) + hashedPreimage[2...30])
func MakeHistoricalStatusKey(serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) [31]byte {
	// E4(blobLength)
	le := serializer.EncodeLittleEndian(4, uint64(blobLength))
	return StateKeyConstructorFromData(serviceIndex, append(le, hashedPreimage[:]...))
}

// Close closes the database
func (r *PebbleStateRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}
