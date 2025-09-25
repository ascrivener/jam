package staterepository

import (
	"fmt"
	"io"
	"jam/pkg/serializer"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

// Node represents both leaf and internal nodes in the Merkle tree
type Node struct {
	Hash           [32]byte
	Value          []byte   // Non-empty for leaf nodes, empty for internal nodes
	OriginalKey    [31]byte // Only used for leaf nodes
	CompressedPath []byte
}

func GetTreeNode(batch *pebble.Batch, path []byte) (*Node, error) {
	prefixedKey := addTreeNodePrefix(path)
	value, closer, err := get(batch, prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	var node Node
	if err := serializer.Deserialize(result, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// // createLeafNode creates a new leaf node
// func createLeafNode(originalKey [31]byte, value []byte) *Node {
// 	hash := calculateLeafHash(originalKey, value)
// 	return &Node{
// 		Hash:           hash,
// 		Value:          value, // Can be empty slice []byte{}
// 		OriginalKey:    originalKey,
// 		CompressedPath: []byte{},
// 	}
// }

// createInternalNode creates a new internal node
// func createInternalNode(leftHash, rightHash [32]byte) *Node {
// 	hash := calculateInternalNodeHash(leftHash, rightHash)
// 	return &Node{
// 		Hash:        hash,
// 		Value:       []byte{},
// 		OriginalKey: [31]byte{},
// 	}
// }

// Get retrieves a value for the given key with automatic "state:" prefixing
func GetStateKV(batch *pebble.Batch, key [31]byte) ([]byte, io.Closer, error) {
	prefixedKey := addStatePrefix(key)
	return get(batch, prefixedKey)
}

// Set stores a key-value pair with automatic "state:" prefixing
func SetStateKV(batch *pebble.Batch, key [31]byte, value []byte) error {
	prefixedKey := addStatePrefix(key)

	// Store the actual data
	if err := set(batch, prefixedKey, value); err != nil {
		return err
	}

	return updateMerkleTreeForSet(batch, key, value)
}

// Delete removes a key with automatic "state:" prefixing
func DeleteStateKV(batch *pebble.Batch, key [31]byte) error {
	prefixedKey := addStatePrefix(key)

	// Delete the actual data
	if err := delete(batch, prefixedKey); err != nil {
		return err
	}

	return updateMerkleTreeForDelete(batch, key)
}

// Exists checks if a key exists
func ExistsStateKV(batch *pebble.Batch, key [31]byte) (bool, error) {
	_, closer, err := GetStateKV(batch, key)
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer closer.Close()
	return true, nil
}

// SetServiceAccount stores service account data
func SetServiceAccount(batch *pebble.Batch, serviceIndex types.ServiceIndex, data []byte) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return SetStateKV(batch, dbKey, data)
}

// DeleteServiceAccount deletes a service account
func DeleteServiceAccount(batch *pebble.Batch, serviceIndex types.ServiceIndex) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return DeleteStateKV(batch, dbKey)
}

// GetServiceStorageItem retrieves a service storage item with proper error handling
func GetServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey []byte) ([]byte, bool, error) {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	value, closer, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetServiceStorageItem stores a service storage item
func SetServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey, value []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return SetStateKV(batch, dbKey, value)
}

// DeleteServiceStorageItem deletes a service storage item
func DeleteServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return DeleteStateKV(batch, dbKey)
}

// GetPreimage retrieves a preimage for a given hash
func GetPreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte) ([]byte, bool, error) {
	dbKey := makePreimageKey(serviceIndex, hash)
	value, closer, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetPreimage stores a preimage for a given hash
func SetPreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte, preimage []byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return SetStateKV(batch, dbKey, preimage)
}

// DeletePreimage deletes a preimage for a given hash
func DeletePreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return DeleteStateKV(batch, dbKey)
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func GetPreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	value, closer, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	var status []types.Timeslot
	if err := serializer.Deserialize(result, &status); err != nil {
		return nil, false, err
	}
	return status, true, nil
}

// SetPreimageLookupHistoricalStatus stores historical status for a preimage lookup
func SetPreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	serializedStatus := serializer.Serialize(status)
	return SetStateKV(batch, dbKey, serializedStatus)
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func DeletePreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	return DeleteStateKV(batch, dbKey)
}

// NewIterator creates an iterator with "state:" prefix filtering
func NewIterator(batch *pebble.Batch) (*pebble.Iterator, error) {
	opts := &pebble.IterOptions{
		LowerBound: []byte("state:"),
		UpperBound: []byte("state;"), // Next ASCII character after ':'
	}
	return NewIter(batch, opts)
}

// addStatePrefix adds the "state:" prefix to a key
func addStatePrefix(key [31]byte) []byte {
	return append([]byte("state:"), key[:]...)
}

// GetBlock retrieves block data with automatic "block:" prefixing
func GetBlock(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	prefixedKey := addBlockPrefix(key)
	return get(batch, prefixedKey)
}

// addBlockPrefix adds the "block:" prefix to a key
func addBlockPrefix(key []byte) []byte {
	return append([]byte("block:"), key...)
}

func GetTip(batch *pebble.Batch) ([]byte, io.Closer, error) {
	return get(batch, []byte("meta:chaintip"))
}

// GetRaw retrieves a value using the exact key without any prefixing
func GetRaw(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	return get(batch, key)
}

// DeleteRaw deletes a value using the exact key without any prefixing
func DeleteRaw(batch *pebble.Batch, key []byte) error {
	return delete(batch, key)
}

// GetPreimageByHash retrieves a preimage by its hash with automatic "preimage:" prefixing
func GetPreimageByHash(batch *pebble.Batch, hash [32]byte) ([]byte, bool, error) {
	prefixedKey := addPreimagePrefix(hash[:])
	value, closer, err := get(batch, prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetPreimageByHash stores a preimage by its hash with automatic "preimage:" prefixing
func SetPreimageByHash(batch *pebble.Batch, hash [32]byte, preimage []byte) error {
	prefixedKey := addPreimagePrefix(hash[:])
	return set(batch, prefixedKey, preimage)
}

// addPreimagePrefix adds the "preimage:" prefix to a key
func addPreimagePrefix(key []byte) []byte {
	return append([]byte("preimage:"), key...)
}

// GetWorkReport retrieves a work report with automatic "workreport:" prefixing
func GetWorkReport(batch *pebble.Batch, key []byte) ([]byte, bool, error) {
	prefixedKey := addWorkReportPrefix(key)
	value, closer, err := get(batch, prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetWorkReportBySegmentRoot stores a work report by segment root
func SetWorkReportBySegmentRoot(batch *pebble.Batch, segmentRoot [32]byte, workReportData []byte) error {
	key := append([]byte("workreport:sr:"), segmentRoot[:]...)
	return set(batch, key, workReportData)
}

// SetWorkReportIndex stores a work package hash -> segment root mapping
func SetWorkReportIndex(batch *pebble.Batch, workPackageHash [32]byte, segmentRoot [32]byte) error {
	key := append([]byte("workreport:wph:"), workPackageHash[:]...)
	return set(batch, key, segmentRoot[:])
}

// GetWorkReportBySegmentRoot retrieves a work report by segment root
func GetWorkReportBySegmentRoot(batch *pebble.Batch, segmentRoot [32]byte) ([]byte, bool, error) {
	key := append([]byte("workreport:sr:"), segmentRoot[:]...)
	value, closer, err := get(batch, key)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// GetWorkReportIndex retrieves segment root by work package hash
func GetWorkReportIndex(batch *pebble.Batch, workPackageHash [32]byte) ([]byte, bool, error) {
	key := append([]byte("workreport:wph:"), workPackageHash[:]...)
	value, closer, err := get(batch, key)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// addWorkReportPrefix adds the "workreport:" prefix to a key
func addWorkReportPrefix(key []byte) []byte {
	return append([]byte("workreport:"), key...)
}

func addTreeNodePrefix(key []byte) []byte {
	return append([]byte("tree:node:"), key...)
}

func treeRootPrefix() []byte {
	return []byte("tree:root")
}

// GetStateRoot retrieves the current Merkle root
func GetStateRoot(batch *pebble.Batch) ([32]byte, error) {
	rootData, closer, err := get(batch, treeRootPrefix())
	if err == pebble.ErrNotFound {
		return [32]byte{}, nil // Empty tree
	}
	if err != nil {
		return [32]byte{}, err
	}
	defer closer.Close()

	var root [32]byte
	copy(root[:], rootData)
	return root, nil
}

// updateMerkleTreeForSet updates the Merkle tree for a set operation
func updateMerkleTreeForSet(batch *pebble.Batch, key [31]byte, value []byte) error {
	return upsertLeaf(batch, key, value)
}

// upsertLeaf inserts or updates a leaf node and returns the new root hash
func upsertLeaf(batch *pebble.Batch, key [31]byte, value []byte) error {
	_, err := upsertLeafHelper(batch, key, value, []byte{})
	if err != nil {
		return fmt.Errorf("failed to upsert leaf: %w", err)
	}
	return nil
}

// upsertLeafHelper recursively inserts a leaf node starting from curNode at given depth
func upsertLeafHelper(batch *pebble.Batch, key [31]byte, value []byte, path []byte) (*Node, error) {
	fmt.Printf("=== HELPER at depth %d: leafKey=%x ===\n",
		len(path), key[:8])

	curNode, err := GetTreeNode(batch, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree node: %w", err)
	}

	if curNode == nil {
		keyBits := keyToBits(key)
		newLeafPath := keyBits[len(path):]
		newLeaf := &Node{
			Hash:           calculateLeafHash(key, value),
			Value:          value,
			OriginalKey:    key,
			CompressedPath: newLeafPath,
		}
		if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(newLeaf)); err != nil {
			return nil, fmt.Errorf("failed to store new leaf: %w", err)
		}
		return newLeaf, nil
	}

	matchLength := 0
	for i, bit := range curNode.CompressedPath {
		idx := len(path) + i
		byteIndex := idx / 8
		bitPos := 7 - (idx % 8)
		if (key[byteIndex]>>bitPos)&1 != bit {
			break
		}
		matchLength++
	}

	if matchLength == len(curNode.CompressedPath) {

		childPath := append(path, curNode.CompressedPath...)

		if len(childPath) == 248 {
			// Case 1: This is a leaf node - update the value
			if curNode.OriginalKey == key {
				fmt.Printf("SAME KEY: updating value\n")
				updatedLeaf := &Node{
					Hash:           calculateLeafHash(key, value),
					Value:          value,
					OriginalKey:    key,
					CompressedPath: curNode.CompressedPath,
				}
				if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(updatedLeaf)); err != nil {
					return nil, fmt.Errorf("failed to store updated leaf: %w", err)
				}
				return updatedLeaf, nil
			} else {
				// Different key but same compressed path - this shouldn't happen in a proper Patricia tree
				return nil, fmt.Errorf("key mismatch in leaf node")
			}
		} else {
			// Case 2: This is an internal node - continue navigation
			// Calculate the next bit in the key after the compressed path
			nextBitIndex := len(path) + len(curNode.CompressedPath)
			if nextBitIndex >= 248 { // 31 bytes * 8 bits
				return nil, fmt.Errorf("key too long")
			}

			byteIndex := nextBitIndex / 8
			bitPos := 7 - (nextBitIndex % 8)
			nextBit := (key[byteIndex] >> bitPos) & 1

			// Recursively insert into the child
			newChild, err := upsertLeafHelper(batch, key, value, append(childPath, nextBit))
			if err != nil {
				return nil, err
			}

			// Update this internal node's hash (child changed)
			var leftHash, rightHash [32]byte
			if nextBit == 0 {
				leftHash = newChild.Hash
				// Get right child hash
				rightChildPath := append(path, curNode.CompressedPath...)
				rightChildPath = append(rightChildPath, 1)
				rightChild, err := GetTreeNode(batch, rightChildPath)
				if err == nil && rightChild != nil {
					rightHash = rightChild.Hash
				}
			} else {
				rightHash = newChild.Hash
				// Get left child hash
				leftChildPath := append(path, curNode.CompressedPath...)
				leftChildPath = append(leftChildPath, 0)
				leftChild, err := GetTreeNode(batch, leftChildPath)
				if err == nil && leftChild != nil {
					leftHash = leftChild.Hash
				}
			}

			updatedInternal := &Node{
				Hash:           calculateInternalNodeHash(leftHash, rightHash),
				Value:          []byte{},
				OriginalKey:    [31]byte{},
				CompressedPath: curNode.CompressedPath,
			}

			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(updatedInternal)); err != nil {
				return nil, fmt.Errorf("failed to store updated internal node: %w", err)
			}

			return updatedInternal, nil
		}
	} else {
		// PARTIAL MATCH - need to split the compressed path
		fmt.Printf("SPLITTING: matchLength=%d, compressedPath=%v\n", matchLength, curNode.CompressedPath)

		// Modify current node to have the remaining compressed path
		splitBitIndex := len(path) + matchLength
		existingNodeBit := curNode.CompressedPath[matchLength]

		modifiedExistingNode := &Node{
			Hash:           curNode.Hash, // Keep original hash for now
			Value:          curNode.Value,
			OriginalKey:    curNode.OriginalKey,
			CompressedPath: curNode.CompressedPath[matchLength+1:], // Skip the split bit
		}

		// Store the cur node at its new position
		existingChildPath := append(path, curNode.CompressedPath[:matchLength]...)
		existingChildPath = append(existingChildPath, existingNodeBit)

		if err := set(batch, addTreeNodePrefix(existingChildPath), serializer.Serialize(modifiedExistingNode)); err != nil {
			return nil, fmt.Errorf("failed to store modified existing node: %w", err)
		}

		// Create new leaf node with remaining key bits
		keyBits := keyToBits(key)
		newLeafPath := keyBits[splitBitIndex+1:] // Skip the split bit

		newLeaf := &Node{
			Hash:           calculateLeafHash(key, value),
			Value:          value,
			OriginalKey:    key,
			CompressedPath: newLeafPath,
		}

		newLeafChildPath := append(path, curNode.CompressedPath[:matchLength]...)
		newLeafChildPath = append(newLeafChildPath, 1-existingNodeBit)

		if err := set(batch, addTreeNodePrefix(newLeafChildPath), serializer.Serialize(newLeaf)); err != nil {
			return nil, fmt.Errorf("failed to store new leaf: %w", err)
		}

		// Calculate internal node hash
		var leftHash, rightHash [32]byte
		if existingNodeBit == 0 {
			leftHash = modifiedExistingNode.Hash
			rightHash = newLeaf.Hash
		} else {
			leftHash = newLeaf.Hash
			rightHash = modifiedExistingNode.Hash
		}

		// Create new internal node with the matching prefix
		newInternal := &Node{
			Hash:           calculateInternalNodeHash(leftHash, rightHash),
			Value:          []byte{},
			OriginalKey:    [31]byte{},
			CompressedPath: curNode.CompressedPath[:matchLength],
		}

		// Store the new internal node
		if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(newInternal)); err != nil {
			return nil, fmt.Errorf("failed to store new internal node: %w", err)
		}

		return newInternal, nil
	}
}

// updateMerkleTreeForDelete updates the Merkle tree for a delete operation
func updateMerkleTreeForDelete(batch *pebble.Batch, key [31]byte) error {
	return nil
}

// calculateLeafHash computes hash for a leaf node
func calculateLeafHash(key [31]byte, value []byte) [32]byte {
	buf := make([]byte, 64)
	if len(value) <= 32 {
		maskedSize := uint8(len(value)) & 0x3F // Keep only lower 6 bits
		buf[0] = 0x80 | maskedSize
		copy(buf[1:32], key[:])
		copy(buf[32:], value)
	} else {
		buf[0] = 0xC0
		copy(buf[1:32], key[:])
		valueHash := blake2b.Sum256(value)
		copy(buf[32:], valueHash[:])
	}
	return blake2b.Sum256(buf)
}

// calculateInternalNodeHash computes hash for internal nodes
func calculateInternalNodeHash(leftHash, rightHash [32]byte) [32]byte {
	var nodeData [64]byte
	leftHash[0] &= 0x7F // Clear first bit (set to 0)
	copy(nodeData[:32], leftHash[:])
	copy(nodeData[32:], rightHash[:])
	return blake2b.Sum256(nodeData[:])
}

// keyToBits converts a [31]byte key to a slice of bytes where each byte represents a single bit (0 or 1)
// This creates a 248-bit representation (31 bytes * 8 bits per byte)
func keyToBits(key [31]byte) []byte {
	bits := make([]byte, 248) // 31 bytes * 8 bits per byte

	for byteIndex := 0; byteIndex < 31; byteIndex++ {
		for bitPos := 0; bitPos < 8; bitPos++ {
			bitIndex := byteIndex*8 + bitPos
			// Extract bit at position (7-bitPos) from the byte
			bit := (key[byteIndex] >> (7 - bitPos)) & 1
			bits[bitIndex] = bit
		}
	}

	return bits
}
