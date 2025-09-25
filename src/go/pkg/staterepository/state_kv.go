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
	Hash        [32]byte
	Value       []byte   // Non-empty for leaf nodes, empty for internal nodes
	OriginalKey [31]byte // Only used for leaf nodes
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

// createLeafNode creates a new leaf node
func createLeafNode(originalKey [31]byte, value []byte) *Node {
	hash := calculateLeafHash(originalKey, value)
	return &Node{
		Hash:        hash,
		Value:       value, // Can be empty slice []byte{}
		OriginalKey: originalKey,
	}
}

// createInternalNode creates a new internal node
func createInternalNode(leftHash, rightHash [32]byte) *Node {
	hash := calculateInternalNodeHash(leftHash, rightHash)
	return &Node{
		Hash:        hash,
		Value:       []byte{},
		OriginalKey: [31]byte{},
	}
}

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
	return upsertLeaf(batch, createLeafNode(key, value))
}

// upsertLeaf inserts or updates a leaf node and returns the new root hash
func upsertLeaf(batch *pebble.Batch, leafNode *Node) error {
	rootNode, err := GetTreeNode(batch, []byte{})
	if err != nil {
		return fmt.Errorf("failed to get tree root node: %w", err)
	}
	_, err = upsertLeafHelper(batch, rootNode, leafNode, []byte{})
	if err != nil {
		return fmt.Errorf("failed to upsert leaf: %w", err)
	}
	return nil
}

// upsertLeafHelper recursively inserts a leaf node starting from curNode at given depth
func upsertLeafHelper(batch *pebble.Batch, curNode, leafNode *Node, path []byte) (*Node, error) {
	fmt.Printf("=== HELPER at depth %d: leafKey=%x ===\n",
		len(path), leafNode.OriginalKey[:8])

	// Base case: empty tree or reached max depth
	if curNode == nil {
		// Empty tree - just place our leaf
		fmt.Printf("EMPTY TREE: placing leaf at depth %d\n", len(path))

		if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(leafNode)); err != nil {
			return nil, fmt.Errorf("failed to store leaf node: %w", err)
		}

		return leafNode, nil
	}

	leftNode, err := GetTreeNode(batch, append(path, 0))
	if err != nil {
		return nil, fmt.Errorf("failed to get left node: %w", err)
	}

	rightNode, err := GetTreeNode(batch, append(path, 1))
	if err != nil {
		return nil, fmt.Errorf("failed to get right node: %w", err)
	}

	if leftNode == nil && rightNode == nil {
		if curNode.OriginalKey == leafNode.OriginalKey {
			fmt.Printf("SAME KEY: updating value\n")
			// Same key - just update the value
			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(leafNode)); err != nil {
				return nil, fmt.Errorf("failed to store updated leaf: %w", err)
			}

			return leafNode, nil
		}

		byteIndex := len(path) / 8
		bitPos := 7 - (len(path) % 8)
		bit := (curNode.OriginalKey[byteIndex] >> bitPos) & 1

		if err := set(batch, addTreeNodePrefix(append(path, bit)), serializer.Serialize(curNode)); err != nil {
			return nil, fmt.Errorf("failed to store new leaf: %w", err)
		}

		if bit == 0 {
			leftNode = curNode
		} else {
			rightNode = curNode
		}
	}

	// Get the bit at current depth for the new leaf
	byteIndex := len(path) / 8
	bitPos := 7 - (len(path) % 8)
	bit := (leafNode.OriginalKey[byteIndex] >> bitPos) & 1

	var newLeftHash, newRightHash [32]byte
	if bit == 0 {
		// Go left
		newLeft, err := upsertLeafHelper(batch, leftNode, leafNode, append(path, 0))
		if err != nil {
			return nil, err
		}
		newLeftHash = newLeft.Hash
		if rightNode != nil {
			newRightHash = rightNode.Hash
		}
	} else {
		// Go right
		newRight, err := upsertLeafHelper(batch, rightNode, leafNode, append(path, 1))
		if err != nil {
			return nil, err
		}
		newRightHash = newRight.Hash
		if leftNode != nil {
			newLeftHash = leftNode.Hash
		}
	}

	// Create new internal node with updated child
	newInternalNode := createInternalNode(newLeftHash, newRightHash)

	if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(newInternalNode)); err != nil {
		return nil, fmt.Errorf("failed to store new internal node: %w", err)
	}

	return newInternalNode, nil
}

// updateMerkleTreeForDelete updates the Merkle tree for a delete operation
func updateMerkleTreeForDelete(batch *pebble.Batch, key [31]byte) error {
	// For deletion, we need to recalculate the path without this leaf
	return updateTreePath(batch, key, [32]byte{}, 247) // Start at deepest bit
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
