package staterepository

import (
	"bytes"
	"fmt"
	"io"
	"jam/pkg/serializer"
	"jam/pkg/types"

	"strings"

	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

type Node struct {
	Hash        [32]byte
	Value       []byte
	OriginalKey [31]byte
	LeftHash    [32]byte // For internal nodes
	RightHash   [32]byte // For internal nodes
}

type StateKV struct {
	Key   [31]byte
	Value []byte
}

func GetTreeNode(batch *pebble.Batch, path []byte) (*Node, error) {
	prefixedKey := addTreeNodePrefix(path)
	value, closer, err := get(batch, prefixedKey)
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

// createInternalNodeWithBit calculates the bit, recursively inserts, and creates an internal node
func createInternalNodeWithBit(batch *pebble.Batch, curNode *Node, key [31]byte, value []byte, path []byte) (*Node, error) {
	// Recursively insert and get child hashes
	leftHash, rightHash, err := recursiveInsertAndGetHashes(batch, curNode, key, value, path)
	if err != nil {
		return nil, err
	}

	// Create internal node
	internalNode := &Node{
		Hash:        calculateInternalNodeHash(leftHash, rightHash),
		Value:       []byte{},
		OriginalKey: [31]byte{},
		LeftHash:    leftHash,
		RightHash:   rightHash,
	}

	if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(internalNode)); err != nil {
		return nil, fmt.Errorf("failed to store internal node: %w", err)
	}

	return internalNode, nil
}

// upsertLeafHelper recursively inserts a leaf node starting from curNode at given depth
func upsertLeafHelper(batch *pebble.Batch, key [31]byte, value []byte, path []byte) (*Node, error) {

	curNode, err := GetTreeNode(batch, path)
	if err != nil && err != pebble.ErrNotFound {
		return nil, fmt.Errorf("failed to get tree node: %w", err)
	}

	if curNode == nil {
		newLeaf := &Node{
			Hash:        calculateLeafHash(key, value),
			Value:       value,
			OriginalKey: key,
			LeftHash:    [32]byte{},
			RightHash:   [32]byte{},
		}
		if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(newLeaf)); err != nil {
			return nil, fmt.Errorf("failed to store new leaf: %w", err)
		}
		return newLeaf, nil
	}

	// Check if current node is a leaf (has value) or internal (no value)
	if curNode.RightHash == [32]byte{} && curNode.LeftHash == [32]byte{} {
		// Current node is a LEAF
		if curNode.OriginalKey == key {
			// Case A: Key matches - update value
			updatedLeaf := &Node{
				Hash:        calculateLeafHash(key, value),
				Value:       value,
				OriginalKey: key,
				LeftHash:    [32]byte{},
				RightHash:   [32]byte{},
			}
			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(updatedLeaf)); err != nil {
				return nil, fmt.Errorf("failed to store updated leaf: %w", err)
			}
			return updatedLeaf, nil
		}
		// Case B: Key doesn't match - need to create internal node and split
		// This happens when two different keys end up at the same path
		// We need to create an internal node and continue deeper

		// Find the next bit where the keys differ
		if len(path) >= 248 {
			return nil, fmt.Errorf("path too deep")
		}

		// Get the next bit for existing key for split
		byteIndex := len(path) / 8
		bitPos := 7 - (len(path) % 8)
		existingBit := (curNode.OriginalKey[byteIndex] >> bitPos) & 1

		// Move existing leaf to its proper position based on its bit
		existingNewPath := append(path, existingBit)
		if err := set(batch, addTreeNodePrefix(existingNewPath), serializer.Serialize(curNode)); err != nil {
			return nil, fmt.Errorf("failed to move existing leaf: %w", err)
		}
	}
	result, err := createInternalNodeWithBit(batch, curNode, key, value, path)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deleteLeafHelper recursively deletes a leaf node and cleans up the tree
func deleteLeafHelper(batch *pebble.Batch, key [31]byte, path []byte) error {
	curNode, err := GetTreeNode(batch, path)
	if err != nil && err != pebble.ErrNotFound {
		return fmt.Errorf("failed to get tree node: %w", err)
	}

	if curNode == nil {
		// Key doesn't exist - nothing to delete
		return nil
	}

	// Check if current node is a leaf (has value) or internal (no value)
	if curNode.RightHash == [32]byte{} && curNode.LeftHash == [32]byte{} {
		// Current node is a LEAF
		if curNode.OriginalKey == key {
			// Found the key to delete - remove this node
			if err := delete(batch, addTreeNodePrefix(path)); err != nil {
				return fmt.Errorf("failed to delete leaf node: %w", err)
			}
			return nil
		} else {
			// Different key - nothing to delete
			return nil
		}
	} else {
		// Current node is INTERNAL - recurse to appropriate child
		if len(path) >= 248 {
			return fmt.Errorf("path too deep")
		}

		// Get the next bit to determine which child to follow
		byteIndex := len(path) / 8
		bitPos := 7 - (len(path) % 8)
		nextBit := (key[byteIndex] >> bitPos) & 1

		// Recursively delete from the appropriate child
		err := deleteLeafHelper(batch, key, append(path, nextBit))
		if err != nil {
			return err
		}

		// Get both children to see if we need to clean up this internal node
		var leftChild, rightChild *Node

		leftChild, err = GetTreeNode(batch, append(path, 0))
		if err != nil && err != pebble.ErrNotFound {
			return fmt.Errorf("failed to get left child: %w", err)
		}

		rightChild, err = GetTreeNode(batch, append(path, 1))
		if err != nil && err != pebble.ErrNotFound {
			return fmt.Errorf("failed to get right child: %w", err)
		}

		// Smart cleanup: only collapse if exactly one child exists AND it's a leaf
		if leftChild == nil && rightChild == nil {
			// No children left - delete this internal node
			if err := delete(batch, addTreeNodePrefix(path)); err != nil {
				return fmt.Errorf("failed to delete empty internal node: %w", err)
			}
			return nil
		} else if leftChild == nil && rightChild != nil && len(rightChild.Value) > 0 {
			// Only right child exists AND it's a leaf - collapse
			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(rightChild)); err != nil {
				return fmt.Errorf("failed to move right leaf up: %w", err)
			}
			// Delete the old right child position
			if err := delete(batch, addTreeNodePrefix(append(path, 1))); err != nil {
				return fmt.Errorf("failed to delete old right child: %w", err)
			}
			return nil
		} else if rightChild == nil && leftChild != nil && len(leftChild.Value) > 0 {
			// Only left child exists AND it's a leaf - collapse
			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(leftChild)); err != nil {
				return fmt.Errorf("failed to move left leaf up: %w", err)
			}
			// Delete the old left child position
			if err := delete(batch, addTreeNodePrefix(append(path, 0))); err != nil {
				return fmt.Errorf("failed to delete old left child: %w", err)
			}
			return nil
		} else {
			// Either both children exist, or single child is internal - update hash
			var leftHash, rightHash [32]byte
			if leftChild != nil {
				leftHash = leftChild.Hash
			}
			if rightChild != nil {
				rightHash = rightChild.Hash
			}

			updatedInternal := &Node{
				Hash:        calculateInternalNodeHash(leftHash, rightHash),
				Value:       []byte{},
				OriginalKey: [31]byte{},
				LeftHash:    leftHash,
				RightHash:   rightHash,
			}

			if err := set(batch, addTreeNodePrefix(path), serializer.Serialize(updatedInternal)); err != nil {
				return fmt.Errorf("failed to update internal node: %w", err)
			}

			return nil
		}
	}
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

// updateMerkleTreeForDelete updates the Merkle tree for a delete operation
func updateMerkleTreeForDelete(batch *pebble.Batch, key [31]byte) error {
	err := deleteLeafHelper(batch, key, []byte{})
	if err != nil {
		return fmt.Errorf("failed to delete leaf: %w", err)
	}
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

// calculateInternalNodeHash computes hash for internal nodes with compressed path support
func calculateInternalNodeHash(leftHash, rightHash [32]byte) [32]byte {
	var nodeData [64]byte
	leftHash[0] &= 0x7F // Clear first bit (set to 0)
	copy(nodeData[:32], leftHash[:])
	copy(nodeData[32:], rightHash[:])
	return blake2b.Sum256(nodeData[:])
}

func recursiveInsertAndGetHashes(batch *pebble.Batch, curNode *Node, key [31]byte, value []byte, path []byte) ([32]byte, [32]byte, error) {
	// Get the next bit to determine which child to follow
	byteIndex := len(path) / 8
	bitPos := 7 - (len(path) % 8)
	bit := (key[byteIndex] >> bitPos) & 1
	newChild, err := upsertLeafHelper(batch, key, value, append(path, bit))
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	var leftHash, rightHash [32]byte

	// Check if curNode was originally a leaf (being split) or internal node (being updated)
	if curNode.RightHash == [32]byte{} && curNode.LeftHash == [32]byte{} {
		// curNode was a leaf that's being split
		// Get the existing leaf's bit at this position
		existingBit := (curNode.OriginalKey[byteIndex] >> bitPos) & 1

		if bit == existingBit {
			// Both keys go to the same child - other child is empty (zero hash)
			if bit == 0 {
				leftHash = newChild.Hash
				rightHash = [32]byte{} // Empty
			} else {
				rightHash = newChild.Hash
				leftHash = [32]byte{} // Empty
			}
		} else {
			// Keys go to different children - sibling is the existing leaf
			if bit == 0 {
				leftHash = newChild.Hash
				rightHash = curNode.Hash // Existing leaf
			} else {
				rightHash = newChild.Hash
				leftHash = curNode.Hash // Existing leaf
			}
		}
	} else {
		// curNode was already an internal node - can use stored child hashes
		if bit == 0 {
			leftHash = newChild.Hash
			rightHash = curNode.RightHash
		} else {
			rightHash = newChild.Hash
			leftHash = curNode.LeftHash
		}
	}

	return leftHash, rightHash, nil
}

func GetStateKV(batch *pebble.Batch, key [31]byte) ([]byte, error) {
	val, closer, err := get(batch, addStatePrefix(key))
	if err != nil {
		return nil, err
	}
	defer closer.Close()

	// Make a copy of the data since it's only valid until closer.Close()
	dataCopy := make([]byte, len(val))
	copy(dataCopy, val)

	return dataCopy, nil
}

func SetStateKV(batch *pebble.Batch, key [31]byte, value []byte) error {
	return set(batch, addStatePrefix(key), value)
}

func DeleteStateKV(batch *pebble.Batch, key [31]byte) error {
	return delete(batch, addStatePrefix(key))
}

// Exists checks if a key exists
func ExistsStateKV(batch *pebble.Batch, key [31]byte) (bool, error) {
	_, err := GetStateKV(batch, key)
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
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
	value, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

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
	value, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

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
	value, err := GetStateKV(batch, dbKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

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
	return append([]byte("tree:"), key...)
}

// GetStateRoot retrieves the current Merkle root
func GetStateRoot(batch *pebble.Batch) ([32]byte, error) {
	root, err := GetTreeNode(batch, []byte{})
	if err != nil {
		return [32]byte{}, err
	}
	return root.Hash, nil
}

// GetAllKVsFromTree extracts all key-value pairs from the tree by traversing leaf nodes
func GetAllKVsFromTree(batch *pebble.Batch) ([]StateKV, error) {
	var kvs []StateKV

	// Create iterator for all tree nodes
	iter, err := NewIter(batch, &pebble.IterOptions{
		LowerBound: []byte("tree:"),
		UpperBound: []byte("tree;"), // Next ASCII character after ':'
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create tree iterator: %w", err)
	}
	defer iter.Close()

	// Iterate through all tree nodes and collect leaves
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		// Remove "tree:" prefix to get path and make a copy to avoid iterator memory reuse
		pathSlice := key[5:] // len("tree:") = 5
		path := make([]byte, len(pathSlice))
		copy(path, pathSlice)

		nodeData := iter.Value()
		node := &Node{}
		if err := serializer.Deserialize(nodeData, node); err != nil {
			continue // Skip invalid nodes
		}

		// Only collect leaf nodes (nodes with values)
		if len(node.Value) > 0 {
			kvs = append(kvs, StateKV{
				Key:   node.OriginalKey,
				Value: node.Value,
			})
		}
	}

	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterator error: %w", err)
	}

	return kvs, nil
}

// PrintTreeStructure prints the entire tree structure for debugging
func PrintTreeStructure(batch *pebble.Batch) error {
	fmt.Println("=== TREE STRUCTURE ===")

	// Create iterator for all tree nodes
	iter, err := NewIter(batch, &pebble.IterOptions{
		LowerBound: []byte("tree:"),
		UpperBound: []byte("tree;"), // Next ASCII character after ':'
	})
	if err != nil {
		return fmt.Errorf("failed to create tree iterator: %w", err)
	}
	defer iter.Close()

	// Collect all nodes first to sort by path
	type nodeInfo struct {
		path []byte
		node *Node
	}
	var nodes []nodeInfo

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		// Remove "tree:" prefix to get path and make a copy to avoid iterator memory reuse
		pathSlice := key[5:] // len("tree:") = 5
		path := make([]byte, len(pathSlice))
		copy(path, pathSlice)

		nodeData := iter.Value()
		node := &Node{}
		if err := serializer.Deserialize(nodeData, node); err != nil {
			fmt.Printf("ERROR deserializing node at path %x: %v\n", path, err)
			continue
		}

		nodes = append(nodes, nodeInfo{path: path, node: node})
	}

	// Sort nodes by path length (root first, then by path)
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if len(nodes[i].path) > len(nodes[j].path) ||
				(len(nodes[i].path) == len(nodes[j].path) && string(nodes[i].path) > string(nodes[j].path)) {
				nodes[i], nodes[j] = nodes[j], nodes[i]
			}
		}
	}

	// Print each node
	for _, nodeInfo := range nodes {
		path := nodeInfo.path
		node := nodeInfo.node

		indent := strings.Repeat("  ", len(path))
		var pathStr string
		if len(path) == 0 {
			pathStr = "ROOT"
		} else {
			// Convert binary path to bit string (0s and 1s)
			pathStr = ""
			for _, b := range path {
				if b == 0 {
					pathStr += "0"
				} else {
					pathStr += "1"
				}
			}
		}

		if len(node.Value) > 0 {
			// Leaf node
			fmt.Printf("%s%s: LEAF hash=%x key=%x value=%x\n",
				indent, pathStr, node.Hash[:8], node.OriginalKey[:8], node.Value[:min(8, len(node.Value))])
		} else {
			// Internal node
			fmt.Printf("%s%s: INTERNAL hash=%x\n",
				indent, pathStr, node.Hash[:8])
		}
	}

	fmt.Println("=== END TREE STRUCTURE ===")
	return nil
}

func ApplyMerkleTreeUpdates(batch *pebble.Batch) error {
	repr := batch.Repr()
	reader, count := pebble.ReadBatch(repr)

	if count == 0 {
		return nil // Return if batch is empty
	}

	statePrefix := []byte("state:")

	// Track final operation per key (last-writer-wins) and process in single pass
	finalOps := make(map[string]struct {
		kind  pebble.InternalKeyKind
		key   [31]byte
		value []byte
	})

	// First pass: identify final operations
	for {
		kind, key, value, ok, err := reader.Next()
		if err != nil {
			return fmt.Errorf("failed to read batch operation: %w", err)
		}
		if !ok {
			break // No more operations
		}

		// Only process state operations
		if !bytes.HasPrefix(key, statePrefix) {
			continue // Skip non-state operations
		}

		// Extract the actual state key (remove "state:" prefix)
		if len(key) < 6 {
			return fmt.Errorf("invalid state key length: %d", len(key))
		}
		stateKeyBytes := key[6:] // Remove "state:" prefix (6 bytes)
		if len(stateKeyBytes) != 31 {
			return fmt.Errorf("invalid state key length after prefix removal: expected 31, got %d", len(stateKeyBytes))
		}

		var stateKey [31]byte
		copy(stateKey[:], stateKeyBytes)

		keyStr := string(key)
		finalOps[keyStr] = struct {
			kind  pebble.InternalKeyKind
			key   [31]byte
			value []byte
		}{
			kind:  kind,
			key:   stateKey,
			value: append([]byte{}, value...), // Copy value
		}
	}

	// Second pass: apply Merkle tree updates for final operations only
	for _, op := range finalOps {
		switch op.kind {
		case pebble.InternalKeyKindSet:
			if err := updateMerkleTreeForSet(batch, op.key, op.value); err != nil {
				return fmt.Errorf("failed to update Merkle tree for set: %w", err)
			}
		case pebble.InternalKeyKindDelete:
			if err := updateMerkleTreeForDelete(batch, op.key); err != nil {
				return fmt.Errorf("failed to update Merkle tree for delete: %w", err)
			}
		default:
			return fmt.Errorf("unsupported operation type: %d", op.kind)
		}
	}

	return nil
}
