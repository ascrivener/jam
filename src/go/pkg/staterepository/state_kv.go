package staterepository

import (
	"bytes"
	"fmt"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/blake2b"
)

type Node struct {
	Hash        [32]byte
	OriginalKey [31]byte
	LeftHash    [32]byte // For internal nodes
	RightHash   [32]byte // For internal nodes
}

func (n *Node) IsLeaf() bool {
	return n.LeftHash == [32]byte{} && n.RightHash == [32]byte{}
}

// createInternalNodeWithBit calculates the bit, recursively inserts, and creates an internal node
func createInternalNodeWithBit(tx *TrackedTx, curNode *Node, key [31]byte, value []byte, path []byte) (*Node, error) {
	// Recursively insert and get child hashes
	leftHash, rightHash, err := recursiveInsertAndGetHashes(tx, curNode, key, value, path)
	if err != nil {
		return nil, err
	}

	// Create internal node
	internalNode := &Node{
		Hash:        calculateInternalNodeHash(leftHash, rightHash),
		OriginalKey: [31]byte{},
		LeftHash:    leftHash,
		RightHash:   rightHash,
	}

	if err := SetTreeNodeData(tx, path, serializer.Serialize(internalNode)); err != nil {
		return nil, fmt.Errorf("failed to store internal node: %w", err)
	}

	return internalNode, nil
}

// upsertLeafHelper recursively inserts a leaf node starting from curNode at given depth
func upsertLeafHelper(tx *TrackedTx, key [31]byte, value []byte, path []byte) (*Node, error) {

	curNode, exists, err := GetTreeNode(tx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree node: %w", err)
	}
	if !exists {
		newLeaf := &Node{
			Hash:        calculateLeafHash(key, value),
			OriginalKey: key,
			LeftHash:    [32]byte{},
			RightHash:   [32]byte{},
		}
		if err := SetTreeNodeData(tx, path, serializer.Serialize(newLeaf)); err != nil {
			return nil, fmt.Errorf("failed to store new leaf: %w", err)
		}
		return newLeaf, nil
	}

	// Check if current node is a leaf (has value) or internal (no value)
	if curNode.IsLeaf() {
		// Current node is a LEAF
		if curNode.OriginalKey == key {
			curNode.Hash = calculateLeafHash(key, value)
			if err := SetTreeNodeData(tx, path, serializer.Serialize(curNode)); err != nil {
				return nil, fmt.Errorf("failed to store updated leaf: %w", err)
			}
			return curNode, nil
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
		if err := SetTreeNodeData(tx, existingNewPath, serializer.Serialize(curNode)); err != nil {
			return nil, fmt.Errorf("failed to move existing leaf: %w", err)
		}
	}
	result, err := createInternalNodeWithBit(tx, curNode, key, value, path)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deleteLeafHelper recursively deletes a leaf node and cleans up the tree
func deleteLeafHelper(tx *TrackedTx, key [31]byte, path []byte) error {
	curNode, exists, err := GetTreeNode(tx, path)
	if err != nil {
		return fmt.Errorf("failed to get tree node: %w", err)
	}

	if !exists {
		// Key doesn't exist - nothing to delete
		return nil
	}

	// Check if current node is a leaf (has value) or internal (no value)
	if curNode.IsLeaf() {
		// Current node is a LEAF
		if curNode.OriginalKey == key {
			// Found the key to delete - remove this node
			if err := DeleteTreeNodeData(tx, path); err != nil {
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
		err := deleteLeafHelper(tx, key, append(path, nextBit))
		if err != nil {
			return err
		}

		// Get both children to see if we need to clean up this internal node
		var leftChild, rightChild *Node

		leftChild, leftExists, err := GetTreeNode(tx, append(path, 0))
		if err != nil {
			return fmt.Errorf("failed to get left child: %w", err)
		}

		rightChild, rightExists, err := GetTreeNode(tx, append(path, 1))
		if err != nil {
			return fmt.Errorf("failed to get right child: %w", err)
		}

		// Smart cleanup: only collapse if exactly one child exists AND it's a leaf
		if !leftExists && !rightExists {
			// No children left - delete this internal node
			if err := DeleteTreeNodeData(tx, path); err != nil {
				return fmt.Errorf("failed to delete empty internal node: %w", err)
			}
			return nil
		} else if !leftExists && rightExists && rightChild.IsLeaf() {
			// Only right child exists AND it's a leaf - collapse
			if err := SetTreeNodeData(tx, path, serializer.Serialize(rightChild)); err != nil {
				return fmt.Errorf("failed to move right leaf up: %w", err)
			}
			// Delete the old right child position
			if err := DeleteTreeNodeData(tx, append(path, 1)); err != nil {
				return fmt.Errorf("failed to delete old right child: %w", err)
			}
			return nil
		} else if !rightExists && leftExists && leftChild.IsLeaf() {
			// Only left child exists AND it's a leaf - collapse
			if err := SetTreeNodeData(tx, path, serializer.Serialize(leftChild)); err != nil {
				return fmt.Errorf("failed to move left leaf up: %w", err)
			}
			// Delete the old left child position
			if err := DeleteTreeNodeData(tx, append(path, 0)); err != nil {
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

			curNode.Hash = calculateInternalNodeHash(leftHash, rightHash)
			curNode.LeftHash = leftHash
			curNode.RightHash = rightHash

			if err := SetTreeNodeData(tx, path, serializer.Serialize(curNode)); err != nil {
				return fmt.Errorf("failed to update internal node: %w", err)
			}

			return nil
		}
	}
}

// updateMerkleTreeForSet updates the Merkle tree for a set operation
func updateMerkleTreeForSet(tx *TrackedTx, key [31]byte, value []byte) error {
	return upsertLeaf(tx, key, value)
}

// upsertLeaf inserts or updates a leaf node and returns the new root hash
func upsertLeaf(tx *TrackedTx, key [31]byte, value []byte) error {
	_, err := upsertLeafHelper(tx, key, value, []byte{})
	if err != nil {
		return fmt.Errorf("failed to upsert leaf: %w", err)
	}
	return nil
}

// updateMerkleTreeForDelete updates the Merkle tree for a delete operation
func updateMerkleTreeForDelete(tx *TrackedTx, key [31]byte) error {
	err := deleteLeafHelper(tx, key, []byte{})
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

func recursiveInsertAndGetHashes(tx *TrackedTx, curNode *Node, key [31]byte, value []byte, path []byte) ([32]byte, [32]byte, error) {
	// Get the next bit to determine which child to follow
	byteIndex := len(path) / 8
	bitPos := 7 - (len(path) % 8)
	bit := (key[byteIndex] >> bitPos) & 1
	newChild, err := upsertLeafHelper(tx, key, value, append(path, bit))
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}

	var leftHash, rightHash [32]byte

	// Check if curNode was originally a leaf (being split) or internal node (being updated)
	if curNode.IsLeaf() {
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

func GetStateKV(tx *TrackedTx, key [31]byte) ([]byte, bool, error) {
	if tx.memoryMode {
		if value, exists := tx.memWrites[key]; exists {
			if value == nil {
				return nil, false, nil // Deleted
			}
			return value, true, nil // Set
		}
	}
	return getKV(tx, "state", key[:])
}

func SetStateKV(tx *TrackedTx, key [31]byte, value []byte) error {
	tx.memWrites[key] = value
	return nil
}

func DeleteStateKV(tx *TrackedTx, key [31]byte) error {
	tx.memWrites[key] = nil
	return nil
}

func normalizeTreePath(path []byte) []byte {
	// Use special key for empty path (root node)
	if len(path) == 0 {
		return []byte("ROOT")
	}
	return path
}

func GetTreeNodeData(tx *TrackedTx, path []byte) ([]byte, bool, error) {
	return getKV(tx, "tree", normalizeTreePath(path))
}

func SetTreeNodeData(tx *TrackedTx, path []byte, value []byte) error {
	return setKV(tx, "tree", normalizeTreePath(path), value)
}

func DeleteTreeNodeData(tx *TrackedTx, path []byte) error {
	return deleteKV(tx, "tree", normalizeTreePath(path))
}

func GetBlockKV(tx *TrackedTx, key [32]byte) ([]byte, bool, error) {
	return getKV(tx, "blocks", key[:])
}

func SetBlockKV(tx *TrackedTx, key [32]byte, value []byte) error {
	return setKV(tx, "blocks", key[:], value)
}

func DeleteBlockKV(tx *TrackedTx, key []byte) error {
	return deleteKV(tx, "blocks", key)
}

func GetTip(tx *TrackedTx) ([32]byte, error) {
	value, exists, err := getKV(tx, "meta", []byte("chaintip"))
	if err != nil {
		return [32]byte{}, err
	}
	if !exists {
		return [32]byte{}, fmt.Errorf("chain tip not found")
	}
	var tip [32]byte
	copy(tip[:], value)
	return tip, nil
}

func SetTip(tx *TrackedTx, tip [32]byte) error {
	return setKV(tx, "meta", []byte("chaintip"), tip[:])
}

func GetPreimage(tx *TrackedTx, hash [32]byte) ([]byte, bool, error) {
	return getKV(tx, "preimage", hash[:])
}

func SetPreimage(tx *TrackedTx, hash [32]byte, preimage []byte) error {
	return setKV(tx, "preimage", hash[:], preimage)
}

func DeletePreimage(tx *TrackedTx, hash [32]byte) error {
	return deleteKV(tx, "preimage", hash[:])
}

func GetWorkReport(tx *TrackedTx, key []byte) ([]byte, bool, error) {
	return getKV(tx, "workreport", key)
}

func SetWorkReport(tx *TrackedTx, key []byte, value []byte) error {
	return setKV(tx, "workreport", key, value)
}

func DeleteWorkReport(tx *TrackedTx, key []byte) error {
	return deleteKV(tx, "workreport", key)
}

func getKV(tx *TrackedTx, bucketName string, key []byte) ([]byte, bool, error) {
	if tx == nil {
		return nil, false, fmt.Errorf("transaction cannot be nil")
	}
	bucket := tx.Bucket([]byte(bucketName))
	if bucket == nil {
		return nil, false, fmt.Errorf("%s bucket not found", bucketName)
	}
	val := bucket.Get(key)
	if val == nil {
		return nil, false, nil // Key not found
	}
	// Make a copy since BoltDB values are only valid during transaction
	dataCopy := make([]byte, len(val))
	copy(dataCopy, val)
	return dataCopy, true, nil
}

func setKV(tx *TrackedTx, bucketName string, key, value []byte) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}
	bucket := tx.Bucket([]byte(bucketName))
	if bucket == nil {
		return fmt.Errorf("%s bucket not found", bucketName)
	}
	return bucket.Put(key, value)
}

func deleteKV(tx *TrackedTx, bucketName string, key []byte) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}
	bucket := tx.Bucket([]byte(bucketName))
	if bucket == nil {
		return fmt.Errorf("%s bucket not found", bucketName)
	}
	return bucket.Delete(key)
}

// TrackedTx wraps bolt.Tx and tracks state changes
type TrackedTx struct {
	*bolt.Tx
	memWrites  map[[31]byte][]byte
	memoryMode bool
}

// Snapshot represents metadata for a state snapshot
type Snapshot struct {
	BlockHash [32]byte
	StateRoot [32]byte
}

// NewTrackedTx creates a new tracked transaction wrapper
func NewTrackedTx() (*TrackedTx, error) {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil, fmt.Errorf("global repository not initialized")
	}
	tx, err := repo.db.Begin(true) // writable transaction
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	return &TrackedTx{
		Tx:         tx,
		memWrites:  make(map[[31]byte][]byte),
		memoryMode: false,
	}, nil
}

// GetStateChanges returns all tracked state changes
func (t *TrackedTx) GetStateChanges() map[[31]byte][]byte {
	return t.memWrites
}

func (t *TrackedTx) SetMemoryMode(mode bool) {
	t.memoryMode = mode
}

func (tx *TrackedTx) CreateChild() *TrackedTx {
	child := &TrackedTx{
		Tx:         tx.Tx,
		memWrites:  make(map[[31]byte][]byte),
		memoryMode: true,
	}

	// Copy parent state
	for key, value := range tx.memWrites {
		if value == nil {
			child.memWrites[key] = nil // Copy delete
		} else {
			child.memWrites[key] = append([]byte{}, value...) // Copy value
		}
	}

	return child
}

func (tx *TrackedTx) Apply(childTx *TrackedTx) error {
	if childTx == nil {
		return fmt.Errorf("child transaction cannot be nil")
	}

	// Merge all changes from child into parent
	for key, value := range childTx.memWrites {
		if value == nil {
			tx.memWrites[key] = nil // Copy delete operation
		} else {
			// Copy the value to avoid shared references
			tx.memWrites[key] = append([]byte{}, value...)
		}
	}

	return nil
}

// SetServiceAccount stores service account data
func SetServiceAccount(tx *TrackedTx, serviceIndex types.ServiceIndex, data []byte) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return SetStateKV(tx, dbKey, data)
}

// DeleteServiceAccount deletes a service account
func DeleteServiceAccount(tx *TrackedTx, serviceIndex types.ServiceIndex) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return DeleteStateKV(tx, dbKey)
}

// GetServiceStorageItem retrieves a service storage item with proper error handling
func GetServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey []byte) ([]byte, bool, error) {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return GetStateKV(tx, dbKey)
}

// SetServiceStorageItem stores a service storage item
func SetServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey, value []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return SetStateKV(tx, dbKey, value)
}

// DeleteServiceStorageItem deletes a service storage item
func DeleteServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return DeleteStateKV(tx, dbKey)
}

// GetServicePreimage retrieves a preimage for a given hash
func GetServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte) ([]byte, bool, error) {
	dbKey := makePreimageKey(serviceIndex, hash)
	return GetStateKV(tx, dbKey)
}

// SetServicePreimage stores a preimage for a given hash
func SetServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte, preimage []byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return SetStateKV(tx, dbKey, preimage)
}

// DeleteServicePreimage deletes a preimage for a given hash
func DeleteServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return DeleteStateKV(tx, dbKey)
}

// SetWorkReportBySegmentRoot stores a work report by segment root
func SetWorkReportBySegmentRoot(tx *TrackedTx, segmentRoot [32]byte, workReportData []byte) error {
	key := append([]byte("sr:"), segmentRoot[:]...)
	return setKV(tx, "workreport", key, workReportData)
}

// SetWorkReportIndex stores a work package hash -> segment root mapping
func SetWorkReportIndex(tx *TrackedTx, workPackageHash [32]byte, segmentRoot [32]byte) error {
	key := append([]byte("wph:"), workPackageHash[:]...)
	return setKV(tx, "workreport", key, segmentRoot[:])
}

// GetWorkReportBySegmentRoot retrieves a work report by segment root
func GetWorkReportBySegmentRoot(tx *TrackedTx, segmentRoot [32]byte) ([]byte, bool, error) {
	key := append([]byte("sr:"), segmentRoot[:]...)
	return getKV(tx, "workreport", key)
}

// GetWorkReportIndex retrieves segment root by work package hash
func GetWorkReportIndex(tx *TrackedTx, workPackageHash [32]byte) ([]byte, bool, error) {
	key := append([]byte("wph:"), workPackageHash[:]...)
	return getKV(tx, "workreport", key)
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func GetPreimageLookupHistoricalStatus(tx *TrackedTx, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	value, exists, err := GetStateKV(tx, dbKey)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}

	var status []types.Timeslot
	if err := serializer.Deserialize(value, &status); err != nil {
		return nil, false, err
	}
	return status, true, nil
}

// SetPreimageLookupHistoricalStatus stores historical status for a preimage lookup
func SetPreimageLookupHistoricalStatus(tx *TrackedTx, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	serializedStatus := serializer.Serialize(status)
	return SetStateKV(tx, dbKey, serializedStatus)
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func DeletePreimageLookupHistoricalStatus(tx *TrackedTx, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	return DeleteStateKV(tx, dbKey)
}

func GetTreeNode(tx *TrackedTx, path []byte) (*Node, bool, error) {
	value, exists, err := GetTreeNodeData(tx, path)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil // Node not found
	}

	var node Node
	if err := serializer.Deserialize(value, &node); err != nil {
		return nil, false, err
	}
	return &node, true, nil
}

// GetStateRoot retrieves the current Merkle root
func GetStateRoot(tx *TrackedTx) ([32]byte, error) {
	root, exists, err := GetTreeNode(tx, []byte{})
	if err != nil {
		return [32]byte{}, err
	}
	if !exists {
		return [32]byte{}, nil
	}
	return root.Hash, nil
}

// GetAllKeysFromTree extracts all keys from the tree by traversing leaf nodes
func GetAllKeysFromTree(tx *TrackedTx) ([][31]byte, error) {
	var keys [][31]byte

	// Get the tree bucket
	bucket := tx.Bucket([]byte("tree"))
	if bucket == nil {
		return keys, nil // Empty tree if bucket doesn't exist
	}

	// Create cursor to iterate through all key-value pairs in tree bucket
	cursor := bucket.Cursor()

	// Iterate through all tree nodes and collect leaves
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		// Make copies since BoltDB data is only valid during transaction
		path := make([]byte, len(k))
		copy(path, k)

		value := make([]byte, len(v))
		copy(value, v)

		node := &Node{}
		if err := serializer.Deserialize(value, node); err != nil {
			continue // Skip invalid nodes
		}

		// Only collect leaf nodes (nodes with values)
		if node.IsLeaf() {
			keys = append(keys, node.OriginalKey)
		}
	}

	return keys, nil
}

// IterOptions represents iteration options (simplified from Pebble)
type IterOptions struct {
	LowerBound []byte
	UpperBound []byte
}

type Iterator interface {
	First() ([]byte, []byte)
	Next() ([]byte, []byte)
	Valid() bool
	Close() error
}

// BoltIterator wraps bolt cursor for iteration
type BoltIterator struct {
	cursor     *bolt.Cursor
	bucket     *bolt.Bucket
	lowerBound []byte
	upperBound []byte
	valid      bool
}

func (iter *BoltIterator) First() ([]byte, []byte) {
	var k, v []byte
	if iter.lowerBound != nil {
		k, v = iter.cursor.Seek(iter.lowerBound)
		iter.valid = k != nil && (iter.upperBound == nil || bytes.Compare(k, iter.upperBound) < 0)
	} else {
		k, v = iter.cursor.First()
		iter.valid = k != nil
	}
	return k, v
}

func (iter *BoltIterator) Next() ([]byte, []byte) {
	k, v := iter.cursor.Next()
	iter.valid = k != nil && (iter.upperBound == nil || bytes.Compare(k, iter.upperBound) < 0)
	return k, v
}

func (iter *BoltIterator) Valid() bool {
	return iter.valid
}

func (iter *BoltIterator) Close() error {
	return nil // Bolt cursors don't need explicit closing
}

// NewIter creates a new iterator for the given bucket
func NewIter(tx *TrackedTx, bucketName string, opts *IterOptions) (Iterator, error) {
	bucket := tx.Bucket([]byte(bucketName))
	if bucket == nil {
		return nil, fmt.Errorf("%s bucket not found", bucketName)
	}

	cursor := bucket.Cursor()

	iter := &BoltIterator{
		cursor: cursor,
		bucket: bucket,
		valid:  false,
	}

	if opts != nil {
		iter.lowerBound = opts.LowerBound
		iter.upperBound = opts.UpperBound
	}

	return iter, nil
}

// PrintTreeStructure prints the entire tree structure for debugging
func PrintTreeStructure(tx *TrackedTx) error {
	fmt.Println("=== TREE STRUCTURE ===")

	// Get the tree bucket
	bucket := tx.Bucket([]byte("tree"))
	if bucket == nil {
		return nil // Empty tree if bucket doesn't exist
	}

	// Create cursor to iterate through all key-value pairs in tree bucket
	cursor := bucket.Cursor()

	// Collect all nodes first to sort by path
	type nodeInfo struct {
		path []byte
		node *Node
	}
	var nodes []nodeInfo

	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		// Make copies since BoltDB data is only valid during transaction
		path := make([]byte, len(k))
		copy(path, k)

		value := make([]byte, len(v))
		copy(value, v)

		node := &Node{}
		if err := serializer.Deserialize(value, node); err != nil {
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

		if node.IsLeaf() {
			// Leaf node
			fmt.Printf("%s%s: LEAF hash=%x key=%x\n",
				indent, pathStr, node.Hash[:8], node.OriginalKey[:8])
		} else {
			// Internal node
			fmt.Printf("%s%s: INTERNAL hash=%x\n",
				indent, pathStr, node.Hash[:8])
		}
	}

	fmt.Println("=== END TREE STRUCTURE ===")
	return nil
}

func ApplyMerkleTreeUpdates(trackedTx *TrackedTx) error {
	// Apply changes to Merkle tree in sequence
	for key, value := range trackedTx.memWrites {
		if value == nil {
			if err := deleteKV(trackedTx, "state", key[:]); err != nil {
				return fmt.Errorf("failed to delete state kv: %w", err)
			}
			if err := updateMerkleTreeForDelete(trackedTx, key); err != nil {
				return fmt.Errorf("failed to update merkle tree for delete: %w", err)
			}
		} else {
			if err := setKV(trackedTx, "state", key[:], value); err != nil {
				return fmt.Errorf("failed to set state kv for set: %w", err)
			}
			if err := updateMerkleTreeForSet(trackedTx, key, value); err != nil {
				return fmt.Errorf("failed to update merkle tree for set: %w", err)
			}
		}
	}

	return nil
}
