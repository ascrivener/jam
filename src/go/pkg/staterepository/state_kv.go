package staterepository

import (
	"bytes"
	"fmt"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"strings"
	"sync"

	"maps"

	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

type Node struct {
	OriginalKey   [31]byte
	OriginalValue []byte
	LeftHash      [32]byte // For internal nodes
	RightHash     [32]byte // For internal nodes
}

func (n *Node) IsLeaf() bool {
	return n.LeftHash == [32]byte{} && n.RightHash == [32]byte{}
}

func keysMatchAtDepth(key1, key2 [31]byte, depth int) bool {
	byteIndex := depth / 8
	bitIndex := 7 - (depth % 8)

	if byteIndex >= len(key1) || byteIndex >= len(key2) {
		return false
	}

	bit1 := (key1[byteIndex] >> bitIndex) & 1
	bit2 := (key2[byteIndex] >> bitIndex) & 1

	return bit1 == bit2
}

// createInternalNodeWithBit calculates the bit, recursively inserts, and creates an internal node
func createInternalNodeWithBit(tx *TrackedTx, curNode *Node, hash [32]byte, key [31]byte, value []byte, depth int) ([32]byte, error) {

	// Get key's bit at this depth
	byteIndex := depth / 8
	bitIndex := 7 - (depth % 8)
	keyBit := (key[byteIndex] >> bitIndex) & 1

	var leftHash, rightHash [32]byte
	var err error
	if keyBit == 0 {
		// New key goes left, collision goes right
		leftHash, err = upsertLeafHelper(tx, key, value, curNode.LeftHash, depth+1)
		if err != nil {
			return [32]byte{}, err
		}
		rightHash = curNode.RightHash
	} else {
		// New key goes right, collision goes left
		leftHash = curNode.LeftHash
		rightHash, err = upsertLeafHelper(tx, key, value, curNode.RightHash, depth+1)
		if err != nil {
			return [32]byte{}, err
		}
	}

	if leftHash == curNode.LeftHash && rightHash == curNode.RightHash {
		return hash, nil
	}

	// Create internal node
	internalNode := &Node{
		OriginalKey:   [31]byte{},
		OriginalValue: []byte{},
		LeftHash:      leftHash,
		RightHash:     rightHash,
	}
	internalNodeHash := calculateInternalNodeHash(leftHash, rightHash)

	setTreeNode(tx, internalNodeHash, internalNode)

	return internalNodeHash, nil
}

// splitLeafCollision creates internal nodes until keys diverge, then places both leaves
func splitLeafCollision(tx *TrackedTx, existingLeaf *Node, newKey [31]byte, newValue []byte, depth int) ([32]byte, error) {
	// Find where keys diverge
	divergeDepth := depth
	for keysMatchAtDepth(existingLeaf.OriginalKey, newKey, divergeDepth) {
		divergeDepth++
	}

	// Create new leaf
	newLeaf := &Node{
		OriginalKey:   newKey,
		OriginalValue: newValue,
		LeftHash:      [32]byte{},
		RightHash:     [32]byte{},
	}
	newLeafHash := calculateLeafHash(newKey, newValue)
	existingLeafHash := calculateLeafHash(existingLeaf.OriginalKey, existingLeaf.OriginalValue)

	// Store new leaf
	setTreeNode(tx, newLeafHash, newLeaf)

	var currentHash [32]byte

	// Work backwards from divergeDepth to depth, creating internal nodes
	for currentDepth := divergeDepth; currentDepth >= depth; currentDepth-- {
		pathByteIndex := currentDepth / 8
		pathBitIndex := 7 - (currentDepth % 8)
		pathBit := (newKey[pathByteIndex] >> pathBitIndex) & 1

		var leftHash, rightHash [32]byte
		if currentDepth == divergeDepth {
			// At diverge depth - place the leaves
			if pathBit == 0 {
				leftHash = newLeafHash
				rightHash = existingLeafHash
			} else {
				leftHash = existingLeafHash
				rightHash = newLeafHash
			}
		} else {
			// Above diverge depth - determine path direction
			if pathBit == 0 {
				leftHash = currentHash
				rightHash = [32]byte{}
			} else {
				leftHash = [32]byte{}
				rightHash = currentHash
			}
		}

		currentHash = calculateInternalNodeHash(leftHash, rightHash)
		internalNode := &Node{
			OriginalKey:   [31]byte{},
			OriginalValue: []byte{},
			LeftHash:      leftHash,
			RightHash:     rightHash,
		}

		setTreeNode(tx, currentHash, internalNode)
	}

	return currentHash, nil
}

func getLeafHelper(tx *TrackedTx, key [31]byte, hash [32]byte, depth int) ([]byte, bool, error) {
	curNode, exists, err := GetTreeNode(tx, hash)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get tree node: %w", err)
	}

	if !exists {
		return nil, false, nil
	}

	if curNode.IsLeaf() {
		if curNode.OriginalKey == key {
			return curNode.OriginalValue, true, nil
		}
		return nil, false, nil
	}

	// Internal node - follow the key's bit
	byteIndex := depth / 8
	bitIndex := 7 - (depth % 8)
	bit := (key[byteIndex] >> bitIndex) & 1

	if bit == 0 {
		return getLeafHelper(tx, key, curNode.LeftHash, depth+1)
	} else {
		return getLeafHelper(tx, key, curNode.RightHash, depth+1)
	}
}

// upsertLeafHelper recursively inserts a leaf node starting from curNode at given depth
func upsertLeafHelper(tx *TrackedTx, key [31]byte, value []byte, hash [32]byte, depth int) ([32]byte, error) {

	curNode, exists, err := GetTreeNode(tx, hash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to get tree node: %w", err)
	}

	if !exists {
		// Case 1: create new leaf
		newLeaf := &Node{
			OriginalKey:   key,
			OriginalValue: value,
			LeftHash:      [32]byte{},
			RightHash:     [32]byte{},
		}
		newHash := calculateLeafHash(key, value)
		setTreeNode(tx, newHash, newLeaf)
		return newHash, nil
	}
	if curNode.IsLeaf() {
		if curNode.OriginalKey == key {
			if bytes.Equal(curNode.OriginalValue, value) {
				return hash, nil
			}
			newLeaf := &Node{
				OriginalKey:   key,
				OriginalValue: value,
				LeftHash:      [32]byte{},
				RightHash:     [32]byte{},
			}
			newHash := calculateLeafHash(key, value)
			setTreeNode(tx, newHash, newLeaf)
			return newHash, nil
		}
		return splitLeafCollision(tx, curNode, key, value, depth)
	}

	newHash, err := createInternalNodeWithBit(tx, curNode, hash, key, value, depth)
	if err != nil {
		return [32]byte{}, err
	}
	return newHash, nil
}

// Phase 1: Find and delete the target node
func deleteLeafHelper(tx *TrackedTx, key [31]byte, hash [32]byte, depth int) ([32]byte, bool, error) {
	curNode, exists, err := GetTreeNode(tx, hash)
	if err != nil {
		return [32]byte{}, false, fmt.Errorf("failed to get tree node: %w", err)
	}

	if !exists {
		return [32]byte{}, false, nil
	}

	if curNode.IsLeaf() {
		if curNode.OriginalKey == key {
			return [32]byte{}, true, nil // Delete this leaf
		}
		return hash, false, nil
	}

	// Recurse to find the target
	byteIndex := depth / 8
	bitIndex := 7 - (depth % 8)
	bit := (key[byteIndex] >> bitIndex) & 1

	var leftHash, rightHash [32]byte

	if bit == 0 {
		newLeftHash, windup, err := deleteLeafHelper(tx, key, curNode.LeftHash, depth+1)
		if err != nil {
			return [32]byte{}, false, err
		}
		if windup {
			if curNode.RightHash == [32]byte{} {
				return newLeftHash, true, nil
			}
			if newLeftHash == [32]byte{} {
				rightNode, exists, err := GetTreeNode(tx, curNode.RightHash)
				if err != nil {
					return [32]byte{}, false, fmt.Errorf("failed to get right node: %w", err)
				}
				if !exists {
					return [32]byte{}, false, fmt.Errorf("right node does not exist")
				}
				if rightNode.IsLeaf() {
					return curNode.RightHash, true, nil
				}
			}
		}
		leftHash = newLeftHash
		rightHash = curNode.RightHash
	} else {
		newRightHash, windup, err := deleteLeafHelper(tx, key, curNode.RightHash, depth+1)
		if err != nil {
			return [32]byte{}, false, err
		}
		if windup {
			if curNode.LeftHash == [32]byte{} {
				return newRightHash, true, nil
			}
			if newRightHash == [32]byte{} {
				leftNode, exists, err := GetTreeNode(tx, curNode.LeftHash)
				if err != nil {
					return [32]byte{}, false, fmt.Errorf("failed to get left node: %w", err)
				}
				if !exists {
					return [32]byte{}, false, fmt.Errorf("left node does not exist")
				}
				if leftNode.IsLeaf() {
					return curNode.LeftHash, true, nil
				}
			}
		}
		leftHash = curNode.LeftHash
		rightHash = newRightHash
	}
	newInternalNode := &Node{
		OriginalKey:   [31]byte{},
		OriginalValue: []byte{},
		LeftHash:      leftHash,
		RightHash:     rightHash,
	}
	newInternalNodeHash := calculateInternalNodeHash(leftHash, rightHash)
	setTreeNode(tx, newInternalNodeHash, newInternalNode)
	return newInternalNodeHash, false, nil
}

func getLeaf(tx *TrackedTx, key [31]byte) ([]byte, bool, error) {
	return getLeafHelper(tx, key, tx.stateRoot, 0)
}

// upsertLeaf inserts or updates a leaf node and returns the new root hash
func UpsertLeaf(tx *TrackedTx, key [31]byte, value []byte) error {
	newStateRoot, err := upsertLeafHelper(tx, key, value, tx.stateRoot, 0)
	if err != nil {
		return fmt.Errorf("failed to upsert leaf: %w", err)
	}
	tx.stateRoot = newStateRoot
	return nil
}

// updateMerkleTreeForDelete updates the Merkle tree for a delete operation
func DeleteLeaf(tx *TrackedTx, key [31]byte) error {
	newStateRoot, _, err := deleteLeafHelper(tx, key, tx.stateRoot, 0)
	if err != nil {
		return fmt.Errorf("failed to delete leaf: %w", err)
	}
	tx.stateRoot = newStateRoot
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

func GetStateKV(tx *TrackedTx, key [31]byte) ([]byte, bool, error) {
	value, exists := tx.memory[key]
	if exists {
		if value == nil {
			return nil, false, nil // Explicitly deleted
		}
		return value, true, nil
	}
	return getLeaf(tx, key)
}

func SetStateKV(tx *TrackedTx, key [31]byte, value []byte) {
	tx.memory[key] = value
}

func DeleteStateKV(tx *TrackedTx, key [31]byte) {
	tx.memory[key] = nil
}

func setTreeNode(tx *TrackedTx, hash [32]byte, value *Node) {
	tx.treeNodes[hash] = value
}

func SetTreeNodeDB(tx *TrackedTx, hash [32]byte, value *Node) error {
	return setKV(tx, "tree", hash[:], serializer.Serialize(value))
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

	repo := GetGlobalRepository()
	if repo == nil {
		return nil, false, fmt.Errorf("global repository not initialized")
	}

	// Create prefixed key: "bucketName:key"
	prefixedKey := append([]byte(bucketName+":"), key...)

	val, closer, err := repo.db.Get(prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil // Key not found
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since Pebble values are only valid until closer.Close()
	dataCopy := make([]byte, len(val))
	copy(dataCopy, val)
	return dataCopy, true, nil
}

func setKV(tx *TrackedTx, bucketName string, key, value []byte) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	prefixedKey := append([]byte(bucketName+":"), key...)

	return tx.batch.Set(prefixedKey, value, &pebble.WriteOptions{Sync: false})
}

func deleteKV(tx *TrackedTx, bucketName string, key []byte) error {
	if tx == nil {
		return fmt.Errorf("transaction cannot be nil")
	}

	prefixedKey := append([]byte(bucketName+":"), key...)

	return tx.batch.Delete(prefixedKey, nil)
}

// TrackedTx wraps pebble.Batch and tracks state changes
type TrackedTx struct {
	batch     *pebble.Batch
	stateRoot [32]byte
	memory    map[[31]byte][]byte
	treeNodes map[[32]byte]*Node
}

// NewTrackedTx creates a new tracked transaction wrapper
func NewTrackedTx(stateRoot [32]byte) (*TrackedTx, error) {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil, fmt.Errorf("global repository not initialized")
	}
	return &TrackedTx{
		batch:     repo.db.NewBatch(),
		stateRoot: stateRoot,
		memory:    make(map[[31]byte][]byte),
		treeNodes: make(map[[32]byte]*Node),
	}, nil
}

func (tx *TrackedTx) Close() error {
	return tx.batch.Close()
}

func (tx *TrackedTx) Commit() error {
	repo := GetGlobalRepository()
	if repo == nil {
		return fmt.Errorf("global repository not initialized")
	}
	return repo.db.Apply(tx.batch, nil)
}

func (tx *TrackedTx) GetStateRoot() [32]byte {
	return tx.stateRoot
}

func (tx *TrackedTx) SetStateRoot(stateRoot [32]byte) {
	tx.stateRoot = stateRoot
}

func (tx *TrackedTx) CreateChild() *TrackedTx {
	child := &TrackedTx{
		batch:     tx.batch,
		stateRoot: tx.stateRoot,
		memory:    make(map[[31]byte][]byte),
	}

	maps.Copy(child.memory, tx.memory)

	return child
}

func (tx *TrackedTx) Apply(childTx *TrackedTx) error {
	if childTx == nil {
		return fmt.Errorf("child transaction cannot be nil")
	}

	maps.Copy(tx.memory, childTx.memory)

	return nil
}

func (tx *TrackedTx) FlushMemoryToDB() error {
	for key, val := range tx.GetMemoryContents() {
		if val == nil {
			if err := DeleteLeaf(tx, key); err != nil {
				return err
			}
		} else {
			if err := UpsertLeaf(tx, key, val); err != nil {
				return err
			}
		}
	}

	// Prune unreachable tree nodes
	prunedTree := tx.PruneUnreachableNodes()

	for key, val := range prunedTree {
		if val == nil { // This should never happen
			return fmt.Errorf("pruned tree node is nil")
		} else {
			if err := SetTreeNodeDB(tx, key, val); err != nil {
				return err
			}
		}
	}

	return nil
}

func (tx *TrackedTx) GetMemoryContents() map[[31]byte][]byte {
	return tx.memory
}

func (tx *TrackedTx) PruneUnreachableNodes() map[[32]byte]*Node {
	reachable := make(map[[32]byte]bool)
	tx.markReachableNodes(tx.GetStateRoot(), reachable)

	// Remove unreachable nodes from treeNodes map
	for hash := range tx.treeNodes {
		if !reachable[hash] {
			delete(tx.treeNodes, hash)
		}
	}

	return tx.treeNodes
}

func (tx *TrackedTx) markReachableNodes(hash [32]byte, reachable map[[32]byte]bool) {
	if reachable[hash] {
		return
	}
	if node, exists := tx.treeNodes[hash]; exists {
		reachable[hash] = true
		if node.LeftHash != ([32]byte{}) {
			tx.markReachableNodes(node.LeftHash, reachable)
		}
		if node.RightHash != ([32]byte{}) {
			tx.markReachableNodes(node.RightHash, reachable)
		}
	}
}

func GetServiceAccount(tx *TrackedTx, serviceIndex types.ServiceIndex) ([]byte, bool, error) {
	return GetStateKV(tx, stateKeyConstructorFromServiceIndex(serviceIndex))
}

// SetServiceAccount stores service account data
func SetServiceAccount(tx *TrackedTx, serviceIndex types.ServiceIndex, data []byte) {
	SetStateKV(tx, stateKeyConstructorFromServiceIndex(serviceIndex), data)
}

// DeleteServiceAccount deletes a service account
func DeleteServiceAccount(tx *TrackedTx, serviceIndex types.ServiceIndex) {
	DeleteStateKV(tx, stateKeyConstructorFromServiceIndex(serviceIndex))
}

// GetServiceStorageItem retrieves a service storage item with proper error handling
func GetServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey []byte) ([]byte, bool, error) {
	return GetStateKV(tx, makeServiceStorageKey(serviceIndex, storageKey))
}

// SetServiceStorageItem stores a service storage item
func SetServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey, value []byte) {
	SetStateKV(tx, makeServiceStorageKey(serviceIndex, storageKey), value)
}

// DeleteServiceStorageItem deletes a service storage item
func DeleteServiceStorageItem(tx *TrackedTx, serviceIndex types.ServiceIndex, storageKey []byte) {
	DeleteStateKV(tx, makeServiceStorageKey(serviceIndex, storageKey))
}

// GetServicePreimage retrieves a preimage for a given hash
func GetServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte) ([]byte, bool, error) {
	return GetStateKV(tx, makePreimageKey(serviceIndex, hash))
}

// SetServicePreimage stores a preimage for a given hash
func SetServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte, preimage []byte) {
	SetStateKV(tx, makePreimageKey(serviceIndex, hash), preimage)
}

// DeleteServicePreimage deletes a preimage for a given hash
func DeleteServicePreimage(tx *TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte) {
	DeleteStateKV(tx, makePreimageKey(serviceIndex, hash))
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
func SetPreimageLookupHistoricalStatus(tx *TrackedTx, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) {
	SetStateKV(tx, makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage), serializer.Serialize(status))
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func DeletePreimageLookupHistoricalStatus(tx *TrackedTx, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) {
	DeleteStateKV(tx, makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage))
}

var (
	globalTreeNodeCache = make(map[[32]byte]*Node)
	globalTreeNodeMutex sync.RWMutex
)

func GetTreeNode(tx *TrackedTx, hash [32]byte) (*Node, bool, error) {
	// 1. Check tx-level cache first
	if node, exists := tx.treeNodes[hash]; exists {
		return node, true, nil
	}

	// 2. Check global cache
	globalTreeNodeMutex.RLock()
	if node, exists := globalTreeNodeCache[hash]; exists {
		globalTreeNodeMutex.RUnlock()
		return node, true, nil
	}
	globalTreeNodeMutex.RUnlock()

	// 3. Load from database
	value, exists, err := getKV(tx, "tree", hash[:])
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}

	var node Node
	if err := serializer.Deserialize(value, &node); err != nil {
		return nil, false, err
	}

	// 4. Cache at both levels
	globalTreeNodeMutex.Lock()
	globalTreeNodeCache[hash] = &node
	globalTreeNodeMutex.Unlock()

	return &node, true, nil
}

// GetAllKeysFromTree extracts all keys from the tree by traversing leaf nodes
func GetAllKeysFromTree(tx *TrackedTx) ([][31]byte, error) {
	var keys [][31]byte

	repo := GetGlobalRepository()
	if repo == nil {
		return keys, fmt.Errorf("global repository not initialized")
	}

	// Create iterator for "tree:" prefixed keys
	prefix := []byte("tree:")
	iter, err := repo.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: append(prefix, 0xff), // End of "tree:" range
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	// Iterate through all tree nodes and collect leaves
	for iter.First(); iter.Valid(); iter.Next() {
		// Make copies since Pebble data is only valid during iteration
		key := make([]byte, len(iter.Key()))
		copy(key, iter.Key())

		value := make([]byte, len(iter.Value()))
		copy(value, iter.Value())

		node := &Node{}
		if err := serializer.Deserialize(value, node); err != nil {
			continue // Skip invalid nodes
		}

		// Only collect leaf nodes (nodes with values)
		if node.IsLeaf() {
			keys = append(keys, node.OriginalKey)
		}
	}

	return keys, iter.Error()
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

func PrintTreeStructure(tx *TrackedTx) error {
	fmt.Println("=== TREE STRUCTURE ===")

	if tx.stateRoot == [32]byte{} {
		fmt.Println("Empty tree (no state root)")
		return nil
	}

	return printNodeRecursive(tx, tx.stateRoot, 0, "ROOT")
}

// PrintTreeStructure prints the entire tree structure for debugging
func printNodeRecursive(tx *TrackedTx, hash [32]byte, depth int, pathStr string) error {
	if hash == [32]byte{} {
		return nil // Empty child
	}

	node, exists, err := GetTreeNode(tx, hash)
	if err != nil {
		return fmt.Errorf("failed to get node: %w", err)
	}

	if !exists {
		fmt.Printf("%sNOT FOUND: hash=%x\n", strings.Repeat("  ", depth), hash[:8])
		return nil
	}

	indent := strings.Repeat("  ", depth)

	if node.IsLeaf() {
		fmt.Printf("%s%s: LEAF hash=%x key=%x value=%x\n",
			indent, pathStr, hash[:8], node.OriginalKey[:8], node.OriginalValue[:8])
	} else {
		fmt.Printf("%s%s: INTERNAL hash=%x\n",
			indent, pathStr, hash[:8])

		// Recursively print children
		if err := printNodeRecursive(tx, node.LeftHash, depth+1, pathStr+"0"); err != nil {
			return err
		}
		if err := printNodeRecursive(tx, node.RightHash, depth+1, pathStr+"1"); err != nil {
			return err
		}
	}

	return nil
}
