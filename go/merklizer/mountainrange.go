package merklizer

// MMRNode represents a node in the Merkle Mountain Range
// nil value represents an empty node
type MMRNode *[32]byte

// MMRRange is the Merkle Mountain Range structure
// a slice of optional nodes (nil means empty)
type MMRRange []MMRNode

// Append (function A in the formula) adds a new item to the MMR
// r: the current MMR range
// l: the leaf to append
// hash: hash function
func Append(r MMRRange, l *[32]byte, hash func([]byte) [32]byte) MMRRange {
	return appendHelper(r, l, 0, hash)
}

// appendHelper (function P in the formula) is the recursive helper for Append
func appendHelper(r MMRRange, l *[32]byte, n int, hash func([]byte) [32]byte) MMRRange {
	// Case 1: n ≥ |r| - we've gone past the end, append l
	if n >= len(r) {
		return append(r, l)
	}

	// Case 2: n < |r| and r[n] is empty - place l at position n
	if r[n] == nil {
		r[n] = l
		return r
	}

	// Case 3: otherwise recurse with:
	// - Hash of r[n] concat l
	// - n+1

	// Save the current node value
	currentNode := r[n]

	// Clear this position
	r[n] = nil

	// Concatenate the current node with l and hash
	var concatenated []byte
	concatenated = append(concatenated, currentNode[:]...)
	concatenated = append(concatenated, l[:]...)
	hashedValue := hash(concatenated)

	// Create a pointer to the hash result
	hashPtr := new([32]byte)
	copy(hashPtr[:], hashedValue[:])

	// Recursive call
	return appendHelper(r, hashPtr, n+1, hash)
}
