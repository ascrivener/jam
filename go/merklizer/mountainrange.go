package merklizer

// MMRNode represents a node in the Merkle Mountain Range
// nil value represents an empty node
type MMRNode *[32]byte

// MMRRange is the Merkle Mountain Range structure
// a slice of optional nodes (nil means empty)
type MMRRange []MMRNode

// DeepCopy creates a completely new copy of an MMRRange with new memory allocations
func (r MMRRange) DeepCopy() MMRRange {
	if r == nil {
		return nil
	}

	result := make(MMRRange, len(r))
	for i, node := range r {
		if node != nil {
			// Create a new [32]byte and copy the data
			newNode := new([32]byte)
			copy(newNode[:], node[:])
			result[i] = newNode
		}
	}
	return result
}

// Append (function A in the formula) adds a new item to the MMR
// r: the current MMR range
// l: the leaf to append
// hash: hash function
func Append(r MMRRange, l [32]byte, hash func([]byte) [32]byte) MMRRange {
	return appendHelper(r, l, 0, hash)
}

// appendHelper (function P in the formula) is the recursive helper for Append
func appendHelper(r MMRRange, l [32]byte, n int, hash func([]byte) [32]byte) MMRRange {
	// Case 1: n ≥ |r| - we've gone past the end, append l
	if n >= len(r) {
		return append(r, &l)
	}

	// Case 2: n < |r| and r[n] is empty - place l at position n
	if r[n] == nil {
		replaceAtIndex(r, n, &l)
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

	// Recursive call
	return appendHelper(r, hashedValue, n+1, hash)
}

func replaceAtIndex[T any](r []T, idx int, value T) {
	r[idx] = value
}
