package merklizer

import "golang.org/x/crypto/sha3"

// MMRNode represents a node in the Merkle Mountain Range
// nil value represents an empty node
type MMRNode *[32]byte

// MMBelt is the Merkle Mountain Range structure
// a slice of optional nodes (nil means empty)
type MMBelt []MMRNode

// DeepCopy creates a completely new copy of an MMBelt with new memory allocations
func (r MMBelt) DeepCopy() MMBelt {
	if r == nil {
		return nil
	}

	result := make(MMBelt, len(r))
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

// Append (function A in the formula) adds a new item to the MMBelt
// r: the current MMBelt
// l: the leaf to append
// hash: hash function
func Append(r MMBelt, l [32]byte, hash func([]byte) [32]byte) MMBelt {
	return appendHelper(r, l, 0, hash)
}

// appendHelper (function P in the formula) is the recursive helper for Append
func appendHelper(r MMBelt, l [32]byte, n int, hash func([]byte) [32]byte) MMBelt {
	if n >= len(r) {
		return append(r, &l)
	}

	if r[n] == nil {
		replaceAtIndex(r, n, &l)
		return r
	}

	// Otherwise recurse with:
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

func Keccak256Hash(data []byte) [32]byte {
	var result [32]byte
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	sum := hash.Sum(nil)
	copy(result[:], sum[:])
	return result
}
