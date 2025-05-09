package merklizer

import (
	"bytes"
)

func node(blobs [][]byte, hash func([]byte) [32]byte) []byte {
	if len(blobs) == 0 {
		return make([]byte, 32) // Creates a zero-filled byte slice of length 32
	}
	if len(blobs) == 1 {
		return blobs[0]
	}
	// Split at midpoint (ceiling of length/2)
	mid := (len(blobs) + 1) / 2

	// Process left half
	leftHalf := node(blobs[:mid], hash)

	// Process right half
	rightHalf := node(blobs[mid:], hash)

	// Concatenate prefix with both halves and hash
	var buffer bytes.Buffer
	buffer.Write([]byte("$node")) // Add $node prefix
	buffer.Write(leftHalf)        // Add N(v...⌈∣v∣/2⌉, H)
	buffer.Write(rightHalf)       // Add N(v⌈∣v∣/2⌉..., H)

	// Hash the result: H($node ⌢ N(left) ⌢ N(right))
	hashResult := hash(buffer.Bytes())

	// Convert [32]byte to []byte
	return hashResult[:]
}

func trace(blobs [][]byte, index int, hash func([]byte) [32]byte) [][]byte {
	// Base case: if there's only one or zero blobs, return empty proof
	if len(blobs) <= 1 {
		return [][]byte{}
	}

	// Calculate the midpoint (ceiling of length/2)
	mid := (len(blobs) + 1) / 2

	// Determine which half contains our index
	if index < mid {
		// Index is in the left half
		// Need to include right half node in the proof
		rightHalf := node(blobs[mid:], hash)

		// Recursively trace the left half, keeping the same index
		subTrace := trace(blobs[:mid], index, hash)

		// Return the right half node concatenated with the sub-trace
		return append([][]byte{rightHalf}, subTrace...)
	} else {
		// Index is in the right half
		// Need to include left half node in the proof
		leftHalf := node(blobs[:mid], hash)

		// Recursively trace the right half, adjusting the index
		subTrace := trace(blobs[mid:], index-mid, hash)

		// Return the left half node concatenated with the sub-trace
		return append([][]byte{leftHalf}, subTrace...)
	}
}

func WellBalancedBinaryMerkle(blobs [][]byte, hash func([]byte) [32]byte) [32]byte {
	if len(blobs) == 1 {
		return hash(blobs[0])
	}
	return [32]byte(node(blobs, hash))
}
