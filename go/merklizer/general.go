package merklizer

import (
	"bytes"
	"math/bits"

	"github.com/ascrivener/jam/constants"
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
	buffer.Write([]byte("node")) // Add $node prefix
	buffer.Write(leftHalf)       // Add N(v...⌈∣v∣/2⌉, H)
	buffer.Write(rightHalf)      // Add N(v⌈∣v∣/2⌉..., H)

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

// (E.4)
func constantDepthBinaryMerkleFn(blobs [][]byte, hash func([]byte) [32]byte) [32]byte {
	constancyHashes := constancyPreprocessor(blobs, hash)
	return [32]byte(node(hashSliceToByteSlice(constancyHashes), hash))
}

// (E.5)
func pageJustification(blobs [][]byte, height, index int, hashFn func([]byte) [32]byte) [][32]byte {
	constancyHashes := constancyPreprocessor(blobs, hashFn)
	traceSlice := trace(hashSliceToByteSlice(constancyHashes), index<<height, hashFn)[:calcRemainingHeight(len(constancyHashes), height)]
	return byteSliceToHashSlice(traceSlice)
}

// calcRemainingHeight computes max(0, ⌈log2(max(1,|v|))−x⌉)
func calcRemainingHeight(blobsLen, height int) int {
	// max(1, |v|)
	maxLen := blobsLen
	if maxLen < 1 {
		maxLen = 1
	}

	// For 0 and 1, log2 ceiling is 0
	if maxLen <= 1 {
		return 0
	}

	// bits.Len(uint(n)) returns the minimum number of bits required to represent n,
	// which equals floor(log2(n)) + 1 for n > 0
	// For any value m, bits.Len(m-1) equals ceiling(log2(m)) when m > 1
	log2Ceil := bits.Len(uint(maxLen - 1))

	return max(0, log2Ceil-height)
}

// (E.6)
func leavesPage(blobs [][]byte, height, index int, hashFn func([]byte) [32]byte) [][32]byte {
	startIdx := index << height
	endIdx := min(startIdx+(1<<height), len(blobs))
	leaves := make([][32]byte, endIdx-startIdx)
	for i := startIdx; i < endIdx; i++ {
		leaves[i-startIdx] = hashFn(append([]byte("leaf"), blobs[i]...))
	}
	return leaves
}

// (E.7)
func constancyPreprocessor(blobs [][]byte, hash func([]byte) [32]byte) [][32]byte {
	hashes := make([][32]byte, nextPowerOfTwo(len(blobs)))
	for i := range hashes {
		if i < len(blobs) {
			hashes[i] = hash(append([]byte("leaf"), blobs[i]...))
		} else {
			hashes[i] = [32]byte{}
		}
	}
	return hashes
}

func nextPowerOfTwo(n int) int {
	// If n is already a power of 2, return it
	if n > 0 && (n&(n-1)) == 0 {
		return n
	}

	// Find the position of the most significant bit
	power := 1
	for power < n {
		power <<= 1
	}

	return power
}

func WellBalancedBinaryMerkle(blobs [][]byte, hash func([]byte) [32]byte) [32]byte {
	if len(blobs) == 1 {
		return hash(blobs[0])
	}
	return [32]byte(node(blobs, hash))
}

func MMRSuperPeak(mmrRange MMRRange) [32]byte {
	nonNullBelt := make([][32]byte, 0)
	for _, node := range mmrRange {
		if node != nil {
			nonNullBelt = append(nonNullBelt, *node)
		}
	}
	return mmrSuperPeakHelper(nonNullBelt)
}

func mmrSuperPeakHelper(blobs [][32]byte) [32]byte {
	if len(blobs) == 0 {
		return [32]byte{}
	}
	if len(blobs) == 1 {
		return blobs[0]
	}
	var buffer bytes.Buffer
	buffer.Write([]byte("peak"))
	mmrSuperPeak := mmrSuperPeakHelper(blobs[:len(blobs)-1])
	buffer.Write(mmrSuperPeak[:])
	buffer.Write(blobs[len(blobs)-1][:])
	return Keccak256Hash(buffer.Bytes())
}

func PagedProofsFromSegments(segments [][constants.SegmentSize]byte) [][constants.SegmentSize]byte {
	return segments
}

func JustificationFromProofPage(proofPage [constants.SegmentSize]byte, segmentIndex uint16, segment [constants.SegmentSize]byte, erasureRoot [32]byte) ([][32]byte, bool) {
	return [][32]byte{}, false
}

func hashSliceToByteSlice(fixed [][32]byte) [][]byte {
	result := make([][]byte, len(fixed))
	for i, f := range fixed {
		result[i] = f[:]
	}
	return result
}

func byteSliceToHashSlice(bytes [][]byte) [][32]byte {
	result := make([][32]byte, len(bytes))
	for i, b := range bytes {
		copy(result[i][:], b)
	}
	return result
}
