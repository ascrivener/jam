package util

func OctetArrayZeroPadding(x []byte, n int) []byte {
	// Original length
	length := len(x)

	// Calculate padding size: ((length+n-1) mod n) + 1...n
	// This ensures the result length is a multiple of n
	paddingSize := (n - (length % n)) % n

	// Create the result slice with appropriate capacity
	result := make([]byte, length+paddingSize)

	// Copy the original data
	copy(result, x)

	// The padding bytes are already zeros (Go initializes byte slices with zeros)

	return result
}

// GetWrappedValues returns values from a slice for a range of indices
// with wrapping (modular access) for indices that exceed slice bounds
func GetWrappedValues[T any](slice []T, startIdx, endIdx int) []T {
	if len(slice) == 0 {
		return []T{}
	}

	count := endIdx - startIdx
	if count <= 0 {
		return []T{}
	}

	result := make([]T, count)

	for i := 0; i < count; i++ {
		// Calculate the wrapped index
		wrappedIdx := (startIdx + i) % len(slice)
		// Handle negative indices
		if wrappedIdx < 0 {
			wrappedIdx += len(slice)
		}

		result[i] = slice[wrappedIdx]
	}

	return result
}
