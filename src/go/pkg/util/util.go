package util

func OctetArrayZeroPadding(x []byte, n int) []byte {
	length := len(x)
	paddingSize := (n - (length % n)) % n
	result := make([]byte, length+paddingSize)
	copy(result, x)
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
		wrappedIdx := (startIdx + i) % len(slice)
		if wrappedIdx < 0 {
			wrappedIdx += len(slice)
		}
		result[i] = slice[wrappedIdx]
	}

	return result
}

func SliceToArray32(b []byte) [32]byte {
	var arr [32]byte
	copy(arr[:], b)
	return arr
}
