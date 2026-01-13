package bitsequence

import (
	"fmt"
	"math/bits"

	"jam/pkg/constants"
)

// BitSequence represents a sequence of bits stored in a []byte.
// The bits are packed in LSB-first order within each byte (i.e. bit 0 is stored in the least significant bit).
type BitSequence struct {
	buf    []byte // underlying byte slice
	bitLen int    // number of bits stored in the sequence
}

// FromBytesLSBWithLength creates a new BitSequence with a specific bit length,
// reading bits from least significant (bit 0) to most significant (bit 7) within each byte.
// It verifies that the provided byte slice is the correct size for the requested bit length,
// and that all bits beyond the specified length are zeros.
func FromBytesLSBWithLength(b []byte, bitLen int) (*BitSequence, error) {
	requiredBytes := (bitLen + 7) / 8 // Ceiling division to determine required bytes
	if len(b) != requiredBytes {
		return nil, fmt.Errorf("bit length %d requires exactly %d bytes, got %d", bitLen, requiredBytes, len(b))
	}

	// Check that all bits beyond the bitLen are zeros (if there are any partial bytes)
	if remainingBits := bitLen % 8; remainingBits > 0 {
		lastByte := b[len(b)-1]
		// Create a mask for the unused bits in the last byte (the higher bits)
		// For example, if remainingBits=3, mask would be 11111000 (binary)
		mask := byte(0xFF << remainingBits)
		if (lastByte & mask) != 0 {
			return nil, fmt.Errorf("invalid bit sequence: bits beyond position %d must be zeros", bitLen-1)
		}
	}

	// Store bytes directly in LSB order - no conversion needed
	buf := make([]byte, requiredBytes)
	copy(buf, b)

	return &BitSequence{
		buf:    buf,
		bitLen: bitLen,
	}, nil
}

// BitAt returns the bit at position i (0-indexed).
// It panics if i is out of range.
func (bs *BitSequence) BitAt(i int) bool {
	byteIndex := i >> 3
	bitPos := i & 7
	return (bs.buf[byteIndex] & (1 << uint(bitPos))) != 0
}

// Len returns the total number of bits in the sequence.
func (bs *BitSequence) Len() int {
	return bs.bitLen
}

// CountOnes returns the number of 1 bits in the sequence.
// It uses Go's built-in bits.OnesCount8 for optimal performance.
func (bs *BitSequence) CountOnes() int {
	count := 0
	fullBytes := bs.bitLen / 8

	// Count full bytes using bits.OnesCount8
	for i := 0; i < fullBytes; i++ {
		count += bits.OnesCount8(bs.buf[i])
	}

	// Handle remaining bits in the last partial byte
	if remainingBits := bs.bitLen % 8; remainingBits > 0 {
		lastByte := bs.buf[fullBytes]
		mask := byte((1 << remainingBits) - 1)
		count += bits.OnesCount8(lastByte & mask)
	}

	return count
}

// CoreBitMask represents a fixed-length array of bits.
// It wraps a BitSequence and enforces a constant length.
type CoreBitMask struct {
	bs *BitSequence
}

func (ba *CoreBitMask) Len() int {
	return ba.bs.Len()
}

// BitAt returns the bit at position i (0-indexed).
// It panics if i is out of range.
func (ba *CoreBitMask) BitAt(i int) bool {
	return ba.bs.BitAt(i)
}

// CoreBitMaskFromBytesLSB creates a new CoreBitMask from a byte slice,
// reading bits from least significant (bit 0) to most significant (bit 7) within each byte.
// It verifies that the provided byte slice is the correct size for the requested bit length,
// and that all bits beyond the specified length are zeros.
func CoreBitMaskFromBytesLSB(b []byte) (*CoreBitMask, error) {
	// Use the existing BitSequence implementation to handle the conversion
	bs, err := FromBytesLSBWithLength(b, int(constants.NumCores))
	if err != nil {
		return nil, err
	}

	return &CoreBitMask{
		bs: bs,
	}, nil
}

func (cm *CoreBitMask) ToBytesLSB() []byte {
	return cm.bs.buf
}
