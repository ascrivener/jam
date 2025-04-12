package bitsequence

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// BitSequence represents a sequence of bits stored in a []byte.
// The bits are packed in big-endian order within each byte (i.e. bit 0 is stored in the most significant bit).
type BitSequence struct {
	buf    []byte // underlying byte slice
	bitLen int    // number of bits stored in the sequence
}

// New returns an empty BitSequence.
func New() *BitSequence {
	return &BitSequence{
		buf:    []byte{},
		bitLen: 0,
	}
}

// NewZeros creates a new BitSequence with n bits, all initialized to 0.
func NewZeros(n int) *BitSequence {
	if n < 0 {
		panic("NewZeros: negative bit length")
	}
	numBytes := (n + 7) / 8 // calculates how many bytes are needed to store n bits
	return &BitSequence{
		buf:    make([]byte, numBytes), // slice is zero-initialized
		bitLen: n,
	}
}

// FromBytes creates a new BitSequence initialized with the bits from the given []byte.
// The entire byte slice is appended (8 bits per byte) in order.
func FromBytes(b []byte) *BitSequence {
	bs := New()
	bs.AppendBytes(b)
	return bs
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

	bs := New()

	// Process all bits at once rather than splitting full bytes and remaining
	for i := 0; i < bitLen; i++ {
		byteIndex := i / 8
		bitPosition := i % 8
		bit := ((b[byteIndex] >> uint(bitPosition)) & 1) == 1
		bs.AppendBit(bit)
	}

	return bs, nil
}

// AppendBit appends a single bit (true for 1, false for 0) to the sequence.
func (bs *BitSequence) AppendBit(bit bool) {
	// If we're at a byte boundary, add a new byte.
	if bs.bitLen%8 == 0 {
		bs.buf = append(bs.buf, 0)
	}
	// Determine the bit position in the last byte.
	pos := 7 - (bs.bitLen % 8)
	if bit {
		bs.buf[len(bs.buf)-1] |= 1 << uint(pos)
	}
	bs.bitLen++
}

// AppendBits appends a slice of bools to the sequence.
func (bs *BitSequence) AppendBits(bits []bool) {
	for _, bit := range bits {
		bs.AppendBit(bit)
	}
}

// AppendBytes appends a byte slice to the bit sequence, adding all 8 bits per byte.
func (bs *BitSequence) AppendBytes(b []byte) {
	for _, by := range b {
		// Append bits from most-significant (bit 7) to least-significant (bit 0)
		for i := 7; i >= 0; i-- {
			bs.AppendBit(((by >> uint(i)) & 1) == 1)
		}
	}
}

// Concat concatenates another BitSequence to the end of this one.
func (bs *BitSequence) Concat(other *BitSequence) {
	// Append each bit from the other sequence.
	for i := 0; i < other.Len(); i++ {
		bs.AppendBit(other.BitAt(i))
	}
}

// Subsequence returns a new BitSequence containing bits in the range [from, to).
// It panics if the indices are out of range.
func (bs *BitSequence) Subsequence(from, to int) *BitSequence {
	if from < 0 || to > bs.bitLen || from > to {
		panic("invalid subsequence indices")
	}
	newBS := New()
	for i := from; i < to; i++ {
		newBS.AppendBit(bs.BitAt(i))
	}
	return newBS
}

func (bs *BitSequence) SubsequenceFrom(from int) *BitSequence {
	return bs.Subsequence(from, bs.bitLen)
}

func (bs *BitSequence) SubsequenceTo(to int) *BitSequence {
	return bs.Subsequence(0, to)
}

// BitAt returns the bit at position i (0-indexed).
// It panics if i is out of range.
func (bs *BitSequence) BitAt(i int) bool {
	if i < 0 || i >= bs.bitLen {
		panic("bit index out of range")
	}
	byteIndex := i / 8
	bitPos := 7 - (i % 8)
	return (bs.buf[byteIndex] & (1 << uint(bitPos))) != 0
}

// SetBitAt sets the bit at index i to the specified value (true for 1, false for 0).
// It assumes bits are stored in big-endian order within each byte (i.e. bit 0 is the most significant bit).
func (bs *BitSequence) SetBitAt(i int, value bool) {
	if i < 0 || i >= bs.bitLen {
		panic("bit index out of range")
	}
	byteIndex := i / 8
	bitPos := 7 - (i % 8) // calculate the position of the bit in the byte (big-endian)
	mask := byte(1 << uint(bitPos))
	if value {
		bs.buf[byteIndex] |= mask
	} else {
		bs.buf[byteIndex] &^= mask
	}
}

// Bytes returns the underlying []byte containing the packed bits.
// Note that the final byte may have unused bits (in the least-significant positions).
func (bs *BitSequence) Bytes() []byte {
	return bs.buf
}

// ToBytesLSB returns a []byte with the bits of the sequence packed in LSB-first order within each byte.
// This is the opposite of the internal representation (which is MSB-first) and matches
// the bit sequence encoding specified in C.1.5.
func (bs *BitSequence) ToBytesLSB() []byte {
	numBytes := (bs.bitLen + 7) / 8
	result := make([]byte, numBytes)

	for byteIndex := 0; byteIndex < numBytes; byteIndex++ {
		// For each byte in the result
		resultByte := byte(0)
		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			// Calculate the absolute bit position in the sequence
			absoluteBitPos := byteIndex*8 + bitIndex
			if absoluteBitPos >= bs.bitLen {
				break // Don't go beyond the length of the bit sequence
			}

			// If the bit is set in the original BitSequence
			if bs.BitAt(absoluteBitPos) {
				// Set the corresponding bit in LSB-first order
				resultByte |= (1 << uint(bitIndex))
			}
		}
		result[byteIndex] = resultByte
	}

	return result
}

// Len returns the total number of bits in the sequence.
func (bs *BitSequence) Len() int {
	return bs.bitLen
}

// BitSeqKey is a comparable representation of a BitSequence.
type BitSeqKey string

// Key converts the BitSequence to a BitSeqKey.
func (bs *BitSequence) Key() BitSeqKey {
	return BitSeqKey(fmt.Sprintf("%d:%x", bs.bitLen, bs.Bytes()))
}

// ToBitSequence converts a BitSeqKey back into a BitSequence.
// It assumes the key is formatted as "<bitLen>:<hexBytes>".
func (k BitSeqKey) ToBitSequence() *BitSequence {
	parts := strings.SplitN(string(k), ":", 2)
	if len(parts) != 2 {
		panic(fmt.Errorf("invalid BitSeqKey format"))
	}

	// Parse the bit length.
	bitLen, err := strconv.Atoi(parts[0])
	if err != nil {
		panic(fmt.Errorf("invalid bit length in key: %w", err))
	}

	// Decode the hex string to get the underlying bytes.
	data, err := hex.DecodeString(parts[1])
	if err != nil {
		panic(fmt.Errorf("invalid hex data in key: %w", err))
	}

	return &BitSequence{
		buf:    data,
		bitLen: bitLen,
	}
}

// SumBits returns the total number of bits set to true in the BitSequence.
func (bs *BitSequence) SumBits() int {
	count := 0
	fullBytes := bs.bitLen / 8
	// Count ones for all full bytes.
	for i := range fullBytes {
		count += bits.OnesCount8(bs.buf[i])
	}
	// Count ones in the last partial byte (if any).
	remaining := bs.bitLen % 8
	if remaining > 0 {
		// Create a mask to only consider the upper 'remaining' bits.
		mask := byte(0xFF << (8 - remaining))
		count += bits.OnesCount8(bs.buf[fullBytes] & mask)
	}
	return count
}

// LeadingZeros returns the number of consecutive 0 bits
// starting from the beginning (bit index 0) of the BitSequence.
func (bs *BitSequence) LeadingZeros() int {
	count := 0
	for i := 0; i < bs.bitLen; i++ {
		if bs.BitAt(i) {
			break
		}
		count++
	}
	return count
}

// TrailingZeros returns the number of consecutive 0 bits starting from the last bit
// of the BitSequence (i.e. from index bs.bitLen-1 backwards).
func (bs *BitSequence) TrailingZeros() int {
	count := 0
	// Iterate from the last bit (index bs.bitLen-1) backwards.
	for i := bs.bitLen - 1; i >= 0; i-- {
		if bs.BitAt(i) {
			break
		}
		count++
	}
	return count
}

// And returns a new BitSequence resulting from the bitwise AND of bs and other.
// It panics if the two sequences have different lengths.
func (bs *BitSequence) And(other *BitSequence) *BitSequence {
	if bs.bitLen != other.bitLen {
		panic("BitSequence.And: bit sequences must have the same length")
	}
	numBytes := (bs.bitLen + 7) / 8
	result := &BitSequence{
		buf:    make([]byte, numBytes),
		bitLen: bs.bitLen,
	}
	for i := range numBytes {
		result.buf[i] = bs.buf[i] & other.buf[i]
	}
	// For a partially used last byte, ensure bits beyond bitLen remain zero.
	if rem := bs.bitLen % 8; rem != 0 {
		mask := byte(0xFF << (8 - rem))
		result.buf[numBytes-1] &= mask
	}
	return result
}

// Or returns a new BitSequence resulting from the bitwise OR of bs and other.
// It panics if the two sequences have different lengths.
func (bs *BitSequence) Or(other *BitSequence) *BitSequence {
	if bs.bitLen != other.bitLen {
		panic("BitSequence.Or: bit sequences must have the same length")
	}
	numBytes := (bs.bitLen + 7) / 8
	result := &BitSequence{
		buf:    make([]byte, numBytes),
		bitLen: bs.bitLen,
	}
	for i := range numBytes {
		result.buf[i] = bs.buf[i] | other.buf[i]
	}
	if rem := bs.bitLen % 8; rem != 0 {
		mask := byte(0xFF << (8 - rem))
		result.buf[numBytes-1] &= mask
	}
	return result
}

// Xor returns a new BitSequence resulting from the bitwise XOR of bs and other.
// It panics if the two sequences have different lengths.
func (bs *BitSequence) Xor(other *BitSequence) *BitSequence {
	if bs.bitLen != other.bitLen {
		panic("BitSequence.Xor: bit sequences must have the same length")
	}
	numBytes := (bs.bitLen + 7) / 8
	result := &BitSequence{
		buf:    make([]byte, numBytes),
		bitLen: bs.bitLen,
	}
	for i := range numBytes {
		result.buf[i] = bs.buf[i] ^ other.buf[i]
	}
	if rem := bs.bitLen % 8; rem != 0 {
		mask := byte(0xFF << (8 - rem))
		result.buf[numBytes-1] &= mask
	}
	return result
}

// Rotate returns a new BitSequence with the bits rotated by the given amount.
// A positive shift rotates the bits left (i.e. moves bits toward lower indices),
// and a negative shift rotates the bits right (i.e. moves bits toward higher indices).
func (bs *BitSequence) Rotate(shift int) *BitSequence {
	n := bs.bitLen
	newBS := NewZeros(n)
	if n == 0 {
		return newBS
	}
	// Normalize shift so that it is in the range [0, n).
	shift = ((shift % n) + n) % n

	for i := range n {
		// The new bit at position i comes from the old bit at (i+shift) mod n.
		newBS.SetBitAt(i, bs.BitAt((i+shift)%n))
	}
	return newBS
}

// Inverse returns a new BitSequence where every bit is the logical NOT of the original.
func (bs *BitSequence) Invert() *BitSequence {
	// Create a new buffer that’s a copy of the original buffer.
	newBuf := make([]byte, len(bs.buf))
	for i := range bs.buf {
		newBuf[i] = ^bs.buf[i]
	}

	// If bitLen is not a multiple of 8, the final byte may include bits
	// beyond bitLen that are not part of the BitSequence.
	// We need to mask these bits so they remain 0.
	rem := bs.bitLen % 8
	if rem != 0 {
		// Only the upper 'rem' bits are valid (bits 0..rem-1 in big-endian order).
		// For example, if rem == 3, valid bits are the three most-significant bits.
		mask := byte(0xFF << (8 - rem))
		newBuf[len(newBuf)-1] &= mask
	}

	return &BitSequence{
		buf:    newBuf,
		bitLen: bs.bitLen,
	}
}
