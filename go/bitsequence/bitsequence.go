package bitsequence

import (
	"encoding/hex"
	"fmt"
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

// FromBytes creates a new BitSequence initialized with the bits from the given []byte.
// The entire byte slice is appended (8 bits per byte) in order.
func FromBytes(b []byte) *BitSequence {
	bs := New()
	bs.AppendBytes(b)
	return bs
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
