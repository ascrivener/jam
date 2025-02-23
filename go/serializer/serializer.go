package serializer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
	"sort"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/sealingkeysequence"
	"github.com/ascrivener/jam/workreport"
)

// Serialize accepts an arbitrary value and returns its []byte representation.
// For struct fields it recurses; if a field is a byte array/slice, it returns the raw bytes.
func Serialize(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := serializeValue(reflect.ValueOf(v), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serializeValue is the recursive helper that writes the serialized form of v into buf.
func serializeValue(v reflect.Value, buf *bytes.Buffer) error {
	// If v is a pointer, encode nil as 0; otherwise, write 1 and serialize its element.
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return buf.WriteByte(0)
		}
		if err := buf.WriteByte(1); err != nil {
			return err
		}
		return serializeValue(v.Elem(), buf)
	}

	switch v.Kind() {
	case reflect.Struct:
		// Special handling for workreport.WorkOutput.
		if v.Type() == reflect.TypeOf(workreport.WorkOutput{}) {
			wo := v.Interface().(workreport.WorkOutput)
			if !wo.HasError() {
				// Tag 0 indicates valid data; then, recursively encode the Data field.
				if err := buf.WriteByte(0); err != nil {
					return err
				}
				return serializeValue(reflect.ValueOf(wo.Data), buf)
			}
			// If there is an error, write the error value as a single octet.
			return buf.WriteByte(byte(wo.Err))
		}

		if v.Type() == reflect.TypeOf(sealingkeysequence.SealingKeySequence{}) {
			sealingKeySequence := v.Interface().(sealingkeysequence.SealingKeySequence)
			if sealingKeySequence.IsSealKeyTickets() {
				if err := buf.WriteByte(0); err != nil {
					return err
				}
				return serializeValue(reflect.ValueOf(sealingKeySequence.SealKeyTickets), buf)
			} else {
				if err := buf.WriteByte(1); err != nil {
					return err
				}
				return serializeValue(reflect.ValueOf(sealingKeySequence.BandersnatchKeys), buf)
			}
		}

		// Special case for BitSequence
		if v.Type() == reflect.TypeOf(bitsequence.BitSequence{}) {
			bs := v.Interface().(bitsequence.BitSequence)
			_, err := buf.Write(bs.Bytes())
			return err
		}

		// Otherwise, for structs, iterate over and serialize all fields.
		for i := range v.NumField() {
			if err := serializeValue(v.Field(i), buf); err != nil {
				return err
			}
		}
		return nil

	case reflect.Map:
		return serializeMap(v, buf)

	case reflect.Array, reflect.Slice:
		return serializeSlice(v, buf)

		// Handle all integer types (signed and unsigned) by writing their little-endian representation.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		l := int(v.Type().Size()) // number of octets to encode
		signedVal := v.Int()
		var x uint64
		if signedVal < 0 {
			x = SignedToUnsigned(l, signedVal)
		} else {
			x = uint64(signedVal)
		}
		buf.Write(EncodeLittleEndian(l, x))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		l := int(v.Type().Size())
		x := v.Uint()
		buf.Write(EncodeLittleEndian(l, x))
		return nil

	default:
		return fmt.Errorf("unsupported type: %s", v.Type().String())
	}
}

// serializeMap handles map serialization.
// For maps with value type struct{} (used as sets), it serializes the sorted keys.
// Otherwise, it writes the length encoding, then each key/value pair in key order.
func serializeMap(v reflect.Value, buf *bytes.Buffer) error {
	// Extract and sort the map keys.
	keys := v.MapKeys()
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch a.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return a.Int() < b.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return a.Uint() < b.Uint()
		case reflect.Float32, reflect.Float64:
			return a.Float() < b.Float()
		case reflect.String:
			return a.String() < b.String()
		default:
			// Fallback: compare string representations.
			return fmt.Sprintf("%v", a.Interface()) < fmt.Sprintf("%v", b.Interface())
		}
	})

	// If the map is used as a set (value type is struct{}), simply serialize the keys.
	if v.Type().Elem() == reflect.TypeOf(struct{}{}) {
		for _, key := range keys {
			if err := serializeValue(key, buf); err != nil {
				return err
			}
		}
		return nil
	}

	// For a normal map, first append the length encoding.
	if err := appendLengthEncoding(v, buf); err != nil {
		return err
	}
	// Then serialize each key followed by its associated value.
	for _, key := range keys {
		if err := serializeValue(key, buf); err != nil {
			return err
		}
		if err := serializeValue(v.MapIndex(key), buf); err != nil {
			return err
		}
	}
	return nil
}

// serializeSlice handles array/slice serialization.
// For slices (but not arrays), it encodes the length first.
// For boolean slices, it bit-packs the booleans; otherwise, it serializes each element.
func serializeSlice(v reflect.Value, buf *bytes.Buffer) error {
	if v.Kind() == reflect.Slice {
		if err := appendLengthEncoding(v, buf); err != nil {
			return err
		}
	}

	// For other slices/arrays, serialize each element.
	for i := 0; i < v.Len(); i++ {
		if err := serializeValue(v.Index(i), buf); err != nil {
			return err
		}
	}
	return nil
}

// appendLengthEncoding encodes the length (v.Len()) of a collection into buf.
// It follows three cases:
//  1. x == 0: output a single 0x00 octet.
//  2. x fits in a computed header + remainder format.
//  3. Otherwise, output 0xFF followed by x as 8 little-endian octets.
func appendLengthEncoding(v reflect.Value, buf *bytes.Buffer) error {
	x := uint64(v.Len())
	if x == 0 {
		return buf.WriteByte(0x00)
	}

	// Compute l = floor(log2(x)) / 7.
	l := uint((bits.Len64(x) - 1) / 7)
	if l <= 7 && x < (uint64(1)<<(7*l+1)) {
		header := (1 << 8) - (1 << (8 - l)) + (x >> (8 * l))
		if err := buf.WriteByte(byte(header)); err != nil {
			return err
		}
		if l > 0 {
			remainder := x & ((uint64(1) << (8 * l)) - 1)
			for i := uint(0); i < l; i++ {
				if err := buf.WriteByte(byte((remainder >> (8 * i)) & 0xFF)); err != nil {
					return err
				}
			}
		}
	} else {
		// Fallback: x < 2^64. Write 0xFF followed by x in 8 little-endian octets.
		if err := buf.WriteByte(0xFF); err != nil {
			return err
		}
		if err := binary.Write(buf, binary.LittleEndian, x); err != nil {
			return err
		}
	}
	return nil
}

func EncodeLittleEndian(octets int, x uint64) []byte {
	result := make([]byte, octets)
	for i := range octets {
		result[i] = byte(x % 256)
		x /= 256
	}
	return result
}

func DecodeLittleEndian(b []byte) uint64 {
	var x uint64
	for i, v := range b {
		x |= uint64(v) << (8 * i)
	}
	return x
}

// UnsignedToSigned converts an unsigned integer x (assumed to be in [0, 2^(8*n)))
// into its two's complement signed representation as an int64.
// If x is less than 2^(8*n-1), it is interpreted as positive; otherwise, we subtract 2^(8*n).
func UnsignedToSigned(octets int, x uint64) int64 {
	totalBits := 8 * octets
	if totalBits > 64 {
		panic(fmt.Sprintf("Unsupported octet width: %d (max 8 allowed)", octets))
	}
	signBit := uint64(1) << uint(totalBits-1)
	modVal := uint64(1) << uint(totalBits)
	if x < signBit {
		return int64(x)
	}
	return int64(x) - int64(modVal)
}

// SignedToUnsigned converts a signed integer a, assumed to be in the range
// [ -2^(8*l-1), 2^(8*l-1) - 1 ], into its unsigned natural representation
// in [0, 2^(8*l)).
func SignedToUnsigned(octets int, a int64) uint64 {
	totalBits := 8 * octets
	modVal := uint64(1) << uint(totalBits)
	// Adjust a so that negative values wrap around properly.
	return (modVal + uint64(a)) % modVal
}

// UintToBitsLE converts an unsigned integer x (with x in [0, 2^(8*n)))
// into a bit vector of length 8*n in little-endian order. That is, the bit at index 0
// is the least-significant bit of x.
func UintToBitSequenceLE(octets int, x uint64) *bitsequence.BitSequence {
	total := 8 * octets
	bs := bitsequence.NewZeros(total) // Create a BitSequence of 'total' bits, all initialized to false.
	for i := range total {
		// Set bit i if the i-th bit of x (starting from LSB) is 1.
		bs.SetBitAt(i, ((x>>uint(i))&1) == 1)
	}
	return bs
}

// BitsToUintLE converts a bit vector (in little-endian order) back into an unsigned integer.
// It assumes bits[0] is the least-significant bit.
func BitSequenceToUintLE(bs *bitsequence.BitSequence) uint64 {
	var x uint64 = 0
	total := bs.Len()
	for i := range total {
		if bs.BitAt(i) {
			x |= 1 << uint(i)
		}
	}
	return x
}

// UintToBitsBE converts an unsigned integer x (with x in [0, 2^(8*n)))
// into a bit vector of length 8*n in big-endian order. That is, the bit at index 0
// is the most-significant bit.
func UintToBitSequenceBE(octets int, x uint64) *bitsequence.BitSequence {
	total := 8 * octets
	bs := bitsequence.NewZeros(total)
	for i := range total {
		// For big-endian, bit at index i corresponds to the bit at position (total-1-i) in x.
		bs.SetBitAt(i, ((x>>uint(total-1-i))&1) == 1)
	}
	return bs
}

// BitsToUintBE converts a bit vector (in big-endian order) back into an unsigned integer.
// It assumes bits[0] is the most-significant bit.
func BitSequenceToUintBE(bs *bitsequence.BitSequence) uint64 {
	total := bs.Len()
	var x uint64 = 0
	for i := range total {
		if bs.BitAt(i) {
			x |= 1 << uint(total-1-i)
		}
	}
	return x
}
