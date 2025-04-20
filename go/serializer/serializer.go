package serializer

import (
	"bytes"
	"fmt"
	"math/bits"
	"reflect"
	"sort"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/sealingkeysequence"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
)

// Serialize accepts an arbitrary value and returns its []byte representation.
// For struct fields it recurses; if a field is a byte array/slice, it returns the raw bytes.
func Serialize(v any) []byte {
	var buf bytes.Buffer
	serializeValue(reflect.ValueOf(v), &buf)
	return buf.Bytes()
}

// Deserialize takes serialized data and reconstructs the original value
// The target parameter must be a pointer to the desired type
func Deserialize(data []byte, target any) error {
	// Ensure target is a pointer
	val := reflect.ValueOf(target)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("deserialize target must be a non-nil pointer")
	}

	buf := bytes.NewBuffer(data)
	return deserializeValue(val.Elem(), buf)
}

// serializeValue is the recursive helper that writes the serialized form of v into buf.
func serializeValue(v reflect.Value, buf *bytes.Buffer) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			buf.WriteByte(0)
			return
		} else {
			buf.WriteByte(1)
			serializeValue(v.Elem(), buf)
		}
		return
	case reflect.Struct:
		// Special handling based on the concrete type of the struct.
		switch v.Type() {
		case reflect.TypeOf(types.ExecutionExitReason{}):
			er := v.Interface().(types.ExecutionExitReason)
			if !er.IsError() {
				// Tag 0 indicates valid data; then, recursively encode the Data field.
				buf.WriteByte(0)
				serializeValue(reflect.ValueOf(er.Blob), buf)
			} else {
				// Write the error value as a single octet.
				buf.WriteByte(byte(*er.ExecutionError))
			}
			return
		case reflect.TypeOf(sealingkeysequence.SealingKeySequence{}):
			sks := v.Interface().(sealingkeysequence.SealingKeySequence)
			if sks.IsSealKeyTickets() {
				buf.WriteByte(0)
				serializeValue(reflect.ValueOf(*sks.SealKeyTickets), buf)
			} else {
				buf.WriteByte(1)
				serializeValue(reflect.ValueOf(*sks.BandersnatchKeys), buf)
			}
			return
		case reflect.TypeOf(bitsequence.BitSequence{}):
			bs := v.Interface().(bitsequence.BitSequence)
			buf.Write(EncodeLength(reflect.ValueOf(bs.ToBytesLSB())))
			buf.Write(bs.ToBytesLSB())
			return
		default:
			// For other structs, iterate over all fields.
			for i := 0; i < v.NumField(); i++ {
				serializeValue(v.Field(i), buf)
			}
			return
		}

	case reflect.Map:
		serializeMap(v, buf)
		return

	case reflect.Array, reflect.Slice:
		serializeSlice(v, buf)
		return

	// Handle integer types by writing their little-endian representation.
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
		return

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		l := int(v.Type().Size())
		x := v.Uint()
		buf.Write(EncodeLittleEndian(l, x))
		return

	default:
		panic(fmt.Sprintf("unsupported kind: %s", v.Kind()))
	}
}

// deserializeValue is the recursive helper that reads from buf into value v
func deserializeValue(v reflect.Value, buf *bytes.Buffer) error {
	switch v.Kind() {
	case reflect.Ptr:
		// Check if pointer is nil
		b, err := buf.ReadByte()
		if err != nil {
			return fmt.Errorf("failed to read pointer tag: %w", err)
		}

		if b == 0 {
			// Nil pointer
			return nil
		}

		// Allocate if nil
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}

		// Deserialize the pointed-to value
		return deserializeValue(v.Elem(), buf)

	case reflect.Struct:
		// Special handling based on the concrete type of the struct
		switch v.Type() {
		case reflect.TypeOf(types.ExecutionExitReason{}):
			tag, err := buf.ReadByte()
			if err != nil {
				return fmt.Errorf("failed to read ExecutionExitReason tag: %w", err)
			}

			er := types.ExecutionExitReason{}
			if tag == 0 {
				// Valid data
				blob := reflect.New(reflect.TypeOf(er.Blob)).Elem()
				if err := deserializeValue(blob, buf); err != nil {
					return err
				}
				if blobPtr, ok := blob.Interface().(*[]byte); ok {
					er.Blob = blobPtr
				} else {
					return fmt.Errorf("expected *[]byte but got %T", blob.Interface())
				}
			} else {
				// Error value
				errVal := types.ExecutionErrorType(tag)
				er.ExecutionError = &errVal
			}
			v.Set(reflect.ValueOf(er))
			return nil

		case reflect.TypeOf(sealingkeysequence.SealingKeySequence{}):
			tag, err := buf.ReadByte()
			if err != nil {
				return fmt.Errorf("failed to read SealingKeySequence tag: %w", err)
			}

			sks := sealingkeysequence.SealingKeySequence{}
			if tag == 0 {
				// Deserialize SealKeyTickets (array of tickets)
				// First create a temporary value to hold the array
				arrayValue := reflect.New(reflect.TypeOf([constants.NumTimeslotsPerEpoch]ticket.Ticket{})).Elem()
				if err := deserializeValue(arrayValue, buf); err != nil {
					return err
				}
				// Extract the array and set a pointer to it in the struct
				ticketArray := arrayValue.Interface().([constants.NumTimeslotsPerEpoch]ticket.Ticket)
				sks.SealKeyTickets = &ticketArray
			} else {
				// Deserialize BandersnatchKeys (array of public keys)
				// First create a temporary value to hold the array
				arrayValue := reflect.New(reflect.TypeOf([constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey{})).Elem()
				if err := deserializeValue(arrayValue, buf); err != nil {
					return err
				}
				// Extract the array and set a pointer to it in the struct
				keyArray := arrayValue.Interface().([constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey)
				sks.BandersnatchKeys = &keyArray
			}
			v.Set(reflect.ValueOf(sks))
			return nil

		case reflect.TypeOf(bitsequence.BitSequence{}):
			// First read length of the bit sequence
			seqLength, n, ok := DecodeLength(buf.Bytes())
			if !ok {
				return fmt.Errorf("failed to decode BitSequence length")
			}
			// Consume the length bytes
			buf.Next(n)

			// Now read only the required bytes for the BitSequence
			dataBytes := make([]byte, seqLength)
			if _, err := buf.Read(dataBytes); err != nil {
				return fmt.Errorf("failed to read BitSequence data: %w", err)
			}

			bs := bitsequence.FromBytes(dataBytes)
			v.Set(reflect.ValueOf(bs))
			return nil

		default:
			// For other structs, iterate over all fields
			for i := 0; i < v.NumField(); i++ {
				if err := deserializeValue(v.Field(i), buf); err != nil {
					return fmt.Errorf("failed to deserialize field %s: %w", v.Type().Field(i).Name, err)
				}
			}
			return nil
		}

	case reflect.Map:
		return deserializeMap(v, buf)

	case reflect.Array, reflect.Slice:
		return deserializeSlice(v, buf)

	// Handle integer types by reading their little-endian representation
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		l := int(v.Type().Size()) // number of octets to decode
		if buf.Len() < l {
			return fmt.Errorf("not enough data to read %d-byte integer", l)
		}

		bytes := make([]byte, l)
		if _, err := buf.Read(bytes); err != nil {
			return fmt.Errorf("failed to read integer bytes: %w", err)
		}

		x := UnsignedToSigned(l, DecodeLittleEndian(bytes))
		v.SetInt(x)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		l := int(v.Type().Size())
		if buf.Len() < l {
			return fmt.Errorf("not enough data to read %d-byte unsigned integer", l)
		}

		bytes := make([]byte, l)
		if _, err := buf.Read(bytes); err != nil {
			return fmt.Errorf("failed to read unsigned integer bytes: %w", err)
		}

		x := DecodeLittleEndian(bytes)
		v.SetUint(x)
		return nil

	default:
		return fmt.Errorf("unsupported kind for deserialization: %s", v.Kind())
	}
}

// serializeMap handles map serialization.
// For maps with value type struct{} (used as sets), it serializes the sorted keys.
// Otherwise, it writes the length encoding, then each key/value pair in key order.
func serializeMap(v reflect.Value, buf *bytes.Buffer) {
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
			serializeValue(key, buf)
		}
	} else {
		// For a normal map, first append the length encoding.
		buf.Write(EncodeLength(v))
		// Then serialize each key followed by its associated value.
		for _, key := range keys {
			serializeValue(key, buf)
			serializeValue(v.MapIndex(key), buf)
		}
	}
}

// deserializeMap is a helper to deserialize maps
func deserializeMap(v reflect.Value, buf *bytes.Buffer) error {
	// Special handling for maps with value type struct{} (used as sets)
	if v.Type().Elem() == reflect.TypeOf(struct{}{}) {
		// Create a new map if the map is nil
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}

		// For sets, deserialize keys only
		keyType := v.Type().Key()
		for buf.Len() > 0 {
			key := reflect.New(keyType).Elem()
			if err := deserializeValue(key, buf); err != nil {
				return fmt.Errorf("failed to deserialize set key: %w", err)
			}
			// Set key with empty struct{}{} value
			v.SetMapIndex(key, reflect.ValueOf(struct{}{}))
		}
		return nil
	}

	// For regular maps, read length prefix
	length, n, ok := DecodeLength(buf.Bytes())
	if !ok {
		return fmt.Errorf("failed to decode map length")
	}
	// Consume the bytes used for length
	buf.Next(n)

	// Create a new map if the map is nil
	if v.IsNil() {
		v.Set(reflect.MakeMap(v.Type()))
	}

	// Deserialize each key-value pair
	keyType := v.Type().Key()
	valueType := v.Type().Elem()

	for i := uint64(0); i < length; i++ {
		// Create new key and value instances
		key := reflect.New(keyType).Elem()
		value := reflect.New(valueType).Elem()

		// Deserialize key
		if err := deserializeValue(key, buf); err != nil {
			return fmt.Errorf("failed to deserialize map key %d: %w", i, err)
		}

		// Deserialize value
		if err := deserializeValue(value, buf); err != nil {
			return fmt.Errorf("failed to deserialize map value %d: %w", i, err)
		}

		// Set key-value pair in map
		v.SetMapIndex(key, value)
	}

	return nil
}

// serializeSlice handles array/slice serialization.
// For slices (but not arrays), it encodes the length first.
// For boolean slices, it bit-packs the booleans; otherwise, it serializes each element.
func serializeSlice(v reflect.Value, buf *bytes.Buffer) {
	if v.Kind() == reflect.Slice {
		buf.Write(EncodeLength(v))
	}

	// For other slices/arrays, serialize each element.
	for i := range v.Len() {
		serializeValue(v.Index(i), buf)
	}
}

// deserializeSlice is a helper to deserialize arrays and slices
func deserializeSlice(v reflect.Value, buf *bytes.Buffer) error {
	// For arrays, we know the length; for slices, read length prefix
	isArray := v.Kind() == reflect.Array
	length := v.Len()

	if !isArray {
		// Read slice length using DecodeLength for consistent decoding
		lengthBytes := buf.Bytes()
		decodedLength, n, ok := DecodeLength(lengthBytes)
		if !ok {
			return fmt.Errorf("failed to decode slice length")
		}
		// Consume the bytes used for length
		buf.Next(n)
		length = int(decodedLength)

		// Allocate slice
		v.Set(reflect.MakeSlice(v.Type(), length, length))
	}

	// Deserialize elements
	elemType := v.Type().Elem()

	// Special case for byte arrays/slices
	if elemType.Kind() == reflect.Uint8 {
		// Directly read bytes
		bytes := make([]byte, length)
		if _, err := buf.Read(bytes); err != nil {
			return fmt.Errorf("failed to read byte slice: %w", err)
		}

		// Copy bytes to array/slice
		reflect.Copy(v, reflect.ValueOf(bytes))
		return nil
	}

	// General case
	for i := 0; i < length; i++ {
		if err := deserializeValue(v.Index(i), buf); err != nil {
			return fmt.Errorf("failed to deserialize element %d: %w", i, err)
		}
	}

	return nil
}

// appendLengthEncoding encodes the length (v.Len()) of a collection into buf.
// It follows three cases:
//  1. x == 0: output a single 0x00 octet.
//  2. x fits in a computed header + remainder format.
//  3. Otherwise, output 0xFF followed by x as 8 little-endian octets.
func EncodeLength(v reflect.Value) []byte {
	x := uint64(v.Len())
	var result []byte
	if x == 0 {
		return []byte{0x00}
	}

	// l = floor(log2(x)/7)
	l := uint((bits.Len64(x) - 1) / 7)

	// check if l < 8 (valid range for compact encoding)
	if l < 8 {
		// Header: 2^8 - 2^(8-l) + ⌊x/(2^(8l))⌋
		header := (1 << 8) - (1 << (8 - l)) + (x >> (8 * l))
		result = append(result, byte(header))

		if l > 0 {
			// Remainder: x mod 2^(8l)
			remainder := x & ((uint64(1) << (8 * l)) - 1)
			result = append(result, EncodeLittleEndian(int(l), remainder)...)
		}
	} else {
		// Fallback case
		result = append(result, 0xFF)
		result = append(result, EncodeLittleEndian(8, x)...)
	}
	return result
}

// countLeadingOnes counts the number of consecutive 1 bits
// starting from the most significant bit in an 8‐bit value.
func countLeadingOnes(b byte) int {
	count := 0
	for i := 7; i >= 0; i-- {
		if (b & (1 << i)) != 0 {
			count++
		} else {
			break
		}
	}
	return count
}

// DecodeLength decodes a length value encoded by EncodeLength from p.
// It returns the decoded length x, the number of bytes consumed, and ok==true on success.
func DecodeLength(p []byte) (x uint64, n int, ok bool) {
	if len(p) == 0 {
		return 0, 0, false
	}

	header := p[0]
	// Case 1: x == 0
	if header == 0x00 {
		return 0, 1, true
	}
	// Case 2: fallback marker
	if header == 0xFF {
		if len(p) < 9 {
			return 0, 0, false
		}
		x = DecodeLittleEndian(p[1:9])
		return x, 1 + 8, true
	}
	// Case 3: header + remainder.
	// Determine l = number of extra bytes from the header.
	l := countLeadingOnes(header)
	// Compute base = (1<<8) - (1 << (8 - l))
	// For example, if l == 1 then base = 256 - (1 << 7) = 256 - 128 = 128.
	base := byte(int(1<<8) - (1 << (8 - l)))
	// headerPart is the high part of x.
	high := uint64(header - base)
	// Make sure there are enough bytes for the remainder.
	if len(p) < 1+int(l) {
		return 0, 0, false
	}
	// Read the remainder (l bytes in little-endian order).
	remainder := DecodeLittleEndian(p[1 : 1+int(l)])
	// Reconstruct x.
	x = (high << (8 * l)) | remainder
	return x, 1 + int(l), true
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

	// Special case for octets = 8 (64 bits)
	if octets == 8 {
		// For 64-bit integers, if the sign bit is set, we need to interpret as negative
		if x >= signBit {
			// This is equivalent to x - 2^64, but we need to be careful with the arithmetic
			// to avoid overflow. Since int64(x) already gives us the correct bit pattern
			// interpreted as signed, we can just return it directly.
			return int64(x)
		}
		return int64(x)
	}

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
	// Special case for octets = 8 (64 bits)
	if octets == 8 {
		// For 64-bit values, we don't need modular arithmetic
		// because uint64(a) already gives the correct bit pattern
		return uint64(a)
	}

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
