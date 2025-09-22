package serializer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
	"sort"
	"unsafe"

	"jam/pkg/bitsequence"
	"jam/pkg/constants"
	"jam/pkg/sealingkeysequence"
	"jam/pkg/ticket"
	"jam/pkg/types"
	"jam/pkg/workpackage"
)

// Cached type variables to avoid repeated reflect.TypeOf() calls
var (
	blobType                 = reflect.TypeOf(types.Blob(nil))
	executionExitReasonType  = reflect.TypeOf(types.ExecutionExitReason{})
	workItemType             = reflect.TypeOf(workpackage.WorkItem{})
	sealingKeySequenceType   = reflect.TypeOf(sealingkeysequence.SealingKeySequence{})
	coreBitMaskType          = reflect.TypeOf(bitsequence.CoreBitMask{})
	genericNumType           = reflect.TypeOf(types.GenericNum(0))
	emptyStructType          = reflect.TypeOf(struct{}{})
	ticketArrayType          = reflect.TypeOf([constants.NumTimeslotsPerEpoch]ticket.Ticket{})
	bandersnatchKeyArrayType = reflect.TypeOf([constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey{})

	// Cached values to avoid repeated reflect.ValueOf() calls
	emptyStructValue = reflect.ValueOf(struct{}{})
)

// Serialize accepts an arbitrary value or pointer and returns its []byte representation.
// For struct fields it recurses; if a field is a byte array/slice, it returns the raw bytes.
func Serialize(v any) []byte {
	val := reflect.ValueOf(v)

	if val.Kind() == reflect.Ptr && !val.IsNil() {
		val = val.Elem()
	}

	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	serializeValue(val, buf)

	return buf.Bytes()
}

func Deserialize(data []byte, target any) error {
	// Ensure target is a pointer
	val := reflect.ValueOf(target)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("deserialize target must be a non-nil pointer")
	}

	buf := bytes.NewBuffer(data)
	if err := deserializeValue(val.Elem(), buf); err != nil {
		return err
	}

	// Check if there are leftover bytes
	if buf.Len() > 0 {
		return fmt.Errorf("extra %d bytes left after deserialization (data: %x)", buf.Len(), data)
	}

	return nil
}

// serializeValue writes value v to buf
func serializeValue(v reflect.Value, buf *bytes.Buffer) {
	typ := v.Type()

	if typ == blobType {
		blob := v.Interface().(types.Blob)
		buf.Write(blob)
		return
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			buf.Write([]byte{0})
			return
		}
		buf.Write([]byte{1})
		serializeValue(v.Elem(), buf)
		return
	case reflect.Struct:
		switch typ {
		case executionExitReasonType:
			er := v.Interface().(types.ExecutionExitReason)
			if !er.IsError() {
				buf.Write([]byte{0})
				serializeValue(reflect.ValueOf(*er.Blob), buf)
			} else {
				buf.Write([]byte{byte(*er.ExecutionError)})
			}
			return
		case workItemType:
			panic("Cannot directly serialize WorkItem")
		case sealingKeySequenceType:
			sks := v.Interface().(sealingkeysequence.SealingKeySequence)
			if sks.IsSealKeyTickets() {
				buf.Write([]byte{0})
				serializeValue(reflect.ValueOf(*sks.SealKeyTickets), buf)
			} else {
				buf.Write([]byte{1})
				serializeValue(reflect.ValueOf(*sks.BandersnatchKeys), buf)
			}
			return
		case coreBitMaskType:
			cm := v.Interface().(bitsequence.CoreBitMask)
			buf.Write(cm.ToBytesLSB())
			return
		default:
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

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		l := int(typ.Size())
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
		if typ == genericNumType {
			buf.Write(EncodeGeneralNatural(v.Uint()))
			return
		}
		l := int(typ.Size())
		x := v.Uint()
		buf.Write(EncodeLittleEndian(l, x))
		return

	default:
		panic(fmt.Sprintf("unsupported kind: %s", v.Kind()))
	}
}

// deserializeValue is the recursive helper that reads from buf into value v
func deserializeValue(v reflect.Value, buf *bytes.Buffer) error {
	// Cache type and kind to avoid repeated calls
	vType := v.Type()
	vKind := v.Kind()

	// Special case for types.Blob
	if vType == blobType {
		// For types.Blob just read all remaining bytes
		// This matches our serialization approach where we write raw bytes
		blob := make([]byte, buf.Len())
		if _, err := buf.Read(blob); err != nil {
			return fmt.Errorf("failed to read types.Blob data: %w", err)
		}
		v.Set(reflect.ValueOf(types.Blob(blob)))
		return nil
	}

	switch vKind {
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
			v.Set(reflect.New(vType.Elem()))
		}

		// Deserialize the pointed-to value
		return deserializeValue(v.Elem(), buf)

	case reflect.Struct:
		switch vType {
		case executionExitReasonType:
			tag, err := buf.ReadByte()
			if err != nil {
				return fmt.Errorf("failed to read ExecutionExitReason tag: %w", err)
			}

			er := types.ExecutionExitReason{}
			if tag == 0 {
				// Valid data
				blobType := reflect.TypeOf([]byte(nil))
				blob := reflect.New(blobType).Elem()
				if err := deserializeValue(blob, buf); err != nil {
					return err
				}
				if blobPtr, ok := blob.Interface().([]byte); ok {
					er.Blob = &blobPtr
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
		case workItemType:
			panic("Cannot directly deserialize WorkItem")
		case sealingKeySequenceType:
			tag, err := buf.ReadByte()
			if err != nil {
				return fmt.Errorf("failed to read SealingKeySequence tag: %w", err)
			}

			sks := sealingkeysequence.SealingKeySequence{}
			if tag == 0 {
				// Deserialize SealKeyTickets (array of tickets)
				// First create a temporary value to hold the array
				arrayValue := reflect.New(ticketArrayType).Elem()
				if err := deserializeValue(arrayValue, buf); err != nil {
					return err
				}
				// Extract the array and set a pointer to it in the struct
				ticketArray := arrayValue.Interface().([constants.NumTimeslotsPerEpoch]ticket.Ticket)
				sks.SealKeyTickets = &ticketArray
			} else {
				// Deserialize BandersnatchKeys (array of public keys)
				// First create a temporary value to hold the array
				arrayValue := reflect.New(bandersnatchKeyArrayType).Elem()
				if err := deserializeValue(arrayValue, buf); err != nil {
					return err
				}
				// Extract the array and set a pointer to it in the struct
				keyArray := arrayValue.Interface().([constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey)
				sks.BandersnatchKeys = &keyArray
			}
			v.Set(reflect.ValueOf(sks))
			return nil

		case coreBitMaskType:
			// For CoreBitMask, we don't encode the length since it's fixed at NumCores
			dataBytes := make([]byte, (constants.NumCores+7)/8)
			if _, err := buf.Read(dataBytes); err != nil {
				return fmt.Errorf("failed to read CoreBitMask data: %w", err)
			}

			cm, err := bitsequence.CoreBitMaskFromBytesLSB(dataBytes)
			if err != nil {
				return fmt.Errorf("failed to create CoreBitMask from bytes: %w", err)
			}
			v.Set(reflect.ValueOf(*cm))
			return nil

		default:
			// For other structs, iterate over all fields.
			numField := v.NumField()
			for i := 0; i < numField; i++ {
				if err := deserializeValue(v.Field(i), buf); err != nil {
					return fmt.Errorf("failed to deserialize field %s: %w", vType.Field(i).Name, err)
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
		l := int(vType.Size()) // Use cached type, number of octets to decode

		// Use a fixed-size buffer to avoid allocation for small integers
		var bytes [8]byte
		if _, err := buf.Read(bytes[:l]); err != nil {
			return fmt.Errorf("failed to read integer bytes: %w", err)
		}

		x := UnsignedToSigned(l, DecodeLittleEndian(bytes[:l]))
		v.SetInt(x)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if vType == genericNumType {
			// For regular maps, read length prefix
			length, n, ok := DecodeGeneralNatural(buf.Bytes())
			if !ok {
				return fmt.Errorf("failed to decode GenericNum length")
			}
			// Consume the bytes used for length
			buf.Next(n)
			v.SetUint(length)
			return nil
		}
		l := int(vType.Size()) // Use cached type

		// Use a fixed-size buffer to avoid allocation for small integers
		var bytes [8]byte
		if _, err := buf.Read(bytes[:l]); err != nil {
			return fmt.Errorf("failed to read unsigned integer bytes: %w", err)
		}

		x := DecodeLittleEndian(bytes[:l])
		v.SetUint(x)
		return nil

	default:
		return fmt.Errorf("unsupported kind for deserialization: %s", vKind)
	}
}

// serializeMap handles map serialization.
// For maps with value type struct{} (used as sets), it serializes the sorted keys.
// Otherwise, it writes the length encoding, then each key-value pair in key order.
func serializeMap(v reflect.Value, buf *bytes.Buffer) {
	keys := v.MapKeys()

	var keyKind reflect.Kind
	var isKeyByteArray bool

	if len(keys) > 0 {
		keyType := keys[0].Type()
		keyKind = keyType.Kind()
		if keyKind == reflect.Array {
			isKeyByteArray = keyType.Elem().Kind() == reflect.Uint8
		}
	}

	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch keyKind {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return a.Int() < b.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return a.Uint() < b.Uint()
		case reflect.Float32, reflect.Float64:
			return a.Float() < b.Float()
		case reflect.String:
			return a.String() < b.String()
		case reflect.Array:
			if isKeyByteArray {
				lenA := a.Len()
				lenB := b.Len()
				minLen := lenA
				if lenB < minLen {
					minLen = lenB
				}

				for k := 0; k < minLen; k++ {
					byteA := byte(a.Index(k).Uint())
					byteB := byte(b.Index(k).Uint())
					if byteA < byteB {
						return true
					}
					if byteA > byteB {
						return false
					}
				}
				return lenA < lenB
			}
			fallthrough
		default:
			return fmt.Sprintf("%v", a.Interface()) < fmt.Sprintf("%v", b.Interface())
		}
	})

	buf.Write(EncodeLength(v))

	valueType := v.Type().Elem()
	isSet := valueType == emptyStructType

	if isSet {
		for _, key := range keys {
			serializeValue(key, buf)
		}
	} else {
		for _, key := range keys {
			serializeValue(key, buf)
			serializeValue(v.MapIndex(key), buf)
		}
	}
}

// deserializeMap is a helper to deserialize maps
func deserializeMap(v reflect.Value, buf *bytes.Buffer) error {
	length, n, ok := DecodeGeneralNatural(buf.Bytes())
	if !ok {
		return fmt.Errorf("failed to decode map length")
	}
	buf.Next(n)

	if v.IsNil() {
		v.Set(reflect.MakeMap(v.Type()))
	}

	typ := v.Type()
	valueType := typ.Elem()
	keyType := typ.Key()
	isSet := valueType == emptyStructType

	if isSet {
		for i := uint64(0); i < length; i++ {
			key := reflect.New(keyType).Elem()
			if err := deserializeValue(key, buf); err != nil {
				return fmt.Errorf("failed to deserialize set key: %w", err)
			}
			v.SetMapIndex(key, emptyStructValue)
		}
	} else {
		for i := uint64(0); i < length; i++ {
			key := reflect.New(keyType).Elem()
			if err := deserializeValue(key, buf); err != nil {
				return fmt.Errorf("failed to deserialize map key: %w", err)
			}

			value := reflect.New(valueType).Elem()
			if err := deserializeValue(value, buf); err != nil {
				return fmt.Errorf("failed to deserialize map value: %w", err)
			}

			v.SetMapIndex(key, value)
		}
	}

	return nil
}

// serializeSlice handles array/slice serialization.
// For slices (but not arrays), it encodes the length first.
// Special case for []byte/[]uint8 to handle them as raw binary data (no length prefix).
func serializeSlice(v reflect.Value, buf *bytes.Buffer) {
	// Cache values to avoid repeated calls
	vKind := v.Kind()
	vLen := v.Len()
	vType := v.Type()

	// Regular handling for non-byte slices/arrays
	if vKind == reflect.Slice {
		buf.Write(EncodeLength(v))
	}

	// Fast path for byte slices/arrays - write bulk data instead of element-by-element
	if vType.Elem().Kind() == reflect.Uint8 {
		if vKind == reflect.Slice {
			// For slices, use v.Bytes() which is fast
			data := v.Bytes()
			buf.Write(data)
		} else {
			// Fast path for arrays (any size) - only if addressable
			if v.CanAddr() {
				data := unsafe.Slice((*byte)(unsafe.Pointer(v.UnsafeAddr())), vLen)
				buf.Write(data)
			} else {
				// Fallback: copy to a slice and use v.Bytes()
				slice := reflect.MakeSlice(reflect.SliceOf(vType.Elem()), vLen, vLen)
				reflect.Copy(slice, v)
				buf.Write(slice.Bytes())
			}
		}
		return
	}

	// General case for other slices/arrays
	for i := 0; i < vLen; i++ {
		serializeValue(v.Index(i), buf)
	}
}

// deserializeSlice is a helper to deserialize arrays and slices
func deserializeSlice(v reflect.Value, buf *bytes.Buffer) error {
	// Cache values to avoid repeated calls
	vKind := v.Kind()
	vType := v.Type()

	// For arrays, we know the length; for slices, read length prefix
	length := v.Len()

	if vKind == reflect.Slice {
		// Read slice length using DecodeGeneralNatural for consistent decoding
		lengthBytes := buf.Bytes()
		decodedLength, n, ok := DecodeGeneralNatural(lengthBytes)
		if !ok {
			return fmt.Errorf("failed to decode slice length")
		}
		// Consume the bytes used for length
		buf.Next(n)
		length = int(decodedLength)

		// Allocate slice
		v.Set(reflect.MakeSlice(vType, length, length))
	}

	// Fast path for byte slices and arrays - read bulk data instead of element-by-element
	if vType.Elem().Kind() == reflect.Uint8 {
		if vKind == reflect.Slice {
			v.Set(reflect.MakeSlice(vType, length, length))
			sliceBytes := v.Bytes()
			if _, err := buf.Read(sliceBytes); err != nil {
				return fmt.Errorf("failed to read byte slice data: %w", err)
			}
			return nil
		} else if vKind == reflect.Array && v.CanAddr() {
			data := unsafe.Slice((*byte)(unsafe.Pointer(v.UnsafeAddr())), length)
			if _, err := buf.Read(data); err != nil {
				return fmt.Errorf("failed to read byte array data: %w", err)
			}
			return nil
		}

		// Fallback: element-by-element for non-addressable arrays
		var singleByte [1]byte
		for i := 0; i < length; i++ {
			if _, err := buf.Read(singleByte[:]); err != nil {
				return fmt.Errorf("failed to read byte data at index %d: %w", i, err)
			}
			v.Index(i).SetUint(uint64(singleByte[0]))
		}
		return nil
	}

	// General case for other slice types
	for i := 0; i < length; i++ {
		if err := deserializeValue(v.Index(i), buf); err != nil {
			return fmt.Errorf("failed to deserialize element %d: %w", i, err)
		}
	}

	return nil
}

// EncodeLength encodes the length (v.Len()) of a collection into buf.
// It follows three cases:
//  1. x == 0: output a single 0x00 octet.
//  2. x fits in a computed header + remainder format.
//  3. Otherwise, output 0xFF followed by x as 8 little-endian octets.
func EncodeLength(v reflect.Value) []byte {
	x := uint64(v.Len())
	return EncodeGeneralNatural(x)
}

// EncodeGeneralNatural encodes a uint64 length value using the compact encoding format.
// It follows three cases:
//  1. x == 0: output a single 0x00 octet.
//  2. x fits in a computed header + remainder format.
//  3. Otherwise, output 0xFF followed by x as 8 little-endian octets.
func EncodeGeneralNatural(x uint64) []byte {
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
		// Directly append 8 bytes in little-endian order
		result = append(result,
			byte(x), byte(x>>8), byte(x>>16), byte(x>>24),
			byte(x>>32), byte(x>>40), byte(x>>48), byte(x>>56))

	}
	return result
}

func EncodeLittleEndian(octets int, x uint64) []byte {
	switch octets {
	case 1:
		return []byte{byte(x)}
	case 2:
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(x))
		return buf[:]
	case 4:
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], uint32(x))
		return buf[:]
	case 8:
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], x)
		return buf[:]
	default:
		// Fallback for unusual sizes
		result := make([]byte, octets)
		for i := 0; i < octets; i++ {
			result[i] = byte(x)
			x >>= 8
		}
		return result
	}
}

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

func DecodeGeneralNatural(p []byte) (x uint64, n int, ok bool) {
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
		x = binary.LittleEndian.Uint64(p[1:9])
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

func DecodeLittleEndian(b []byte) uint64 {
	// Use Go's built-in binary decoding for common sizes
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(b))
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	case 8:
		return binary.LittleEndian.Uint64(b)
	default:
		// Fallback for unusual sizes
		var x uint64
		for i, v := range b {
			x |= uint64(v) << (8 * i)
		}
		return x
	}
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

func BlobLengthFromPreimageLookupHistoricalStatusKey(key [31]byte) types.BlobLength {
	_, h := InvertStateKeyConstructorFromHash(key)
	return types.BlobLength(binary.LittleEndian.Uint32(h[:4]))
}

func InvertStateKeyConstructorFromHash(key [31]byte) (types.ServiceIndex, [32]byte) {
	// Extract service index from interleaved positions 0, 2, 4, 6
	s := uint32(key[0]) |
		(uint32(key[2]) << 8) |
		(uint32(key[4]) << 16) |
		(uint32(key[6]) << 24)

	// Reconstruct the original hash
	var h [32]byte

	// First 4 bytes were interleaved at positions 1, 3, 5, 7
	h[0] = key[1]
	h[1] = key[3]
	h[2] = key[5]
	h[3] = key[7]

	// Remaining bytes were copied starting at position 8
	copy(h[4:], key[8:])

	return types.ServiceIndex(s), h
}

func StateKeyConstructorFromHash(s types.ServiceIndex, h [32]byte) [31]byte {
	var key [31]byte

	// Extract little-endian bytes of the ServiceIndex (s)
	n0 := byte(s)
	n1 := byte(s >> 8)
	n2 := byte(s >> 16)
	n3 := byte(s >> 24)

	// Interleave n0, n1, n2, n3 with the first 4 bytes of h
	key[0] = n0
	key[1] = h[0]
	key[2] = n1
	key[3] = h[1]
	key[4] = n2
	key[5] = h[2]
	key[6] = n3
	key[7] = h[3]

	// Copy the remaining bytes of h from index 4 onward
	copy(key[8:], h[4:])

	return key
}

type ChainParameters struct {
	ServiceMinimumBalancePerItem                      uint64
	ServiceMinimumBalancePerOctet                     uint64
	ServiceMinimumBalance                             uint64
	NumCores                                          uint16
	UnreferencePreimageExpungeTimeslots               uint32
	NumTimeslotsPerEpoch                              uint32
	SingleAccumulationAllocatedGas                    uint64
	IsAuthorizedGasAllocation                         uint64
	RefineGasAllocation                               uint64
	AllAccumulationTotalGasAllocation                 uint64
	RecentHistorySizeBlocks                           uint16
	MaxWorkItemsInPackage                             uint16
	MaxSumDependencyItemsInReport                     uint16
	MaxTicketsPerExtrinsic                            uint16
	LookupAnchorMaxAgeTimeslots                       uint32
	NumTicketEntries                                  uint16
	MaxItemsInAuthorizationsPool                      uint16
	SlotPeriodInSeconds                               uint16
	AuthorizerQueueLength                             uint16
	ValidatorCoreAssignmentsRotationPeriodInTimeslots uint16
	MaxExtrinsicsInWorkPackage                        uint16
	UnavailableWorkTimeoutTimeslots                   uint16
	NumValidators                                     uint16
	IsAuthorizedCodeMaxSizeOctets                     uint32
	MaxSizeEncodedWorkPackage                         uint32
	ServiceCodeMaxSize                                uint32
	ErasureCodedPiecesSize                            uint32
	MaxImportsInWorkPackage                           uint32
	ErasureCodedPiecesInSegment                       uint32
	MaxTotalSizeWorkReportBlobs                       uint32
	TransferMemoSize                                  uint32
	MaxExportsInWorkPackage                           uint32
	TicketSubmissionEndingSlotPhaseNumber             uint32
}

func SerializeChainParameters() []byte {
	return Serialize(&ChainParameters{
		ServiceMinimumBalancePerItem:                      constants.ServiceMinimumBalancePerItem,
		ServiceMinimumBalancePerOctet:                     constants.ServiceMinimumBalancePerOctet,
		ServiceMinimumBalance:                             constants.ServiceMinimumBalance,
		NumCores:                                          constants.NumCores,
		UnreferencePreimageExpungeTimeslots:               constants.UnreferencePreimageExpungeTimeslots,
		NumTimeslotsPerEpoch:                              constants.NumTimeslotsPerEpoch,
		SingleAccumulationAllocatedGas:                    constants.SingleAccumulationAllocatedGas,
		IsAuthorizedGasAllocation:                         constants.IsAuthorizedGasAllocation,
		RefineGasAllocation:                               constants.RefineGasAllocation,
		AllAccumulationTotalGasAllocation:                 constants.AllAccumulationTotalGasAllocation,
		RecentHistorySizeBlocks:                           constants.RecentHistorySizeBlocks,
		MaxWorkItemsInPackage:                             constants.MaxWorkItemsInPackage,
		MaxSumDependencyItemsInReport:                     constants.MaxSumDependencyItemsInReport,
		MaxTicketsPerExtrinsic:                            constants.MaxTicketsPerExtrinsic,
		LookupAnchorMaxAgeTimeslots:                       constants.LookupAnchorMaxAgeTimeslots,
		NumTicketEntries:                                  constants.NumTicketEntries,
		MaxItemsInAuthorizationsPool:                      constants.MaxItemsInAuthorizationsPool,
		SlotPeriodInSeconds:                               constants.SlotPeriodInSeconds,
		AuthorizerQueueLength:                             constants.AuthorizerQueueLength,
		ValidatorCoreAssignmentsRotationPeriodInTimeslots: constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots,
		MaxExtrinsicsInWorkPackage:                        constants.MaxExtrinsicsInWorkPackage,
		UnavailableWorkTimeoutTimeslots:                   constants.UnavailableWorkTimeoutTimeslots,
		NumValidators:                                     constants.NumValidators,
		IsAuthorizedCodeMaxSizeOctets:                     constants.IsAuthorizedCodeMaxSizeOctets,
		MaxSizeEncodedWorkPackage:                         constants.MaxSizeEncodedWorkPackage,
		ServiceCodeMaxSize:                                constants.ServiceCodeMaxSize,
		ErasureCodedPiecesSize:                            constants.ErasureCodedPiecesSize,
		MaxImportsInWorkPackage:                           constants.MaxImportsInWorkPackage,
		ErasureCodedPiecesInSegment:                       constants.ErasureCodedPiecesInSegment,
		MaxTotalSizeWorkReportBlobs:                       constants.MaxTotalSizeWorkReportBlobs,
		TransferMemoSize:                                  constants.TransferMemoSize,
		MaxExportsInWorkPackage:                           constants.MaxExportsInWorkPackage,
		TicketSubmissionEndingSlotPhaseNumber:             constants.TicketSubmissionEndingSlotPhaseNumber,
	})
}
