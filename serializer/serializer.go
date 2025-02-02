package serializer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
)

// Serialize accepts an arbitrary value and returns a []byte representation.
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
	// If v is a pointer, dereference it.
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
		// Iterate over struct fields and serialize each one.
		for i := 0; i < v.NumField(); i++ {
			if err := serializeValue(v.Field(i), buf); err != nil {
				return err
			}
		}
		return nil

	case reflect.Array, reflect.Slice:
		if v.Kind() == reflect.Slice {
			// Append the encoding of the length of the slice.
			x := uint64(v.Len())
			// Case 1: if x == 0, output an octet of all 0s.
			if x == 0 {
				if err := buf.WriteByte(0x00); err != nil {
					return err
				}
			} else {
				// Compute l = floor(log2(x)) / 7.
				l := uint((bits.Len64(x) - 1) / 7)
				// Check if we are in the range for Case 2.
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
					// Otherwise, fall back to Case 3:
					// x < 2^64, output the octet 0xFF followed by x in 8 little-endian octets.
					if err := buf.WriteByte(0xFF); err != nil {
						return err
					}
					if err := binary.Write(buf, binary.LittleEndian, x); err != nil {
						return err
					}
				}
			}
		}
		if v.Type().Elem().Kind() == reflect.Bool {
			var octet byte = 0
			count := 0
			for i := 0; i < v.Len(); i++ {
				if v.Index(i).Bool() {
					octet |= 1 << uint(count)
				}
				count++
				if count == 8 {
					if err := buf.WriteByte(octet); err != nil {
						return err
					}
					octet = 0
					count = 0
				}
			}
			// Write any remaining bits.
			if count > 0 {
				if err := buf.WriteByte(octet); err != nil {
					return err
				}
			}
			return nil
		} else {
			for i := 0; i < v.Len(); i++ {
				if err := serializeValue(v.Index(i), buf); err != nil {
					return err
				}
			}
		}
		return nil

	case reflect.Uint8:
		return buf.WriteByte(byte(v.Uint()))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return binary.Write(buf, binary.LittleEndian, v.Int())

	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return binary.Write(buf, binary.LittleEndian, v.Uint())

	default:
		return fmt.Errorf("unsupported type: %s", v.Type().String())
	}
}
