package serializer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
	"sort"

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

		// Otherwise, for structs, iterate over and serialize all fields.
		for i := 0; i < v.NumField(); i++ {
			if err := serializeValue(v.Field(i), buf); err != nil {
				return err
			}
		}
		return nil

	case reflect.Map:
		return serializeMap(v, buf)

	case reflect.Array, reflect.Slice:
		return serializeSlice(v, buf)

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

	// Special case for []bool: pack bits into octets.
	if v.Type().Elem().Kind() == reflect.Bool {
		var octet byte
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
				octet, count = 0, 0
			}
		}
		if count > 0 {
			if err := buf.WriteByte(octet); err != nil {
				return err
			}
		}
		return nil
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
