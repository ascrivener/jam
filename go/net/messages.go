package net

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Message represents a JAMNP-S protocol message
type Message []byte

// SendMessage sends a message on the given stream
// As per the protocol, it first sends the message size as a little-endian 32-bit uint
// followed by the message content
func SendMessage(stream io.Writer, data []byte) error {
	// First send the size as little-endian 32-bit uint
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(data)))

	if _, err := stream.Write(sizeBytes); err != nil {
		return fmt.Errorf("failed to write message size: %w", err)
	}

	// Then send the message content
	_, err := stream.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write message content: %w", err)
	}

	return nil
}

// ReadMessage reads a message from the given stream
// It first reads the message size as a little-endian 32-bit uint
// then reads that many bytes as the message content
func ReadMessage(stream io.Reader) (Message, error) {
	// Read the message size
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(stream, sizeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read message size: %w", err)
	}

	// Parse the message size
	size := binary.LittleEndian.Uint32(sizeBytes)

	// Read the message content
	data := make([]byte, size)
	_, err = io.ReadFull(stream, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read message content: %w", err)
	}

	return data, nil
}

// EncodeByte appends a byte to the message
func (m *Message) EncodeByte(b byte) {
	*m = append(*m, b)
}

// EncodeUint32 appends a uint32 to the message in little-endian format
func (m *Message) EncodeUint32(n uint32) {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, n)
	*m = append(*m, bytes...)
}

// EncodeUint16 appends a uint16 to the message in little-endian format
func (m *Message) EncodeUint16(n uint16) {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, n)
	*m = append(*m, bytes...)
}

// EncodeBytes appends a byte slice to the message
func (m *Message) EncodeBytes(data []byte) {
	*m = append(*m, data...)
}

// EncodeByteSliceWithLength appends a byte slice with its length prefix
func (m *Message) EncodeByteSliceWithLength(data []byte) {
	m.EncodeUint32(uint32(len(data)))
	m.EncodeBytes(data)
}

// EncodeHash appends a 32-byte hash to the message
func (m *Message) EncodeHash(hash [32]byte) {
	m.EncodeBytes(hash[:])
}

// DecodeByte reads a byte from the message at the given offset and advances the offset
func DecodeByte(data []byte, offset *int) (byte, error) {
	if *offset >= len(data) {
		return 0, fmt.Errorf("message truncated: cannot decode byte at offset %d", *offset)
	}

	b := data[*offset]
	*offset++
	return b, nil
}

// DecodeUint32 reads a uint32 from the message at the given offset and advances the offset
func DecodeUint32(data []byte, offset *int) (uint32, error) {
	if *offset+4 > len(data) {
		return 0, fmt.Errorf("message truncated: cannot decode uint32 at offset %d", *offset)
	}

	n := binary.LittleEndian.Uint32(data[*offset : *offset+4])
	*offset += 4
	return n, nil
}

// DecodeUint16 reads a uint16 from the message at the given offset and advances the offset
func DecodeUint16(data []byte, offset *int) (uint16, error) {
	if *offset+2 > len(data) {
		return 0, fmt.Errorf("message truncated: cannot decode uint16 at offset %d", *offset)
	}

	n := binary.LittleEndian.Uint16(data[*offset : *offset+2])
	*offset += 2
	return n, nil
}

// DecodeBytes reads a fixed-length byte slice from the message at the given offset and advances the offset
func DecodeBytes(data []byte, offset *int, length int) ([]byte, error) {
	if *offset+length > len(data) {
		return nil, fmt.Errorf("message truncated: cannot decode %d bytes at offset %d", length, *offset)
	}

	bytes := make([]byte, length)
	copy(bytes, data[*offset:*offset+length])
	*offset += length
	return bytes, nil
}

// DecodeHash reads a 32-byte hash from the message at the given offset and advances the offset
func DecodeHash(data []byte, offset *int) ([32]byte, error) {
	var hash [32]byte

	bytes, err := DecodeBytes(data, offset, 32)
	if err != nil {
		return hash, err
	}

	copy(hash[:], bytes)
	return hash, nil
}

// DecodeByteSliceWithLength reads a length-prefixed byte slice from the message at the given offset and advances the offset
func DecodeByteSliceWithLength(data []byte, offset *int) ([]byte, error) {
	length, err := DecodeUint32(data, offset)
	if err != nil {
		return nil, err
	}

	return DecodeBytes(data, offset, int(length))
}
