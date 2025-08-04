package net

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Message represents a JAMNP-S protocol message
type Message struct {
	Size    uint32
	Content []byte
}

// ReadMessage reads a message from a reader
func ReadMessage(r io.Reader) ([]byte, error) {
	// Read message size (4 bytes, little endian)
	sizeBuffer := make([]byte, 4)
	_, err := io.ReadFull(r, sizeBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read message size: %w", err)
	}

	// Parse message size
	messageSize := binary.LittleEndian.Uint32(sizeBuffer)

	// Read message content
	message := make([]byte, messageSize)
	_, err = io.ReadFull(r, message)
	if err != nil {
		return nil, fmt.Errorf("failed to read message content: %w", err)
	}

	return message, nil
}

// WriteMessage writes a message to a writer
func WriteMessage(w io.Writer, data []byte) error {
	// Create size header (4 bytes, little endian)
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer, uint32(len(data)))

	// Write size header
	_, err := w.Write(sizeBuffer)
	if err != nil {
		return fmt.Errorf("failed to write message size: %w", err)
	}

	// Write message content
	_, err = w.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write message content: %w", err)
	}

	return nil
}

// EncodeBlockAnnouncement encodes a block announcement message
func EncodeBlockAnnouncement(announcement *BlockAnnouncement) []byte {
	// Calculate total size:
	// 4 bytes for header count + sum of (4 bytes length + header) for each header
	// + 32 bytes for finalized hash + 4 bytes for finalized slot
	totalSize := 4 + 36
	for _, header := range announcement.Headers {
		totalSize += 4 + len(header)
	}

	// Allocate buffer
	data := make([]byte, totalSize)
	pos := 0

	// Write header count
	binary.LittleEndian.PutUint32(data[pos:pos+4], uint32(len(announcement.Headers)))
	pos += 4

	// Write headers
	for _, header := range announcement.Headers {
		binary.LittleEndian.PutUint32(data[pos:pos+4], uint32(len(header)))
		pos += 4
		copy(data[pos:pos+len(header)], header)
		pos += len(header)
	}

	// Write finalized block info
	copy(data[pos:pos+32], announcement.FinalizedRef.Hash)
	pos += 32
	binary.LittleEndian.PutUint32(data[pos:pos+4], announcement.FinalizedRef.Slot)

	return data
}

// EncodeStateRequest encodes a state request message
func EncodeStateRequest(options *StateRequestOptions) []byte {
	data := make([]byte, 32+31+31+4) // state root + start key + end key + max size

	// State root (32 bytes)
	copy(data[0:32], options.StateRoot)

	// Start key (31 bytes)
	if len(options.StartKey) > 0 {
		copy(data[32:63], options.StartKey)
	}

	// End key (31 bytes)
	if len(options.EndKey) > 0 {
		copy(data[63:94], options.EndKey)
	} else {
		// If no end key specified, use 0xFF... (get all keys)
		for i := 63; i < 94; i++ {
			data[i] = 0xFF
		}
	}

	// Maximum size (4 bytes)
	binary.LittleEndian.PutUint32(data[94:98], options.MaximumSize)

	return data
}

// ParseStateResponse parses a state response
func ParseStateResponse(boundaryNodesData, kvPairsData []byte) (*StateResponse, error) {
	response := &StateResponse{
		BoundaryNodes: boundaryNodesData,
		KeyValuePairs: []KeyValuePair{},
	}

	// Parse key/value pairs
	kvPairs, err := parseKeyValuePairs(kvPairsData)
	if err != nil {
		return nil, err
	}
	response.KeyValuePairs = kvPairs

	return response, nil
}

// parseKeyValuePairs parses key/value pairs from binary data
func parseKeyValuePairs(data []byte) ([]KeyValuePair, error) {
	var pairs []KeyValuePair
	var pos uint32 = 0
	dataSize := uint32(len(data))

	for pos+31 < dataSize {
		// Each key is 31 bytes
		if pos+31 > dataSize {
			break
		}
		key := make([]byte, 31)
		copy(key, data[pos:pos+31])
		pos += 31

		// Value length is a u32
		if pos+4 > dataSize {
			break
		}

		// Try to detect endianness - first check little endian
		lenBytes := data[pos : pos+4]
		valueLen := binary.LittleEndian.Uint32(lenBytes)

		// If value length seems unreasonable, try big endian
		if valueLen > 100000 || pos+4+valueLen > dataSize {
			valueLen = binary.BigEndian.Uint32(lenBytes)

			// If still unreasonable, use a safe default
			if valueLen > 100000 || pos+4+valueLen > dataSize {
				// Special case: if first bytes are zero, likely a small big-endian number
				if lenBytes[0] == 0 && lenBytes[1] == 0 && lenBytes[2] == 0 {
					valueLen = uint32(lenBytes[3])
				} else {
					// Safe default - read what we can
					valueLen = dataSize - (pos + 4)
					if valueLen > 1024 {
						valueLen = 1024 // Cap at 1KB if too large
					}
				}
			}
		}

		pos += 4 // Skip the length bytes

		// Final safety check
		if pos+valueLen > dataSize {
			valueLen = dataSize - pos
		}

		// Extract the value
		value := make([]byte, valueLen)
		copy(value, data[pos:pos+valueLen])
		pos += valueLen

		// Add to result
		pairs = append(pairs, KeyValuePair{
			Key:   key,
			Value: value,
		})
	}

	return pairs, nil
}

// EncodeWorkReportRequest encodes a work report request
func EncodeWorkReportRequest(hash [32]byte) []byte {
	data := make([]byte, 32)
	copy(data, hash[:])
	return data
}
