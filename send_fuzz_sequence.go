package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	socketPath := "/tmp/jam_target.sock"
	baseDir := "/Users/adamscrivener/Projects/Jam/jam/jam-conformance/fuzz-proto/examples/v1"

	files := []string{
		"00000000_fuzzer_peer_info.bin",
		"00000001_fuzzer_initialize.bin",
		"00000002_fuzzer_import_block.bin",
	}

	// Connect to the Unix socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("Failed to connect to socket %s: %v\n", socketPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Connected to JAM fuzzserver at %s\n", socketPath)

	// Send each file in sequence
	for i, filename := range files {
		fmt.Printf("\n[%d/%d] Sending %s...\n", i+1, len(files), filename)

		filePath := filepath.Join(baseDir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Failed to read file %s: %v\n", filePath, err)
			continue
		}

		// Send length prefix (4 bytes little-endian) + data
		lengthBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lengthBytes, uint32(len(data)))

		// Send length prefix
		_, err = conn.Write(lengthBytes)
		if err != nil {
			fmt.Printf("Failed to send length prefix for %s: %v\n", filename, err)
			continue
		}

		// Send data
		_, err = conn.Write(data)
		if err != nil {
			fmt.Printf("Failed to send data for %s: %v\n", filename, err)
			continue
		}

		fmt.Printf("✓ Sent %s (%d bytes)\n", filename, len(data))

		// Read response
		responseLength := make([]byte, 4)
		_, err = conn.Read(responseLength)
		if err != nil {
			fmt.Printf("Failed to read response length for %s: %v\n", filename, err)
			continue
		}

		respLen := binary.LittleEndian.Uint32(responseLength)
		if respLen > 0 {
			response := make([]byte, respLen)
			_, err = conn.Read(response)
			if err != nil {
				fmt.Printf("Failed to read response for %s: %v\n", filename, err)
				continue
			}
			fmt.Printf("← Response: %d bytes (first few: %x...)\n", respLen, response[:min(8, len(response))])
		} else {
			fmt.Printf("← No response data\n")
		}

		// Small delay between messages
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("\n✓ All files sent successfully!\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
