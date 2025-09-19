package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"jam/pkg/block"
	"jam/pkg/fuzzinterface"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
)

// TestVector represents a complete state transition test vector
type TestVector struct {
	PreState  StateWithRoot `json:"pre_state"`
	Block     block.Block   `json:"block"`
	PostState StateWithRoot `json:"post_state"`
}

type StateWithRoot struct {
	StateRoot [32]byte `json:"state_root"`
	State     merklizer.State
}

func main() {
	socketPath := "/tmp/jam_target.sock"
	baseDir := "/Users/adamscrivener/Projects/Jam/jam/jam-conformance/fuzz-reports/0.7.0/traces/1757406441"

	// First send peer_info, then the specific files
	files := []string{
		"/Users/adamscrivener/Projects/Jam/jam/jam-conformance/fuzz-proto/examples/v1/no_forks/00000000_fuzzer_peer_info.bin",
		"00000116.bin",
		"00000117.bin",
	}

	// Connect to the Unix socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("Error connecting to socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", socketPath)

	// Send each file
	for i, filename := range files {
		var data []byte

		if i == 0 {
			// First file is peer_info - send as-is
			filePath := filename
			fmt.Printf("\n[%d/%d] Sending file: %s\n", i+1, len(files), filepath.Base(filePath))

			data, err = os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", filename, err)
				continue
			}
		} else {
			// Parse .bin file as TestVector and extract block
			filePath := filepath.Join(baseDir, filename)
			fmt.Printf("\n[%d/%d] Processing test vector: %s\n", i+1, len(files), filePath)

			vectorData, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", filename, err)
				continue
			}

			fmt.Println(len(vectorData))

			testVector := TestVector{}
			if err := serializer.Deserialize(vectorData, &testVector); err != nil {
				fmt.Printf("Failed to deserialize test vector %s: %v\n", filename, err)
				continue
			}

			// Determine message type based on file index
			var messageType byte
			var messageData []byte
			if i == 1 {
				messageType = 1 // RequestMessageTypeInitialize for first test vector
				// Create Initialize message structure
				initMessage := fuzzinterface.Initialize{
					Header:   testVector.Block.Header,
					State:    testVector.PostState.State,
					Ancestry: []fuzzinterface.AncestryItem{}, // Empty ancestry for now
				}

				messageData = serializer.Serialize(initMessage)
			} else {
				messageType = 3 // RequestMessageTypeImportBlock for subsequent test vectors
				messageData = serializer.Serialize(testVector.Block)
			}

			// Prepend with the appropriate message type
			data = make([]byte, 1+len(messageData))
			data[0] = messageType
			copy(data[1:], messageData)
		}

		// Send length (4 bytes, little endian)
		lengthBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lengthBytes, uint32(len(data)))

		_, err = conn.Write(lengthBytes)
		if err != nil {
			fmt.Printf("Error sending length for %s: %v\n", filename, err)
			break
		}

		// Send data
		_, err = conn.Write(data)
		if err != nil {
			fmt.Printf("Error sending data for %s: %v\n", filename, err)
			break
		}

		fmt.Printf("Sent %d bytes for %s\n", len(data), filename)

		// Read response length
		responseLengthBytes := make([]byte, 4)
		_, err = conn.Read(responseLengthBytes)
		if err != nil {
			fmt.Printf("Error reading response length for %s: %v\n", filename, err)
			break
		}

		responseLength := binary.LittleEndian.Uint32(responseLengthBytes)
		fmt.Printf("Response length: %d bytes\n", responseLength)

		// Read response data
		responseData := make([]byte, responseLength)
		_, err = conn.Read(responseData)
		if err != nil {
			fmt.Printf("Error reading response for %s: %v\n", filename, err)
			break
		}

		fmt.Printf("Received response: %x\n", responseData)

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("\nAll files sent successfully!")
}
