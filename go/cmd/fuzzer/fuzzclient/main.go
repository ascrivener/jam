package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/fuzzinterface"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/serializer"
)

// FuzzerClient connects to a JAM protocol server and tests its implementation
type FuzzerClient struct {
	conn       net.Conn
	socketPath string
	peerInfo   fuzzinterface.PeerInfo
}

type StateWithRoot struct {
	StateRoot [32]byte
	State     merklizer.State
}

// TestVector represents a complete state transition test vector
type TestVector struct {
	PreState  StateWithRoot `json:"pre_state"`
	Block     block.Block   `json:"block"`
	PostState StateWithRoot `json:"post_state"`
}

// NewFuzzerClient creates a new fuzzer client
func NewFuzzerClient(socketPath string) *FuzzerClient {
	return &FuzzerClient{
		socketPath: socketPath,
	}
}

// Connect establishes a connection to the server
func (fc *FuzzerClient) Connect() error {
	conn, err := net.Dial("unix", fc.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	fc.conn = conn

	// Setup peer info before handshake
	fc.setupPeerInfo()

	// Perform initial handshake
	if err := fc.handshake(); err != nil {
		fc.conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	return nil
}

// Disconnect closes the connection
func (fc *FuzzerClient) Disconnect() {
	if fc.conn != nil {
		fc.conn.Close()
	}
}

// handshake performs the initial PeerInfo exchange
func (fc *FuzzerClient) handshake() error {
	log.Println("Performing handshake with server...")

	// Send our PeerInfo
	req := fuzzinterface.RequestMessage{PeerInfo: &fc.peerInfo}
	if err := fc.sendMessage(req); err != nil {
		return fmt.Errorf("failed to send PeerInfo: %w", err)
	}

	// Receive server's PeerInfo
	resp, err := fc.receiveResponse()
	if err != nil {
		return fmt.Errorf("failed to receive PeerInfo response: %w", err)
	}

	if resp.PeerInfo == nil {
		return fmt.Errorf("server did not respond with PeerInfo")
	}

	log.Printf("Connected to server: %s (JAM v%d.%d.%d)",
		string(resp.PeerInfo.Name),
		resp.PeerInfo.JamVersion.Major, resp.PeerInfo.JamVersion.Minor, resp.PeerInfo.JamVersion.Patch)

	return nil
}

func (fc *FuzzerClient) setupPeerInfo() {
	fc.peerInfo.Name = []byte("test-fuzzer")
	fc.peerInfo.AppVersion = fuzzinterface.Version{
		Major: 0,
		Minor: 1,
		Patch: 0,
	}
	fc.peerInfo.JamVersion = fuzzinterface.Version{
		Major: 0,
		Minor: 6,
		Patch: 6,
	}
}

// encodeRequestMessage encodes a request message according to the JAM protocol format
func encodeRequestMessage(msg fuzzinterface.RequestMessage) ([]byte, error) {
	var encodedMessage []byte
	var msgType fuzzinterface.RequestMessageType

	switch {
	case msg.PeerInfo != nil:
		encodedMessage = serializer.Serialize(*msg.PeerInfo)
		msgType = fuzzinterface.RequestMessageTypePeerInfo
	case msg.ImportBlock != nil:
		encodedMessage = serializer.Serialize(*msg.ImportBlock)
		msgType = fuzzinterface.RequestMessageTypeImportBlock
	case msg.SetState != nil:
		encodedMessage = serializer.Serialize(*msg.SetState)
		msgType = fuzzinterface.RequestMessageTypeSetState
	case msg.GetState != nil:
		encodedMessage = serializer.Serialize(*msg.GetState)
		msgType = fuzzinterface.RequestMessageTypeGetState
	default:
		return nil, fmt.Errorf("unknown message type")
	}

	// Prefix with message type
	result := append([]byte{byte(msgType)}, encodedMessage...)

	// Calculate length and prefix it
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(len(result)))
	return append(lengthBytes, result...), nil
}

// decodeResponseMessage decodes a response message according to the JAM protocol format
func decodeResponseMessage(data []byte) (fuzzinterface.ResponseMessage, error) {
	// First byte is the message type
	if len(data) < 1 {
		return fuzzinterface.ResponseMessage{}, fmt.Errorf("message too short")
	}

	// Get the message type
	msgType := fuzzinterface.ResponseMessageType(data[0])

	// Skip the type byte
	data = data[1:]

	var msg fuzzinterface.ResponseMessage
	var err error

	switch msgType {
	case fuzzinterface.ResponseMessageTypePeerInfo:
		var peerInfo fuzzinterface.PeerInfo
		err = serializer.Deserialize(data, &peerInfo)
		if err != nil {
			return fuzzinterface.ResponseMessage{}, err
		}
		msg.PeerInfo = &peerInfo
	case fuzzinterface.ResponseMessageTypeState:
		var state merklizer.State
		err = serializer.Deserialize(data, &state)
		if err != nil {
			return fuzzinterface.ResponseMessage{}, err
		}
		msg.State = &state
	case fuzzinterface.ResponseMessageTypeStateRoot:
		var stateRoot fuzzinterface.StateRoot
		err = serializer.Deserialize(data, &stateRoot)
		if err != nil {
			return fuzzinterface.ResponseMessage{}, err
		}
		msg.StateRoot = &stateRoot
	default:
		return fuzzinterface.ResponseMessage{}, fmt.Errorf("unknown message type: %d", msgType)
	}

	return msg, nil
}

// sendMessage sends a request message to the server
func (fc *FuzzerClient) sendMessage(msg fuzzinterface.RequestMessage) error {
	data, err := encodeRequestMessage(msg)
	if err != nil {
		return err
	}

	_, err = fc.conn.Write(data)
	return err
}

// receiveResponse receives and decodes a response from the server
func (fc *FuzzerClient) receiveResponse() (fuzzinterface.ResponseMessage, error) {
	// Read message length (4 bytes, little-endian)
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(fc.conn, lengthBytes); err != nil {
		return fuzzinterface.ResponseMessage{}, err
	}
	messageLength := binary.LittleEndian.Uint32(lengthBytes)

	// Read message data
	messageData := make([]byte, messageLength)
	if _, err := io.ReadFull(fc.conn, messageData); err != nil {
		return fuzzinterface.ResponseMessage{}, err
	}

	return decodeResponseMessage(messageData)
}

// RunTests executes a series of tests against the server
func (fc *FuzzerClient) RunTests(vectorsDir string) {
	// Run tests
	fc.testStateTransitions(vectorsDir)
}

// testStateTransitions tests state transitions against test vectors
func (fc *FuzzerClient) testStateTransitions(vectorsDir string) {
	log.Println("Testing state transitions using test vectors...")

	// Get all test vectors from the reports-l0 directory
	genesisVectorPath := filepath.Join(vectorsDir, "genesis.bin")
	genesisVectorData, err := os.ReadFile(genesisVectorPath)
	if err != nil {
		log.Printf("Failed to load genesis vector file: %v", err)
		return
	}

	setState := fuzzinterface.SetState{}
	if err := serializer.Deserialize(genesisVectorData, &setState); err != nil {
		log.Printf("Failed to deserialize genesis vector: %v", err)
		return
	}

	log.Printf("Setting initial genesis state...")
	err = fc.sendMessage(fuzzinterface.RequestMessage{SetState: &setState})
	if err != nil {
		log.Printf("Failed to send SetState message: %v", err)
		return
	}

	// Receive state root response
	resp, err := fc.receiveResponse()
	if err != nil {
		log.Printf("Failed to receive response: %v", err)
		return
	}

	if resp.StateRoot == nil {
		log.Printf("Server did not respond with StateRoot")
		return
	}

	if *resp.StateRoot != setState.StateWithRoot.StateRoot {
		log.Printf("State root mismatch: %x != %x", *resp.StateRoot, setState.StateWithRoot.StateRoot)
		return
	}
	log.Printf("Genesis state set successfully, state root: %x", *resp.StateRoot)

	vectorFiles, err := os.ReadDir(vectorsDir)
	if err != nil {
		log.Printf("Failed to read test vectors directory: %v", err)
		return
	}
	// Sort files by name to ensure proper sequence
	var fileNames []string
	for _, fileInfo := range vectorFiles {
		// Skip directories and the genesis file which we've already processed
		if fileInfo.IsDir() || !strings.HasSuffix(fileInfo.Name(), ".bin") || fileInfo.Name() == "genesis.bin" {
			continue
		}
		fileNames = append(fileNames, fileInfo.Name())
	}
	sort.Strings(fileNames)

	log.Printf("Processing %d test vectors...", len(fileNames))
	for i, fileName := range fileNames {
		log.Printf("[%d/%d] Processing test vector: %s", i+1, len(fileNames), fileName)

		vectorPath := filepath.Join(vectorsDir, fileName)
		vectorData, err := os.ReadFile(vectorPath)
		if err != nil {
			log.Printf("Failed to load test vector file: %v", err)
			return
		}

		testVector := TestVector{}
		if err := serializer.Deserialize(vectorData, &testVector); err != nil {
			log.Printf("Failed to deserialize test vector: %v", err)
			return
		}

		importBlock := fuzzinterface.ImportBlock(testVector.Block)

		// Start timing the block import and response
		importStartTime := time.Now()

		err = fc.sendMessage(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			log.Printf("Failed to send ImportBlock message: %v", err)
			return
		}

		// Receive state root response
		resp, err := fc.receiveResponse()
		if err != nil {
			log.Printf("Failed to receive response: %v", err)
			return
		}

		importDuration := time.Since(importStartTime)
		log.Printf("Block import and response took %v", importDuration)

		if resp.StateRoot == nil {
			log.Printf("Server did not respond with StateRoot")
			return
		}

		if *resp.StateRoot != testVector.PostState.StateRoot {
			log.Printf("State root mismatch: %x != %x", *resp.StateRoot, testVector.PostState.StateRoot)
			headerHash := sha256.Sum256(serializer.Serialize(testVector.Block.Header))
			getState := fuzzinterface.GetState(headerHash)
			err = fc.sendMessage(fuzzinterface.RequestMessage{GetState: &getState})
			if err != nil {
				log.Printf("Failed to send GetState message: %v", err)
				return
			}

			// Receive state response
			resp, err := fc.receiveResponse()
			if err != nil {
				log.Printf("Failed to receive response: %v", err)
				return
			}

			if resp.State == nil {
				log.Printf("Server did not respond with State")
				return
			}

			log.Printf("State: %x", *resp.State)

			return
		}
		log.Printf("✓ State root verified: %x", *resp.StateRoot)
	}
	log.Printf("All test vectors processed successfully!")
}

func main() {
	// Parse command line arguments
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path for the Unix domain socket")
	vectorsPath := flag.String("vectors", "/Users/adamscrivener/Projects/Jam/jam-test-vectors/traces/reports-l1", "Path to the test vectors directory")
	flag.Parse()

	log.Printf("Starting fuzzer client")
	log.Printf("Socket path: %s", *socketPath)
	log.Printf("Test vectors: %s", *vectorsPath)

	fuzzer := NewFuzzerClient(*socketPath)
	if err := fuzzer.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	fuzzer.RunTests(*vectorsPath)
	log.Println("All tests completed")
}
