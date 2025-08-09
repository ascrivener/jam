package main

import (
	"bytes"
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

	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/fuzzinterface"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
	"jam/pkg/state"
	"jam/pkg/staterepository"

	"github.com/google/go-cmp/cmp"
)

// FuzzerClient connects to a JAM protocol server and tests its implementation
type FuzzerClient struct {
	conn       net.Conn
	socketPath string
	peerInfo   fuzzinterface.PeerInfo
	// In-process mode fields
	inProcess bool
	server    *fuzzinterface.Server
}

type StateWithRoot struct {
	StateRoot [32]byte
	State     merklizer.State
}

type GenesisVector struct {
	Header        header.Header
	StateWithRoot StateWithRoot
}

// TestVector represents a complete state transition test vector
type TestVector struct {
	PreState  StateWithRoot `json:"pre_state"`
	Block     block.Block   `json:"block"`
	PostState StateWithRoot `json:"post_state"`
}

// NewFuzzerClient creates a new fuzzer client
func NewFuzzerClient(socketPath string, inProcess bool) *FuzzerClient {
	fc := &FuzzerClient{
		socketPath: socketPath,
		inProcess:  inProcess,
	}

	if inProcess {
		fc.server = fuzzinterface.NewServer()
	}

	return fc
}

// Connect establishes a connection to the server or initializes in-process mode
func (fc *FuzzerClient) Connect() error {
	if fc.inProcess {
		log.Println("Running in in-process mode - no socket connection needed")
		// Initialize state repository for in-process mode
		return staterepository.InitializeGlobalRepository("")
	}

	conn, err := net.Dial("unix", fc.socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to socket %s: %w", fc.socketPath, err)
	}
	fc.conn = conn
	log.Printf("Connected to server at %s", fc.socketPath)

	// Setup peer info before handshake
	fc.setupPeerInfo()

	// Perform handshake
	if err := fc.handshake(); err != nil {
		fc.conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	return nil
}

// Disconnect closes the connection or cleans up in-process mode
func (fc *FuzzerClient) Disconnect() {
	if fc.inProcess {
		staterepository.CloseGlobalRepository()
		log.Println("In-process mode cleaned up")
		return
	}

	if fc.conn != nil {
		fc.conn.Close()
		log.Println("Disconnected from server")
	}
}

// handshake performs the initial PeerInfo exchange
func (fc *FuzzerClient) handshake() error {
	log.Println("Performing handshake...")

	// Send our PeerInfo
	req := fuzzinterface.RequestMessage{PeerInfo: &fc.peerInfo}
	resp, err := fc.sendAndReceive(req)
	if err != nil {
		return fmt.Errorf("failed to send PeerInfo: %w", err)
	}

	if resp.PeerInfo == nil {
		return fmt.Errorf("server did not respond with PeerInfo")
	}

	log.Printf("Handshake successful with peer: %s", string(resp.PeerInfo.Name))
	return nil
}

func (fc *FuzzerClient) setupPeerInfo() {
	fc.peerInfo = fuzzinterface.PeerInfo{
		Name: []byte("fuzzer-client"),
		AppVersion: fuzzinterface.Version{
			Major: 0,
			Minor: 1,
			Patch: 0,
		},
		JamVersion: fuzzinterface.Version{
			Major: 0,
			Minor: 6,
			Patch: 6,
		},
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

// sendAndReceive sends a message and receives response (works for both modes)
func (fc *FuzzerClient) sendAndReceive(msg fuzzinterface.RequestMessage) (fuzzinterface.ResponseMessage, error) {
	if fc.inProcess {
		// Process message directly using server
		return fc.server.HandleMessage(msg)
	}

	// Use existing socket-based communication
	if err := fc.sendMessage(msg); err != nil {
		return fuzzinterface.ResponseMessage{}, err
	}
	return fc.receiveResponse()
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

	genesisVector := GenesisVector{}
	if err := serializer.Deserialize(genesisVectorData, &genesisVector); err != nil {
		log.Printf("Failed to deserialize genesis vector: %v", err)
		return
	}

	log.Printf("Setting initial genesis state...")
	resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{SetState: &fuzzinterface.SetState{Header: genesisVector.Header, State: genesisVector.StateWithRoot.State}})
	if err != nil {
		log.Printf("Failed to send SetState message: %v", err)
		return
	}

	if resp.StateRoot == nil {
		log.Printf("SetState failed: no state root returned")
		return
	}

	if *resp.StateRoot != genesisVector.StateWithRoot.StateRoot {
		log.Printf("SetState failed: state root mismatch")
		return
	}

	log.Printf("Genesis state set successfully")

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
	filedTests := []string{}
	for i, fileName := range fileNames {
		log.Printf("[%d/%d] Processing test vector: %s", i+1, len(fileNames), fileName)
		// if err := pvm.InitFileLogger("pvm." + fileName + ".log"); err != nil {
		// 	log.Printf("Failed to initialize file logger: %v", err)
		// 	return
		// }
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

		resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			log.Printf("Failed to send ImportBlock message: %v", err)
			return
		}

		importDuration := time.Since(importStartTime)
		log.Printf("Block %d imported in %v", i, importDuration)

		if resp.StateRoot == nil {
			log.Printf("No state root returned from ImportBlock")
			return
		}

		log.Printf("Block %d imported in %v, state root: %x", i, importDuration, *resp.StateRoot)

		// Verify the state root matches expected
		if *resp.StateRoot != testVector.PostState.StateRoot {
			filedTests = append(filedTests, fileName)
			log.Printf("State root mismatch: %x != %x", *resp.StateRoot, testVector.PostState.StateRoot)
			headerHash := sha256.Sum256(serializer.Serialize(testVector.Block.Header))
			getState := fuzzinterface.GetState(headerHash)
			getStateResponse, err := fc.sendAndReceive(fuzzinterface.RequestMessage{GetState: &getState})
			if err != nil {
				log.Printf("Failed to send GetState message: %v", err)
				return
			}

			if getStateResponse.State == nil {
				log.Printf("GetState failed: no state returned")
				return
			}

			expectedState, err := state.GetStateFromKVs(testVector.PostState.State)
			if err != nil {
				log.Printf("Failed to get state from KVs: %v", err)
				return
			}

			actualState, err := state.GetStateFromKVs(*getStateResponse.State)
			if err != nil {
				log.Printf("Failed to get state from KVs: %v", err)
				return
			}

			// compare expectedState with actualState
			if diff := cmp.Diff(expectedState, actualState); diff != "" {
				log.Printf("✗ State comparison failed:")
				log.Printf("State mismatch (-expected +actual):\n%s", diff)
			} else {
				log.Printf("✓ State comparison passed: states are identical")
			}
			// Compare the underlying KVs to show any differences
			compareKVs(testVector.PostState.State, *getStateResponse.State)
		} else {
			log.Printf("✓ State root verified: %x", *resp.StateRoot)
		}
	}
	if len(filedTests) > 0 {
		log.Printf("Failed tests: %v", filedTests)
	} else {
		log.Printf("All test vectors processed successfully!")
	}
}

func compareKVs(expectedKVs, actualKVs merklizer.State) {
	// Compare the underlying KVs to show any differences
	expectedKVsMap := make(map[[31]byte][]byte)
	for _, kv := range expectedKVs {
		expectedKVsMap[kv.OriginalKey] = kv.Value
	}

	actualKVsMap := make(map[[31]byte][]byte)
	for _, kv := range actualKVs {
		actualKVsMap[kv.OriginalKey] = kv.Value
	}

	missingKVs := make([][31]byte, 0)
	extraKVs := make([][31]byte, 0)
	differentValues := make([][31]byte, 0)

	for key := range expectedKVsMap {
		if _, ok := actualKVsMap[key]; !ok {
			missingKVs = append(missingKVs, key)
		}
	}

	for key := range actualKVsMap {
		if _, ok := expectedKVsMap[key]; !ok {
			extraKVs = append(extraKVs, key)
		}
	}

	// Check for keys with different values
	for key, expectedValue := range expectedKVsMap {
		if actualValue, exists := actualKVsMap[key]; exists {
			if !bytes.Equal(expectedValue, actualValue) {
				differentValues = append(differentValues, key)
			}
		}
	}

	if len(missingKVs) > 0 {
		log.Printf("Missing KVs:")
		for _, key := range missingKVs {
			log.Printf("- %x: %x", key, expectedKVsMap[key])
		}
	}

	if len(extraKVs) > 0 {
		log.Printf("Extra KVs:")
		for _, key := range extraKVs {
			log.Printf("+ %x: %x", key, actualKVsMap[key])
		}
	}

	if len(differentValues) > 0 {
		log.Printf("Keys with different values:")
		for _, key := range differentValues {
			log.Printf("~ %x:", key)
			log.Printf("  Expected: %x", expectedKVsMap[key])
			log.Printf("  Actual:   %x", actualKVsMap[key])
		}
	}

	if len(missingKVs) == 0 && len(extraKVs) == 0 && len(differentValues) == 0 {
		log.Printf("KV comparison passed: KVs are identical")
	} else {
		log.Printf("KV comparison failed")
	}
}

func main() {
	// Parse command line arguments
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path for the Unix domain socket")
	vectorsPath := flag.String("vectors", "/Users/adamscrivener/Projects/Jam/jam-test-vectors/traces/fallback", "Path to the test vectors directory")
	inProcess := flag.Bool("in-process", false, "Run in in-process mode (no socket communication)")
	flag.Parse()

	if *inProcess {
		log.Printf("Starting fuzzer client in IN-PROCESS mode")
	} else {
		log.Printf("Starting fuzzer client in SOCKET mode")
		log.Printf("Socket path: %s", *socketPath)
	}
	log.Printf("Test vectors: %s", *vectorsPath)

	fuzzer := NewFuzzerClient(*socketPath, *inProcess)
	if err := fuzzer.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	fuzzer.RunTests(*vectorsPath)
	log.Println("All tests completed")
}
