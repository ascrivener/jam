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
	"strconv"
	"strings"
	"testing"
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
		Name: []byte("fuzzer-client"),
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
	case msg.Initialize != nil:
		encodedMessage = serializer.Serialize(*msg.Initialize)
		msgType = fuzzinterface.RequestMessageTypeInitialize
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
	data, err := encodeRequestMessage(msg)
	if err != nil {
		return fuzzinterface.ResponseMessage{}, err
	}

	if fc.inProcess {
		// Process message directly using server
		// skip length bytes
		return fc.server.HandleMessageData(data[4:])
	}

	_, err = fc.conn.Write(data)
	if err != nil {
		return fuzzinterface.ResponseMessage{}, err
	}
	return fc.receiveResponse()
}

// testStateTransitions tests state transitions against test vectors
func (fc *FuzzerClient) testStateTransitions(t *testing.T, vectorsDir string) {
	t.Log("Testing state transitions using test vectors...")

	// Get all test vectors from the reports-l0 directory
	genesisVectorPath := filepath.Join(vectorsDir, "genesis.bin")
	genesisVectorData, err := os.ReadFile(genesisVectorPath)
	if err != nil {
		t.Fatalf("Failed to load genesis vector file: %v", err)
	}

	genesisVector := GenesisVector{}
	if err := serializer.Deserialize(genesisVectorData, &genesisVector); err != nil {
		t.Fatalf("Failed to deserialize genesis vector: %v", err)
	}

	t.Log("Setting initial genesis state...")
	resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{Initialize: &fuzzinterface.Initialize{Header: genesisVector.Header, State: genesisVector.StateWithRoot.State}})
	if err != nil {
		t.Fatalf("Failed to send Initialize message: %v", err)
	}

	if resp.StateRoot == nil {
		t.Fatal("SetState failed: no state root returned")
	}
	if resp.StateRoot == nil {
		t.Fatal("SetState failed: no state root returned")
	}

	if *resp.StateRoot != genesisVector.StateWithRoot.StateRoot {
		t.Fatalf("SetState failed: state root mismatch - expected %x, got %x", genesisVector.StateWithRoot.StateRoot, *resp.StateRoot)
	}

	t.Log("Genesis state set successfully")

	vectorFiles, err := os.ReadDir(vectorsDir)
	if err != nil {
		t.Fatalf("Failed to read test vectors directory: %v", err)
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

	t.Logf("Processing %d test vectors...", len(fileNames))
	failedTests := []string{}
	for i, fileName := range fileNames {
		t.Logf("[%d/%d] Processing test vector: %s", i+1, len(fileNames), fileName)

		vectorPath := filepath.Join(vectorsDir, fileName)
		vectorData, err := os.ReadFile(vectorPath)
		if err != nil {
			t.Errorf("Failed to load test vector file %s: %v", fileName, err)
			failedTests = append(failedTests, fileName)
			continue
		}

		testVector := TestVector{}
		if err := serializer.Deserialize(vectorData, &testVector); err != nil {
			t.Errorf("Failed to deserialize test vector %s: %v", fileName, err)
			failedTests = append(failedTests, fileName)
			continue
		}

		importBlock := fuzzinterface.ImportBlock(testVector.Block)

		// Start timing the block import and response
		importStartTime := time.Now()

		resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			t.Errorf("Failed to send ImportBlock message for %s: %v", fileName, err)
			failedTests = append(failedTests, fileName)
			continue
		}

		importDuration := time.Since(importStartTime)
		t.Logf("Block %d imported in %v", i, importDuration)

		if resp.StateRoot == nil {
			t.Errorf("No state root returned from ImportBlock for %s", fileName)
			failedTests = append(failedTests, fileName)
			continue
		}

		t.Logf("Block %d imported in %v, state root: %x", i, importDuration, *resp.StateRoot)

		// Verify the state root matches expected
		if *resp.StateRoot != testVector.PostState.StateRoot {
			failedTests = append(failedTests, fileName)
			t.Errorf("State root mismatch for %s: expected %x, got %x", fileName, testVector.PostState.StateRoot, *resp.StateRoot)

			headerHash := sha256.Sum256(serializer.Serialize(testVector.Block.Header))
			getState := fuzzinterface.GetState(headerHash)
			getStateResponse, err := fc.sendAndReceive(fuzzinterface.RequestMessage{GetState: &getState})
			if err != nil {
				t.Errorf("Failed to send GetState message for %s: %v", fileName, err)
				continue
			}

			if getStateResponse.State == nil {
				t.Errorf("GetState failed: no state returned for %s", fileName)
				continue
			}

			expectedState, err := state.GetStateFromKVs(testVector.PostState.State)
			if err != nil {
				t.Errorf("Failed to get expected state from KVs for %s: %v", fileName, err)
				continue
			}

			actualState, err := state.GetStateFromKVs(*getStateResponse.State)
			if err != nil {
				t.Errorf("Failed to get actual state from KVs for %s: %v", fileName, err)
				continue
			}

			// compare expectedState with actualState
			if diff := cmp.Diff(expectedState, actualState); diff != "" {
				t.Errorf("State comparison failed for %s:", fileName)
				t.Errorf("State mismatch (-expected +actual):\n%s", diff)
			} else {
				t.Logf("✓ State comparison passed for %s: states are identical", fileName)
			}
			// Compare the underlying KVs to show any differences
			compareKVs(t, testVector.PostState.State, *getStateResponse.State)
		} else {
			t.Logf("✓ State root verified for %s: %x", fileName, *resp.StateRoot)
		}
	}

	if len(failedTests) > 0 {
		t.Errorf("Failed tests: %v", failedTests)
	} else {
		t.Log("All test vectors processed successfully!")
	}
}

func (fc *FuzzerClient) testDisputes(t *testing.T, disputesDir string) {
	// Get all subdirectories in the disputes directory
	entries, err := os.ReadDir(disputesDir)
	if err != nil {
		t.Fatalf("Failed to read disputes directory %s: %v", disputesDir, err)
	}

	var testDirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			testDirs = append(testDirs, filepath.Join(disputesDir, entry.Name()))
		}
	}

	if len(testDirs) == 0 {
		t.Fatalf("No test directories found in %s", disputesDir)
	}

	t.Logf("Found %d test directories in %s", len(testDirs), disputesDir)

	// Run each test directory as a subtest
	for _, testDir := range testDirs {
		if !strings.Contains(testDir, "1757406441") {
			continue
		}
		testName := filepath.Base(testDir)
		t.Run(testName, func(t *testing.T) {
			fc.testIndividualVector(t, testDir)
		})
	}
}

// testStateTransitions tests state transitions against test vectors
func (fc *FuzzerClient) testIndividualVector(t *testing.T, vectorsDir string) {
	// Get all .bin files from the directory (excluding report.bin)
	binFiles, err := filepath.Glob(filepath.Join(vectorsDir, "*.bin"))
	if err != nil {
		t.Logf("Failed to list bin files: %v", err)
		return
	}

	// Filter out report.bin and sort the remaining files
	var testBinFiles []string
	for _, file := range binFiles {
		if !strings.HasSuffix(file, "report.bin") {
			testBinFiles = append(testBinFiles, file)
		}
	}
	sort.Strings(testBinFiles)

	if len(testBinFiles) < 2 {
		t.Logf("Need at least 2 test bin files, found %d", len(testBinFiles))
		return
	}

	// Use first bin file for warp vector
	warpVectorPath := testBinFiles[0]
	warpVectorData, err := os.ReadFile(warpVectorPath)
	if err != nil {
		t.Fatalf("Failed to load genesis vector file: %v", err)
	}

	warpVector := TestVector{}
	if err := serializer.Deserialize(warpVectorData, &warpVector); err != nil {
		t.Logf("Failed to deserialize genesis vector: %v", err)
	}

	t.Logf("Setting initial genesis state...")
	resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{Initialize: &fuzzinterface.Initialize{Header: warpVector.Block.Header, State: warpVector.PostState.State}})
	if err != nil {
		t.Fatalf("Failed to send Initialize message: %v", err)
	}

	if resp.StateRoot == nil {
		t.Fatalf("SetState failed: no state root returned")
	}

	t.Logf("State set successfully, state root: %x", *resp.StateRoot)

	if *resp.StateRoot != warpVector.PostState.StateRoot {
		t.Fatalf("State root mismatch: %x != %x", *resp.StateRoot, warpVector.PostState.StateRoot)
	}

	// Process all test files sequentially after the warp file
	for i := 1; i < len(testBinFiles); i++ {
		testVectorPath := testBinFiles[i]
		testFileName := filepath.Base(testVectorPath)

		t.Logf("Processing test file %d/%d: %s", i, len(testBinFiles)-1, testFileName)

		// Verify sequential numbering
		warpFileName := filepath.Base(testBinFiles[0])
		warpNumStr := strings.TrimSuffix(warpFileName, ".bin")
		testNumStr := strings.TrimSuffix(testFileName, ".bin")

		warpNum, err := strconv.Atoi(warpNumStr)
		if err != nil {
			t.Logf("Failed to parse warp file number from %s: %v", warpFileName, err)
			continue
		}

		testNum, err := strconv.Atoi(testNumStr)
		if err != nil {
			t.Logf("Failed to parse test file number from %s: %v", testFileName, err)
			continue
		}

		expectedNum := warpNum + i
		if testNum != expectedNum {
			t.Logf("Test file %s is not sequential (expected %d, got %d), skipping", testFileName, expectedNum, testNum)
			continue
		}

		testVectorData, err := os.ReadFile(testVectorPath)
		if err != nil {
			t.Fatalf("Failed to load test vector file %s: %v", testVectorPath, err)
		}

		testVector := TestVector{}
		if err := serializer.Deserialize(testVectorData, &testVector); err != nil {
			t.Fatalf("Failed to deserialize test vector from %s", testVectorPath)
		}

		importBlock := fuzzinterface.ImportBlock(testVector.Block)
		resp, err = fc.sendAndReceive(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			t.Logf("Failed to send ImportBlock message for %s: %v", testFileName, err)
			if resp.StateRoot != nil && *resp.StateRoot != testVector.PostState.StateRoot {
				t.Fatalf("State root mismatch for %s: %x != %x", testFileName, *resp.StateRoot, testVector.PostState.StateRoot)
			}
			continue
		}

		if resp.Error != nil {
			if testVector.PostState.StateRoot != testVector.PreState.StateRoot {
				t.Fatalf("ImportBlock failed for %s: %s", testFileName, string(*resp.Error))
			}
			t.Logf("✓ Test passed for %s! Error: %s", testFileName, string(*resp.Error))
			continue
		}

		if *resp.StateRoot != testVector.PostState.StateRoot {
			t.Errorf("State root mismatch for %s: %x != %x", testFileName, *resp.StateRoot, testVector.PostState.StateRoot)
			headerHash := sha256.Sum256(serializer.Serialize(testVector.Block.Header))
			getState := fuzzinterface.GetState(headerHash)
			getStateResponse, err := fc.sendAndReceive(fuzzinterface.RequestMessage{GetState: &getState})
			if err != nil {
				t.Errorf("Failed to send GetState message for %s: %v", testFileName, err)
				continue
			}

			if getStateResponse.State == nil {
				t.Errorf("GetState failed for %s: no state returned", testFileName)
				continue
			}

			expectedState, err := state.GetStateFromKVs(testVector.PostState.State)
			if err != nil {
				t.Errorf("Failed to get state from KVs for %s: %v", testFileName, err)
				continue
			}

			actualState, err := state.GetStateFromKVs(*getStateResponse.State)
			if err != nil {
				t.Errorf("Failed to get state from KVs for %s: %v", testFileName, err)
				continue
			}

			// compare expectedState with actualState
			if diff := cmp.Diff(expectedState, actualState); diff != "" {
				t.Errorf("✗ State comparison failed for %s:", testFileName)
				t.Errorf("State mismatch (-expected +actual):\n%s", diff)
			} else {
				t.Logf("✓ State comparison passed for %s: states are identical", testFileName)
			}
			// Compare the underlying KVs to show any differences
			compareKVs(t, testVector.PostState.State, *getStateResponse.State)
		} else {
			t.Logf("✓ Test passed for %s! State root matches: %x", testFileName, *resp.StateRoot)
		}
	}
}

func (fc *FuzzerClient) testFuzzerVersion(t *testing.T, dir string) {
	// Use first bin file for warp vector
	peerInfoPath := filepath.Join(dir, "00000000_fuzzer_peer_info.bin")
	peerInfoData, err := os.ReadFile(peerInfoPath)
	if err != nil {
		t.Fatalf("Failed to load peer info file: %v", err)
	}

	peerInfo := fuzzinterface.PeerInfo{}
	if err := serializer.Deserialize(peerInfoData[1:], &peerInfo); err != nil {
		t.Fatalf("Failed to deserialize peer info: %v", err)
	}

	resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{PeerInfo: &peerInfo})
	if err != nil {
		t.Fatalf("Failed to send PeerInfo: %v", err)
	}

	if resp.PeerInfo == nil {
		t.Fatalf("Server did not respond with PeerInfo")
	}

	initializePath := filepath.Join(dir, "00000001_fuzzer_initialize.bin")
	initializeData, err := os.ReadFile(initializePath)
	if err != nil {
		t.Fatalf("Failed to load initialize file: %v", err)
	}

	initialize := fuzzinterface.Initialize{}
	if err := serializer.Deserialize(initializeData[1:], &initialize); err != nil {
		t.Fatalf("Failed to deserialize initialize: %v", err)
	}

	resp, err = fc.sendAndReceive(fuzzinterface.RequestMessage{Initialize: &initialize})
	if err != nil {
		t.Fatalf("Failed to send Initialize: %v", err)
	}

	if resp.StateRoot == nil {
		t.Fatalf("Server did not respond with Initialize")
	}

	importBlockPattern := filepath.Join(dir, "*fuzzer_import_block.bin")
	importBlockFiles, err := filepath.Glob(importBlockPattern)
	if err != nil {
		t.Fatalf("Failed to find import block files: %v", err)
	}

	for _, importBlockPath := range importBlockFiles {
		t.Logf("Processing import block file: %s", filepath.Base(importBlockPath))

		importBlockData, err := os.ReadFile(importBlockPath)
		if err != nil {
			t.Fatalf("Failed to load import block file %s: %v", importBlockPath, err)
		}

		importBlock := fuzzinterface.ImportBlock{}
		if err := serializer.Deserialize(importBlockData[1:], &importBlock); err != nil {
			t.Fatalf("Failed to deserialize import block from %s: %v", importBlockPath, err)
		}

		resp, err = fc.sendAndReceive(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			t.Fatalf("Failed to send ImportBlock from %s: %v", importBlockPath, err)
		}

		// Log the response for debugging
		if resp.Error != nil {
			t.Logf("ImportBlock %s resulted in error: %s", filepath.Base(importBlockPath), string(*resp.Error))
		} else if resp.StateRoot != nil {
			t.Logf("ImportBlock %s processed successfully, new state root: %x", filepath.Base(importBlockPath), *resp.StateRoot)
		}
	}
}

func compareKVs(t *testing.T, expectedKVs, actualKVs merklizer.State) {
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
		t.Errorf("Missing KVs:")
		for _, key := range missingKVs {
			t.Errorf("- %x: %x", key, expectedKVsMap[key])
		}
	}

	if len(extraKVs) > 0 {
		t.Errorf("Extra KVs:")
		for _, key := range extraKVs {
			t.Errorf("+ %x: %x", key, actualKVsMap[key])
		}
	}

	if len(differentValues) > 0 {
		t.Errorf("Keys with different values:")
		for _, key := range differentValues {
			t.Errorf("~ %x:", key)
			t.Errorf("  Expected: %x", expectedKVsMap[key])
			t.Errorf("  Actual:   %x", actualKVsMap[key])
		}
	}

	if len(missingKVs) == 0 && len(extraKVs) == 0 && len(differentValues) == 0 {
		t.Logf("KV comparison passed: KVs are identical")
	} else {
		t.Errorf("KV comparison failed")
	}
}

func main() {
	// Parse command line arguments
	socketPath := flag.String("socket", "/tmp/jam_target.sock", "Path for the Unix domain socket")
	vectorsPath := flag.String("vectors", "/Users/adamscrivener/Projects/Jam/jam-test-vectors/traces/fallback", "Path to the test vectors directory")
	inProcess := flag.Bool("in-process", false, "Run in in-process mode (no socket communication)")
	flag.Parse()

	log.Printf("Starting fuzzer client...")
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
}
