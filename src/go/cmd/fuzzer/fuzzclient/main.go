package main

import (
	"bytes"
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
	"jam/pkg/serviceaccount"
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
		encodedMessage = serializer.Serialize(msg.PeerInfo)
		msgType = fuzzinterface.RequestMessageTypePeerInfo
	case msg.ImportBlock != nil:
		encodedMessage = serializer.Serialize(msg.ImportBlock)
		msgType = fuzzinterface.RequestMessageTypeImportBlock
	case msg.Initialize != nil:
		encodedMessage = serializer.Serialize(msg.Initialize)
		msgType = fuzzinterface.RequestMessageTypeInitialize
	case msg.GetState != nil:
		encodedMessage = serializer.Serialize(msg.GetState)
		msgType = fuzzinterface.RequestMessageTypeGetState
	case msg.StartProfiling != nil:
		encodedMessage = serializer.Serialize(msg.StartProfiling)
		msgType = fuzzinterface.RequestMessageTypeStartProfiling
	case msg.StopProfiling != nil:
		encodedMessage = serializer.Serialize(msg.StopProfiling)
		msgType = fuzzinterface.RequestMessageTypeStopProfiling
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
	case fuzzinterface.ResponseMessageTypeError:
		msg.Error = &data
	case fuzzinterface.ResponseMessageTypeProfilingStatus:
		var profilingStatus fuzzinterface.ProfilingStatus
		err = serializer.Deserialize(data, &profilingStatus)
		if err != nil {
			return fuzzinterface.ResponseMessage{}, err
		}
		msg.ProfilingStatus = &profilingStatus
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
		testName := filepath.Base(testDir)
		// if !strings.Contains(testName, "1768864701") {
		// 	continue
		// }
		t.Run(testName, func(t *testing.T) {
			fc.testIndividualVector(t, testDir)
		})
	}
}

func (fc *FuzzerClient) testIndividualVector(t *testing.T, vectorsDir string) {
	peerInfo := fuzzinterface.PeerInfo{
		FuzzVersion: 0,
		Features:    0,
		JamVersion: fuzzinterface.Version{
			Major: 0,
			Minor: 0,
			Patch: 0,
		},
		AppVersion: fuzzinterface.Version{
			Major: 0,
			Minor: 0,
			Patch: 0,
		},
		Name: []byte{},
	}
	resp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{PeerInfo: &peerInfo})
	if err != nil {
		t.Fatalf("Failed to send PeerInfo message: %v", err)
	}

	// Get all .bin files from the directory (excluding report.bin)
	binFiles, err := filepath.Glob(filepath.Join(vectorsDir, "*.bin"))
	if err != nil {
		t.Logf("Failed to list bin files: %v", err)
		return
	}
	// Filter out report.bin and sort the remaining files
	var testBinFiles []string
	var genesisPath string
	for _, file := range binFiles {
		if !strings.HasSuffix(file, "report.bin") {
			if strings.HasSuffix(file, "genesis.bin") {
				genesisPath = file
			} else {
				testBinFiles = append(testBinFiles, file)
			}
		}
	}
	sort.Strings(testBinFiles)

	// Prioritize genesis.bin if it exists, otherwise use first sorted file
	var warpVectorPath string
	if genesisPath != "" {
		warpVectorPath = genesisPath
	} else if len(testBinFiles) > 0 {
		warpVectorPath = testBinFiles[0]
		// Remove it from testBinFiles since we're using it as warp vector
		testBinFiles = testBinFiles[1:]
	} else {
		t.Logf("No test bin files found")
		return
	}

	if len(testBinFiles) < 1 {
		t.Logf("Need at least 1 test bin file after warp vector, found %d", len(testBinFiles))
		return
	}
	warpVectorData, err := os.ReadFile(warpVectorPath)
	if err != nil {
		t.Fatalf("Failed to load warp vector file: %v", err)
	}

	// Deserialize based on file type
	var warpHeader header.Header
	var warpState merklizer.State
	var expectedStateRoot [32]byte

	if strings.HasSuffix(warpVectorPath, "genesis.bin") {
		// Genesis file uses GenesisVector format
		genesisVector := GenesisVector{}
		if err := serializer.Deserialize(warpVectorData, &genesisVector); err != nil {
			t.Fatalf("Failed to deserialize genesis vector: %v", err)
		}
		warpHeader = genesisVector.Header
		warpState = genesisVector.StateWithRoot.State
		expectedStateRoot = genesisVector.StateWithRoot.StateRoot
	} else {
		// Regular test files use TestVector format
		testVector := TestVector{}
		if err := serializer.Deserialize(warpVectorData, &testVector); err != nil {
			t.Fatalf("Failed to deserialize test vector: %v", err)
		}
		warpHeader = testVector.Block.Header
		warpState = testVector.PostState.State
		expectedStateRoot = testVector.PostState.StateRoot
	}

	t.Logf("Setting initial genesis state...")
	resp, err = fc.sendAndReceive(fuzzinterface.RequestMessage{Initialize: &fuzzinterface.Initialize{Header: warpHeader, State: warpState}})
	if err != nil {
		t.Fatalf("Failed to send Initialize message: %v", err)
	}

	if resp.StateRoot == nil {
		t.Fatalf("SetState failed: no state root returned")
	}

	t.Logf("State set successfully, state root: %x", *resp.StateRoot)

	if *resp.StateRoot != expectedStateRoot {
		t.Fatalf("State root mismatch: %x != %x", *resp.StateRoot, expectedStateRoot)
	}

	// Process all test files sequentially after the warp file
	var longestDuration time.Duration
	var longestTestFile string

	// // Start profiling before processing test vectors
	// startProfiling := fuzzinterface.StartProfiling{}
	// _, err = fc.sendAndReceive(fuzzinterface.RequestMessage{StartProfiling: &startProfiling})
	// if err != nil {
	// 	t.Logf("Warning: Failed to start profiling: %v", err)
	// } else {
	// 	t.Logf("Profiling started for ImportBlock operations")
	// }

	for i := 0; i < len(testBinFiles); i++ {
		startTime := time.Now()
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
			t.Fatalf("Failed to deserialize test vector from %s: %v", testVectorPath, err)
		}

		importBlock := fuzzinterface.ImportBlock(testVector.Block)
		resp, err = fc.sendAndReceive(fuzzinterface.RequestMessage{ImportBlock: &importBlock})
		if err != nil {
			t.Fatalf("Failed to send ImportBlock message for %s: %v", testFileName, err)
			continue
		}

		if resp.Error != nil {
			if testVector.PostState.StateRoot != testVector.PreState.StateRoot {
				t.Fatalf("ImportBlock failed for %s: %s", testFileName, string(*resp.Error))
			}
			t.Logf("Test passed for %s! Error: %s", testFileName, string(*resp.Error))
			continue
		}

		if *resp.StateRoot != testVector.PostState.StateRoot {
			t.Errorf("State root mismatch for %s: %x != %x", testFileName, *resp.StateRoot, testVector.PostState.StateRoot)
			getState := fuzzinterface.GetState(testVector.Block.Header.Hash())
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
				t.Errorf("State comparison failed for %s:", testFileName)
				t.Errorf("State mismatch (-expected +actual):\n%s", diff)
			} else {
				t.Logf("State comparison passed for %s: states are identical", testFileName)
			}
			// Compare the underlying KVs to show any differences
			compareKVs(t, testVector.PostState.State, *getStateResponse.State)
		} else {
			t.Logf("Test passed for %s! State root matches: %x", testFileName, *resp.StateRoot)
		}

		// Track longest test
		duration := time.Since(startTime)
		if duration > longestDuration {
			longestDuration = duration
			longestTestFile = testFileName
		}
	}

	// // Stop profiling after processing all test vectors
	// stopProfiling := fuzzinterface.StopProfiling{}
	// stopResp, err := fc.sendAndReceive(fuzzinterface.RequestMessage{StopProfiling: &stopProfiling})
	// if err != nil {
	// 	t.Logf("Warning: Failed to stop profiling: %v", err)
	// } else if stopResp.ProfilingStatus != nil {
	// 	if stopResp.ProfilingStatus.Success == 1 {
	// 		t.Logf("Profiling stopped successfully: %s", string(stopResp.ProfilingStatus.Message))
	// 	} else {
	// 		t.Logf("Profiling stop failed: %s", string(stopResp.ProfilingStatus.Message))
	// 	}
	// }

	if longestTestFile != "" {
		t.Logf("Longest test: %s took %v", longestTestFile, longestDuration)
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

// parseServiceIndexKey checks if a key matches the service index pattern:
// ff + little-endian uint32 service index + zeros
// Returns the service index and true if it matches, 0 and false otherwise
func parseServiceIndexKey(key [31]byte) (uint32, bool) {
	// Check if key starts with 0xff
	if key[0] != 0xff {
		return 0, false
	}

	// Check if the pattern matches: ff, n0, 0, n1, 0, n2, 0, n3, 0, 0...
	// where n0,n1,n2,n3 are the little-endian bytes of a uint32 service index
	if len(key) < 9 { // Need at least ff + 4 service index bytes + 4 zero bytes
		return 0, false
	}

	// Check the pattern: every other byte after ff should be 0
	for i := 2; i < len(key) && i < 9; i += 2 {
		if key[i] != 0 {
			return 0, false
		}
	}

	// Check that remaining bytes are all zeros
	for i := 9; i < len(key); i++ {
		if key[i] != 0 {
			return 0, false
		}
	}

	// Extract the service index from positions 1, 3, 5, 7 (little-endian)
	serviceIndex := uint32(key[1]) | (uint32(key[3]) << 8) | (uint32(key[5]) << 16) | (uint32(key[7]) << 24)

	return serviceIndex, true
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
			expectedValue := expectedKVsMap[key]
			actualValue := actualKVsMap[key]
			// Check if this key matches the service index pattern
			if serviceIndex, isServiceKey := parseServiceIndexKey(key); isServiceKey {
				fmt.Printf("Service index key mismatch detected: %d\n", serviceIndex)
				expectedServiceAccount := serviceaccount.ServiceAccountData{}
				if err := serializer.Deserialize(expectedValue, &expectedServiceAccount); err != nil {
					fmt.Printf("Failed to deserialize expected service account: %v\n", err)
				}
				actualServiceAccount := serviceaccount.ServiceAccountData{}
				if err := serializer.Deserialize(actualValue, &actualServiceAccount); err != nil {
					fmt.Printf("Failed to deserialize actual service account: %v\n", err)
				}
				if diff := cmp.Diff(expectedServiceAccount, actualServiceAccount); diff != "" {
					fmt.Printf("Service account mismatch (-expected +actual):\n%s", diff)
				}
			} else {
				fmt.Printf("  Expected: %x\n", expectedValue)
				fmt.Printf("  Actual:   %x\n", actualValue)
			}
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
