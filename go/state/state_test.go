package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/google/go-cmp/cmp"

	"github.com/ascrivener/jam/types"
)

// // Disputes represents the disputes section in a test vector
// type Disputes struct {
// 	Verdicts []interface{} `json:"verdicts"`
// 	Culprits []interface{} `json:"culprits"`
// 	Faults   []interface{} `json:"faults"`
// }

// // Extrinsic represents the extrinsic section in a test vector
// type Extrinsic struct {
// 	Tickets    []interface{} `json:"tickets"`
// 	Preimages  []interface{} `json:"preimages"`
// 	Guarantees []interface{} `json:"guarantees"`
// 	Assurances []interface{} `json:"assurances"`
// 	Disputes   Disputes      `json:"disputes"`
// }

// Define a struct to match the JSON structure
type ValidatorEntry struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519,omitempty"` // Optional
}

type EpochMark struct {
	Entropy        string           `json:"entropy"`
	TicketsEntropy string           `json:"tickets_entropy"`
	Validators     []ValidatorEntry `json:"validators"`
}

type BlockHeader struct {
	Parent          string        `json:"parent"`
	ParentStateRoot string        `json:"parent_state_root"`
	ExtrinsicHash   string        `json:"extrinsic_hash"`
	Slot            int           `json:"slot"`
	AuthorIndex     int           `json:"author_index"`
	EntropySource   string        `json:"entropy_source"`
	Seal            string        `json:"seal"`
	EpochMark       *EpochMark    `json:"epoch_mark"`
	OffendersMark   []interface{} `json:"offenders_mark"`
	TicketsMark     interface{}   `json:"tickets_mark"`
}

type Disputes struct {
	Verdicts []interface{} `json:"verdicts"`
	Culprits []interface{} `json:"culprits"`
	Faults   []interface{} `json:"faults"`
}

type GuaranteeSignatureJSON struct {
	ValidatorIndex int    `json:"validator_index"`
	Signature      string `json:"signature"`
}

type GuaranteeJSON struct {
	Report     WorkReport               `json:"report"`
	Slot       uint64                   `json:"slot"`
	Signatures []GuaranteeSignatureJSON `json:"signatures"`
}

type Assurance struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint64 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type Extrinsic struct {
	Tickets    []interface{}   `json:"tickets"`
	Preimages  []interface{}   `json:"preimages"`
	Guarantees []GuaranteeJSON `json:"guarantees"`
	Assurances []Assurance     `json:"assurances"`
	Disputes   Disputes        `json:"disputes"`
}

type BlockJSON struct {
	Header    BlockHeader `json:"header"`
	Extrinsic Extrinsic   `json:"extrinsic"`
}

// TestVector represents a complete state transition test vector
type TestVector struct {
	PreState  StateKeyValues `json:"pre_state"`
	PostState StateKeyValues `json:"post_state"`
	Block     BlockJSON      `json:"block"`
}

// // Block represents a block in a test vector
// type Block struct {
// 	Header struct {
// 		Parent          string `json:"parent"`
// 		ParentStateRoot string `json:"parent_state_root"`
// 		ExtrinsicHash   string `json:"extrinsic_hash"`
// 		Slot            int    `json:"slot"`
// 		AuthorIndex     int    `json:"author_index"`
// 		EntropySource   string `json:"entropy_source"`
// 		Seal            string `json:"seal"`
// 		EpochMark       struct {
// 			Validators []struct {
// 				Bandersnatch string `json:"bandersnatch"`
// 			} `json:"validators"`
// 			Entropy        string `json:"entropy"`
// 			TicketsEntropy string `json:"tickets_entropy"`
// 		} `json:"epoch_mark"`
// 		OffendersMark []interface{} `json:"offenders_mark"`
// 		TicketsMark   interface{}   `json:"tickets_mark"`
// 	} `json:"header"`
// 	Extrinsic Extrinsic `json:"extrinsic"`
// }

// StateKeyValues represents the key-value pairs in a state
type StateKeyValues struct {
	StateRoot string `json:"state_root"`
	KeyVals   []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"keyvals"`
}

// // TestStateTransitionAccumulation runs accumulation-specific tests with relevant fields
// func TestStateTransitionAccumulation(t *testing.T) {
// 	// List of fields relevant to accumulation based on ASN.1 definition:
// 	// State ::= SEQUENCE {
// 	//    slot TimeSlot,               -> MostRecentBlockTimeslot
// 	//    entropy Entropy,             -> EntropyAccumulator
// 	//    ready-queue ReadyQueue,      -> AccumulationQueue
// 	//    accumulated AccumulatedQueue,-> AccumulationHistory
// 	//    privileges Privileges,       -> PrivilegedServices
// 	//    accounts SEQUENCE OF AccountsMapEntry -> ServiceAccounts
// 	// }
// 	accumulationFields := []string{
// 		"MostRecentBlockTimeslot", // slot in ASN.1
// 		// "EntropyAccumulator",      // entropy in ASN.1
// 		"AccumulationQueue",   // ready-queue in ASN.1
// 		"AccumulationHistory", // accumulated in ASN.1
// 		"PrivilegedServices",  // privileges in ASN.1
// 		"ServiceAccounts",     // accounts in ASN.1
// 	}

// 	// Get test directory from environment variable, default to "tiny"
// 	testDir := os.Getenv("JAM_TEST_VECTOR_DIR")
// 	if testDir == "" {
// 		testDir = "tiny"
// 	}

// 	// Run test cases with accumulation-related fields
// 	// The path is relative to the testVectorDir in runStateTransitionTest
// 	runStateTransitionTest(t, testDir, accumulationFields)
// }

// func TestStateTransitionAssurances(t *testing.T) {
// 	// List of fields relevant to accumulation based on ASN.1 definition:
// 	// State ::= SEQUENCE {
// 	//    slot TimeSlot,               -> MostRecentBlockTimeslot
// 	//    entropy Entropy,             -> EntropyAccumulator
// 	//    ready-queue ReadyQueue,      -> AccumulationQueue
// 	//    accumulated AccumulatedQueue,-> AccumulationHistory
// 	//    privileges Privileges,       -> PrivilegedServices
// 	//    accounts SEQUENCE OF AccountsMapEntry -> ServiceAccounts
// 	// }
// 	fields := []string{
// 		"PendingReports",         // slot in ASN.1
// 		"ValidatorKeysetsActive", // ready-queue in ASN.1
// 	}

// 	// Get test directory from environment variable, default to "tiny"
// 	testDir := os.Getenv("JAM_TEST_VECTOR_DIR")
// 	if testDir == "" {
// 		testDir = "tiny"
// 	}

// 	// Run test cases with accumulation-related fields
// 	// The path is relative to the testVectorDir in runStateTransitionTest
// 	runStateTransitionTestAssurances(t, testDir, fields)
// }

// // runStateTransitionTestAssurances is a helper that runs state transition tests for all JSON files in a directory
// // If fieldsToCompare is empty, all fields will be compared
// func runStateTransitionTestAssurances(t *testing.T, testDir string, fieldsToCompare []string) {
// 	// Base directory containing the test vectors
// 	testVectorDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/assurances"

// 	// Full path to the test directory
// 	fullDirPath := filepath.Join(testVectorDir, testDir)

// 	// Find all JSON files in the directory
// 	files, err := filepath.Glob(filepath.Join(fullDirPath, "*.json"))
// 	if err != nil {
// 		t.Fatalf("Failed to read test directory %s: %v", fullDirPath, err)
// 	}

// 	if len(files) == 0 {
// 		t.Fatalf("No test vectors found in %s", fullDirPath)
// 	}

// 	// Run each test file
// 	for _, file := range files {
// 		fileName := filepath.Base(file)
// 		testName := testDir + "/" + fileName

// 		if testName != "tiny/assurances_for_stale_report-1.json" {
// 			continue
// 		}

// 		t.Run(testName, func(t *testing.T) {
// 			// t.Parallel() // Run tests in parallel

// 			// Log when a test starts
// 			t.Logf("Starting test vector: %s", testName)

// 			// Parse the test vector using our asntypes package
// 			testCase, err := asntypes.ParseAssurancesTestCase(file)
// 			if err != nil {
// 				t.Fatalf("Failed to parse test case: %v", err)
// 			}
// 			t.Logf("✅ Successfully parsed test vector %s", testName)

// 			// Build header.Header
// 			header := header.Header{
// 				TimeSlot:       types.Timeslot(testCase.Input.Slot),
// 				PriorStateRoot: hexToHashMust(string(testCase.Input.Parent)),
// 			}
// 			block := block.Block{
// 				Header: header,
// 				Extrinsics: extrinsics.Extrinsics{
// 					Assurances: convertAsnAssurancesToImpl(testCase.Input.Assurances),
// 				},
// 			}

// 			pendingReports := assignmentsToPendingReports(testCase.PreState.AvailAssignments)
// 			result := computePostGuaranteesExtrinsicIntermediatePendingReports(block.Header, block.Extrinsics.Assurances, pendingReports)
// 			pendingReportsOutput := assignmentsToPendingReports(testCase.PostState.AvailAssignments)

// 			if !reflect.DeepEqual(result, pendingReportsOutput) {
// 				t.Errorf("mismatch:\nExpected: %+v\nActual:   %+v", pendingReportsOutput, result)
// 			}
// 		})
// 	}
// }

// func assignmentsToPendingReports(assignments asntypes.AvailabilityAssignments) [constants.NumCores]*PendingReport {
// 	var arr [constants.NumCores]*PendingReport
// 	for i, entry := range assignments {
// 		if entry == nil {
// 			arr[i] = nil
// 		} else {
// 			arr[i] = &PendingReport{
// 				WorkReport: convertAsnReportToImplReport(entry.WorkReport),
// 				Timeslot:   types.Timeslot(entry.Timeout),
// 			}
// 		}
// 	}
// 	return arr
// }

// // runStateTransitionTest is a helper that runs state transition tests for all JSON files in a directory
// // If fieldsToCompare is empty, all fields will be compared
// func runStateTransitionTest(t *testing.T, testDir string, fieldsToCompare []string) {
// 	// Base directory containing the test vectors
// 	testVectorDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/accumulate"

// 	// Full path to the test directory
// 	fullDirPath := filepath.Join(testVectorDir, testDir)

// 	// Find all JSON files in the directory
// 	files, err := filepath.Glob(filepath.Join(fullDirPath, "*.json"))
// 	if err != nil {
// 		t.Fatalf("Failed to read test directory %s: %v", fullDirPath, err)
// 	}

// 	if len(files) == 0 {
// 		t.Fatalf("No test vectors found in %s", fullDirPath)
// 	}

// 	// Run each test file
// 	for _, file := range files {
// 		fileName := filepath.Base(file)
// 		testName := testDir + "/" + fileName

// 		t.Run(testName, func(t *testing.T) {
// 			// t.Parallel() // Run tests in parallel

// 			// Log when a test starts
// 			t.Logf("Starting test vector: %s", testName)

// 			// Parse the test vector using our asntypes package
// 			testCase, err := asntypes.ParseTestCase(file)
// 			if err != nil {
// 				t.Fatalf("Failed to parse test case: %v", err)
// 			}
// 			t.Logf("✅ Successfully parsed test vector %s", testName)

// 			// Convert asntypes.State to our implementation's State
// 			priorState := convertAsnStateToImplState(testCase.PreState)
// 			t.Logf("✅ Converted prior state from ASN format")

// 			// Extract posterior timeslot from input
// 			reportsTimeslot := types.Timeslot(testCase.Input.Slot) // Assuming prior timeslot is one less
// 			t.Logf("Processing reports for timeslot %d", reportsTimeslot)

// 			// Add input reports to pending reports in prior state (for dispute testing)
// 			// This simulates reports that were submitted in a previous block
// 			reportCount := 0
// 			for _, asnReport := range testCase.Input.Reports {
// 				report := convertAsnReportToImplReport(asnReport)
// 				coreIndex := int(report.CoreIndex)
// 				reportCount++

// 				// Only add if there's not already a pending report for this core
// 				if priorState.PendingReports[coreIndex] == nil {
// 					priorState.PendingReports[coreIndex] = &PendingReport{
// 						WorkReport: report,
// 						Timeslot:   reportsTimeslot,
// 					}
// 				}
// 			}
// 			t.Logf("✅ Added %d reports to pending reports", reportCount)

// 			// Build a mock Block with the necessary components
// 			mockBlock := buildMockBlockFromTestVector(types.Timeslot(testCase.Input.Slot))
// 			t.Logf("✅ Created mock block for timeslot %d", mockBlock.Header.TimeSlot)

// 			// Run the full state transition function
// 			t.Logf("Running state transition function...")
// 			actualState := StateTransitionFunction(priorState, mockBlock)
// 			t.Logf("✅ State transition completed")

// 			// Convert the expected post-state from asntypes.State to our implementation's State
// 			expectedState := convertAsnStateToImplState(testCase.PostState)
// 			t.Logf("✅ Converted expected post-state from ASN format")

// 			// Compare the expected and actual states based on provided fields
// 			t.Logf("Comparing states based on %d fields...", len(fieldsToCompare))
// 			compareStatesSelective(t, expectedState, actualState, fieldsToCompare)

// 			// If we got here without failing, the test passed!
// 			t.Logf("✅ TEST PASSED: %s", testName)
// 		})
// 	}
// }

// func buildMockBlockFromTestVector(posteriorTimeslot types.Timeslot) block.Block {
// 	// Create a minimal valid header
// 	mockHeader := header.Header{
// 		TimeSlot:       posteriorTimeslot,
// 		PriorStateRoot: [32]byte{}, // We can leave this empty for now
// 		// Add other required fields with default/empty values
// 	}

// 	// // Process all reports in the test vector input
// 	// for _, asnReport := range testCase.Input.Reports {
// 	// 	// Convert report to implementation type
// 	// 	report := convertAsnReportToImplReport(asnReport)

// 	// 	// Add to guarantees - these are the actual work reports validators have validated
// 	// 	mockGuarantee := extrinsics.Guarantee{
// 	// 		WorkReport: report,
// 	// 		Timeslot:   posteriorTimeslot, // Use the current timeslot for the guarantee
// 	// 		Credentials: []extrinsics.Credential{
// 	// 			{
// 	// 				ValidatorIndex: 0,                        // Using validator index 0 for simplicity in tests
// 	// 				Signature:      types.Ed25519Signature{}, // Empty signature for tests
// 	// 			},
// 	// 		},
// 	// 	}
// 	// 	mockGuarantees = append(mockGuarantees, mockGuarantee)
// 	// }

// 	// Create the block
// 	mockBlock := block.Block{
// 		Header: mockHeader,
// 		Extrinsics: extrinsics.Extrinsics{
// 			Assurances: makeMockAssurances(),
// 			Guarantees: extrinsics.Guarantees{},
// 			Preimages:  extrinsics.Preimages{},
// 			Disputes:   extrinsics.Disputes{},
// 			Tickets:    extrinsics.Tickets{},
// 		},
// 	}

// 	return mockBlock
// }

// func makeMockAssurances() extrinsics.Assurances {
// 	// For test purposes, we'll create assurances for all validators with all cores marked as available

// 	// Create a bit sequence with all bits set to 1
// 	coreContributions := bitsequence.NewZeros(constants.NumCores)
// 	// Set all bits to 1
// 	for i := 0; i < constants.NumCores; i++ {
// 		coreContributions.SetBitAt(i, true)
// 	}

// 	var assurances extrinsics.Assurances
// 	for validatorIndex := 0; validatorIndex < constants.NumValidators; validatorIndex++ {
// 		// Create an assurance with all bits set
// 		assurance := extrinsics.Assurance{
// 			ParentHash:                    [32]byte{}, // Would be set to the actual parent hash in production
// 			CoreAvailabilityContributions: *coreContributions,
// 			ValidatorIndex:                types.ValidatorIndex(validatorIndex),
// 			Signature:                     types.Ed25519Signature{}, // Empty signature for tests
// 		}

// 		// Append the new assurance
// 		assurances = append(assurances, assurance)
// 	}

// 	return assurances
// }

// hexToBytes converts a hex string (with or without 0x prefix) to a byte slice
func hexToBytes(hexStr string) []byte {
	// Remove 0x prefix if it exists
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	// Add leading zero if odd length
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode hex string: %s", hexStr))
	}

	return bytes
}

// // convertSignatureString converts a hex string signature to a [64]byte array
// func convertSignatureString(hexStr string) [64]byte {
// 	bytes := hexToBytes(hexStr)

// 	// Ensure we have exactly 64 bytes
// 	if len(bytes) != 64 {
// 		panic(fmt.Sprintf("Invalid signature length. Expected 64 bytes, got %d bytes from string: %s", len(bytes), hexStr))
// 	}

// 	var signature [64]byte
// 	copy(signature[:], bytes)
// 	return signature
// }

// // createEmptyState creates a fully initialized State with proper zero values and non-nil fields
// func createEmptyState() State {
// 	// Initialize with zero values but ensure all maps/slices are properly initialized
// 	state := State{
// 		ServiceAccounts:            make(serviceaccount.ServiceAccounts),
// 		AccumulationQueue:          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{},
// 		AccumulationHistory:        [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}{},
// 		EntropyAccumulator:         [4][32]byte{},
// 		RecentBlocks:               make([]RecentBlock, 0),
// 		SafroleBasicState:          SafroleBasicState{},
// 		ValidatorKeysetsStaging:    types.ValidatorKeysets{},
// 		ValidatorKeysetsActive:     types.ValidatorKeysets{},
// 		ValidatorKeysetsPriorEpoch: types.ValidatorKeysets{},
// 		PendingReports:             [constants.NumCores]*PendingReport{},
// 		AuthorizerQueue:            [constants.NumCores][constants.AuthorizerQueueLength][32]byte{},
// 		PrivilegedServices:         types.PrivilegedServices{},
// 		Disputes:                   types.Disputes{},
// 		ValidatorStatistics:        validatorstatistics.ValidatorStatistics{},
// 		MostRecentBlockTimeslot:    0,
// 	}

// 	// Initialize maps in AccumulationHistory
// 	for i := range state.AccumulationHistory {
// 		state.AccumulationHistory[i] = make(map[[32]byte]struct{})
// 	}

// 	// Initialize AuthorizersPool with empty (but non-nil) slices
// 	state.AuthorizersPool = [constants.NumCores][][32]byte{}
// 	for i := 0; i < constants.NumCores; i++ {
// 		state.AuthorizersPool[i] = make([][32]byte, 0)
// 	}

// 	return state
// }

// // convertAsnStateToImplState converts a state from the ASN types to the implementation's State type
// func convertAsnStateToImplState(asnState asntypes.State) State {
// 	// Create a fully initialized state with proper zero values
// 	state := createEmptyState()

// 	// Set the timeslot
// 	state.MostRecentBlockTimeslot = types.Timeslot(asnState.Slot)

// 	// Set entropy from ASN state
// 	entropyHash := hexToHashMust(string(asnState.Entropy))
// 	state.EntropyAccumulator[0] = entropyHash

// 	// Convert ready queue
// 	for idx, queueItem := range asnState.ReadyQueue {
// 		if idx >= constants.NumTimeslotsPerEpoch {
// 			continue // Skip if index is out of bounds
// 		}

// 		w := make([]workreport.WorkReportWithWorkPackageHashes, 0)
// 		for _, readyRecord := range queueItem {
// 			workPackageHashes := make(map[[32]byte]struct{})
// 			for _, dep := range readyRecord.Dependencies {
// 				hash := hexToHashMust(string(dep))
// 				workPackageHashes[hash] = struct{}{}
// 			}

// 			w = append(w, workreport.WorkReportWithWorkPackageHashes{
// 				WorkReport:        convertAsnReportToImplReport(readyRecord.Report),
// 				WorkPackageHashes: workPackageHashes,
// 			})
// 		}
// 		state.AccumulationQueue[idx] = w
// 	}

// 	// Convert accumulated queue
// 	for idx, accItem := range asnState.Accumulated {
// 		if idx >= constants.NumTimeslotsPerEpoch {
// 			continue // Skip if index is out of bounds
// 		}

// 		workPackageHashes := make(map[[32]byte]struct{})
// 		for _, hashStr := range accItem {
// 			hash := hexToHashMust(string(hashStr))
// 			workPackageHashes[hash] = struct{}{}
// 		}
// 		state.AccumulationHistory[idx] = workPackageHashes
// 	}

// 	// Process accounts
// 	for _, account := range asnState.Accounts {
// 		// Create a new service account
// 		serviceAccount := serviceaccount.ServiceAccount{
// 			Balance:                        types.Balance(account.Data.Service.Balance),
// 			MinimumGasForAccumulate:        types.GasValue(account.Data.Service.MinItemGas),
// 			MinimumGasForOnTransfer:        types.GasValue(account.Data.Service.MinMemoGas),
// 			PreimageLookup:                 make(map[[32]byte][]byte),
// 			PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
// 		}

// 		// Set code hash
// 		codeHash := hexToHashMust(string(account.Data.Service.CodeHash))
// 		serviceAccount.CodeHash = codeHash

// 		// Add preimages
// 		for _, preimage := range account.Data.Preimages {
// 			hashArray := hexToHashMust(string(preimage.Hash))
// 			// Properly decode hex string to binary
// 			serviceAccount.PreimageLookup[hashArray] = hexToBytes(string(preimage.Blob))
// 		}

// 		// Add the service account to the state
// 		state.ServiceAccounts[types.ServiceIndex(account.ID)] = &serviceAccount
// 	}

// 	return state
// }

// compareStatesSelective compares specific fields between two State objects
// If fields is nil or empty, all fields are compared
// func compareStatesSelective(t *testing.T, expected, actual State, fields []string) {
// 	if len(fields) == 0 {
// 		// Compare entire state if no fields specified
// 		if diff := cmp.Diff(expected, actual); diff != "" {
// 			t.Errorf("States don't match (-expected +actual):\n%s", diff)
// 		}
// 		return
// 	}

// 	// Check each field individually to provide more focused comparison
// 	// This avoids issues with complex filtering in cmp.FilterPath
// 	for _, fieldName := range fields {
// 		// Use reflection to get the field values
// 		expectedVal := reflect.ValueOf(expected).FieldByName(fieldName)
// 		actualVal := reflect.ValueOf(actual).FieldByName(fieldName)

// 		if !expectedVal.IsValid() || !actualVal.IsValid() {
// 			t.Errorf("Field %s does not exist in State struct", fieldName)
// 			continue
// 		}

// 		// Compare just this individual field
// 		if diff := cmp.Diff(expectedVal.Interface(), actualVal.Interface()); diff != "" {
// 			t.Errorf("Field %s doesn't match (-expected +actual):\n%s", fieldName, diff)
// 		}
// 	}
// }

// TestStateDeserializerWithTransition tests the serialization and deserialization with state transition
func TestStateDeserializerWithTransition(t *testing.T) {
	// Get all test vectors from the reports-l0 directory
	vectorsDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/traces/reports-l0"
	vectorFiles, err := os.ReadDir(vectorsDir)
	if err != nil {
		t.Fatalf("Failed to read test vectors directory: %v", err)
	}

	// Sort files by name to ensure proper sequence
	var fileNames []string
	for _, fileInfo := range vectorFiles {
		if fileInfo.IsDir() || !strings.HasSuffix(fileInfo.Name(), ".json") {
			continue
		}
		fileNames = append(fileNames, fileInfo.Name())
	}
	sort.Strings(fileNames)

	t.Logf("Processing %d test vector files", len(fileNames))

	for idx, fileName := range fileNames {
		if idx == 0 {
			continue
		}
		t.Logf("Processing test vector file: %s", fileName)

		// Load and parse test vector
		testVectorPath := filepath.Join(vectorsDir, fileName)
		testVectorData, err := os.ReadFile(testVectorPath)
		if err != nil {
			t.Fatalf("Failed to load test vector file: %v", err)
		}

		var testVector TestVector
		if err := json.Unmarshal(testVectorData, &testVector); err != nil {
			t.Fatalf("Failed to parse test vector JSON: %v", err)
		}

		// a. Deserialize pre-state from test vector
		statemap := make(map[[31]byte][]byte)

		for _, kv := range testVector.PreState.KeyVals {
			key := hexToBytesMust(kv.Key)
			if len(key) != 31 {
				t.Fatalf("Invalid serialized state key length: %d", len(key))
			}

			var keyArray [31]byte
			copy(keyArray[:], key)

			value := hexToBytesMust(kv.Value)
			statemap[keyArray] = value
		}

		preState, stateDeserializationErr := StateDeserializer(statemap)
		if stateDeserializationErr != nil {
			t.Fatalf("Failed to deserialize pre-state: %v", stateDeserializationErr)
		}

		// b. Convert block to implementation block and run state transition
		testBlock, err := BlockFromJSON(testVector.Block)
		if err != nil {
			t.Fatalf("Failed to parse block JSON: %v", err)
		}

		// Run state transition function
		postState := StateTransitionFunction(preState, testBlock)

		// Convert test vector's post-state key-values to the format expected by StateDeserializer
		expectedSerializedState := make(map[[31]byte][]byte)
		for _, kv := range testVector.PostState.KeyVals {
			key := hexToBytesMust(kv.Key)
			if len(key) != 31 {
				t.Fatalf("Invalid serialized state key length: %d", len(key))
			}

			var keyArray [31]byte
			copy(keyArray[:], key)

			expectedSerializedState[keyArray] = hexToBytesMust(kv.Value)
		}

		// Deserialize the expected state
		expectedPostState, err := StateDeserializer(expectedSerializedState)
		if err != nil {
			t.Fatalf("Failed to deserialize expected post-state: %v", err)
		}

		// Use cmp.Diff for a detailed comparison of the state objects
		if diff := cmp.Diff(expectedPostState, postState); diff != "" {
			t.Fatalf("Post-state mismatch (-expected +actual):\n%s", diff)
		}

		t.Logf("Successfully processed %s", fileName)
	}

	t.Logf("All tests passed successfully")
}

// convertExtrinsics converts the test vector extrinsic to block.Extrinsics
// func convertExtrinsics(extrinsic Extrinsic) extrinsics.Extrinsics {
// 	result := extrinsics.Extrinsics{}

// 	// // Convert tickets if any
// 	// for _, ticket := range extrinsic.Tickets {
// 	// 	// Parse ticket data from the test vector and add to result.Tickets
// 	// 	// This would require the specific ticket structure from the test vector
// 	// 	// For now, we'll skip if there are no tickets
// 	// }

// 	// // Convert preimages if any
// 	// for _, preimage := range extrinsic.Preimages {
// 	// 	// Parse preimage data from the test vector and add to result.Preimages
// 	// 	// This would require the specific preimage structure from the test vector
// 	// 	// For now, we'll skip if there are no preimages
// 	// }

// 	// // Convert guarantees if any
// 	// for _, guarantee := range extrinsic.Guarantees {
// 	// 	// Parse guarantee data from the test vector and add to result.Guarantees
// 	// 	// This would require the specific guarantee structure from the test vector
// 	// 	// For now, we'll skip if there are no guarantees
// 	// }

// 	// // Convert assurances if any
// 	// for _, assurance := range extrinsic.Assurances {
// 	// 	// Parse assurance data from the test vector and add to result.Assurances
// 	// 	// This would require the specific assurance structure from the test vector
// 	// 	// For now, we'll skip if there are no assurances
// 	// }

// 	// Convert disputes if any
// 	if len(extrinsic.Disputes.Verdicts) > 0 || len(extrinsic.Disputes.Culprits) > 0 || len(extrinsic.Disputes.Faults) > 0 {
// 		// Parse dispute data from the test vector and add to result.Disputes
// 		// This would require the specific dispute structure from the test vector
// 		// For now, we'll skip if there are no disputes
// 	}

// 	return result
// }

// BlockFromJSON parses a JSON block representation directly into a block.Block
func BlockFromJSON(blockJSON BlockJSON) (block.Block, error) {

	// Build the header
	blockHeader := header.Header{
		ParentHash:                   hexToHashMust(blockJSON.Header.Parent),
		PriorStateRoot:               hexToHashMust(blockJSON.Header.ParentStateRoot),
		ExtrinsicHash:                hexToHashMust(blockJSON.Header.ExtrinsicHash),
		TimeSlot:                     types.Timeslot(blockJSON.Header.Slot),
		BandersnatchBlockAuthorIndex: types.ValidatorIndex(blockJSON.Header.AuthorIndex),
		VRFSignature:                 types.BandersnatchVRFSignature(hexToBytes(blockJSON.Header.EntropySource)),
		BlockSeal:                    types.BandersnatchVRFSignature(hexToBytes(blockJSON.Header.Seal)),
	}

	if blockJSON.Header.EpochMark != nil {
		// Convert validators
		var validatorKeys [constants.NumValidators]struct {
			types.BandersnatchPublicKey
			types.Ed25519PublicKey
		}
		for i, v := range blockJSON.Header.EpochMark.Validators {
			validatorKeys[i] = struct {
				types.BandersnatchPublicKey
				types.Ed25519PublicKey
			}{
				types.BandersnatchPublicKey(hexToHashMust(v.Bandersnatch)),
				types.Ed25519PublicKey(hexToHashMust(v.Ed25519)),
			}
		}

		// Set up epoch mark
		blockHeader.EpochMarker = &header.EpochMarker{
			CurrentEpochRandomness: hexToHashMust(blockJSON.Header.EpochMark.Entropy),
			TicketsRandomness:      hexToHashMust(blockJSON.Header.EpochMark.TicketsEntropy),
			ValidatorKeys:          validatorKeys,
		}
	}

	// Handle OffendersMark if present
	offenders := make([]types.Ed25519PublicKey, 0)
	for _, offender := range blockJSON.Header.OffendersMark {
		// Convert offender to string if possible, otherwise skip
		if offenderMap, ok := offender.(map[string]interface{}); ok {
			if ed25519Str, ok := offenderMap["ed25519"].(string); ok {
				var key types.Ed25519PublicKey
				copy(key[:], hexToBytes(ed25519Str))
				offenders = append(offenders, key)
			}
		}
	}
	blockHeader.OffendersMarker = offenders

	blockHeader.WinningTicketsMarker = nil

	// Handle WinningTicketsMarker if present
	if blockJSON.Header.TicketsMark != nil {
		// Initialize with empty tickets to satisfy the type
		var tickets [constants.NumTimeslotsPerEpoch]header.Ticket
		blockHeader.WinningTicketsMarker = &tickets
	}

	// Convert extrinsic part (simplified for now)
	extrinsics := extrinsics.Extrinsics{
		Guarantees: convertGuarantees(blockJSON.Extrinsic.Guarantees),
		Assurances: convertAssurances(blockJSON.Extrinsic.Assurances),
		Disputes: extrinsics.Disputes{
			Verdicts: []extrinsics.Verdict{},
			Culprits: []extrinsics.Culprit{},
			Faults:   []extrinsics.Fault{},
		},
		Tickets:   extrinsics.Tickets{},
		Preimages: extrinsics.Preimages{},
	}

	// Build the full block
	return block.Block{
		Header:     blockHeader,
		Extrinsics: extrinsics,
	}, nil
}

// convertGuarantees converts JSON guarantees to extrinsics.Guarantees
func convertGuarantees(guaranteesJSON []GuaranteeJSON) extrinsics.Guarantees {
	guarantees := extrinsics.Guarantees{}

	for _, g := range guaranteesJSON {
		// Convert the work report
		implReport := convertJSONReportToImplReport(g.Report)

		// Convert signatures
		signatures := make([]extrinsics.Credential, 0, len(g.Signatures))
		for _, sig := range g.Signatures {
			// Convert the signature string to byte array
			sigBytes := hexToBytesMust(sig.Signature)

			// Create the Ed25519Signature (which is [64]byte)
			var ed25519Sig types.Ed25519Signature
			copy(ed25519Sig[:], sigBytes)

			// Create and append the guarantee signature
			signatures = append(signatures, extrinsics.Credential{
				ValidatorIndex: types.ValidatorIndex(sig.ValidatorIndex),
				Signature:      ed25519Sig,
			})
		}

		// Create and append the guarantee
		guarantee := extrinsics.Guarantee{
			WorkReport:  implReport,
			Timeslot:    types.Timeslot(g.Slot),
			Credentials: signatures,
		}

		guarantees = append(guarantees, guarantee)
	}

	return guarantees
}

func convertAssurances(assurancesJSON []Assurance) extrinsics.Assurances {
	assurances := extrinsics.Assurances{}

	for _, a := range assurancesJSON {
		// Convert anchor (parent hash) from hex string to [32]byte
		parentHash := hexToHashMust(a.Anchor)

		bytes := hexToBytesMust(a.Bitfield)

		// Convert bitfield string to BitSequence
		bitfield, err := bitsequence.FromBytesLSBWithLength(bytes, constants.NumCores)
		if err != nil {
			panic(err)
		}

		signature := hexToBytesMust(a.Signature)
		if len(signature) != 64 {
			panic("signature wrong length")
		}

		// Create and append the assurance
		assurance := extrinsics.Assurance{
			ParentHash:                    parentHash,
			CoreAvailabilityContributions: *bitfield,
			ValidatorIndex:                types.ValidatorIndex(a.ValidatorIndex),
			Signature:                     types.Ed25519Signature(signature),
		}

		assurances = append(assurances, assurance)
	}

	return assurances
}
