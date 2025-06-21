package statetransition

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/workreport"

	"github.com/ascrivener/jam/types"
)

// Define a struct to match the JSON structure
type ValidatorEntry struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
}

type EpochMark struct {
	Entropy        string           `json:"entropy"`
	TicketsEntropy string           `json:"tickets_entropy"`
	Validators     []ValidatorEntry `json:"validators"`
}

type TicketMark struct {
	ID      string `json:"id"`
	Attempt uint64 `json:"attempt"`
}

type OffenderMark struct {
}

type BlockHeader struct {
	Parent          string         `json:"parent"`
	ParentStateRoot string         `json:"parent_state_root"`
	ExtrinsicHash   string         `json:"extrinsic_hash"`
	Slot            int            `json:"slot"`
	AuthorIndex     int            `json:"author_index"`
	EntropySource   string         `json:"entropy_source"`
	Seal            string         `json:"seal"`
	EpochMark       *EpochMark     `json:"epoch_mark"`
	OffendersMark   []OffenderMark `json:"offenders_mark"`
	TicketsMark     *[]TicketMark  `json:"tickets_mark"`
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
	Report     WorkReportJSON           `json:"report"`
	Slot       uint64                   `json:"slot"`
	Signatures []GuaranteeSignatureJSON `json:"signatures"`
}

type Assurance struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint64 `json:"validator_index"`
	Signature      string `json:"signature"`
}

type Ticket struct {
	Attempt   uint64 `json:"attempt"`
	Signature string `json:"signature"`
}

type Preimage struct {
	ServiceIndex uint64 `json:"requester"`
	Data         string `json:"blob"`
}

type Extrinsic struct {
	Tickets    []Ticket        `json:"tickets"`
	Preimages  []Preimage      `json:"preimages"`
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

type KeyVals []struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// StateKeyValues represents the key-value pairs in a state
type StateKeyValues struct {
	StateRoot string  `json:"state_root"`
	KeyVals   KeyVals `json:"keyvals"`
}

func (k KeyVals) toMap() map[[31]byte][]byte {
	statemap := make(map[[31]byte][]byte)

	for _, kv := range k {
		key := hexToBytesMust(kv.Key)
		if len(key) != 31 {
			panic("Invalid serialized state key length:")
		}

		var keyArray [31]byte
		copy(keyArray[:], key)

		value := hexToBytesMust(kv.Value)
		statemap[keyArray] = value
	}

	return statemap
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
		t.Errorf("Failed to read test vectors directory: %v", err)
		return
	}

	testVectorPath := filepath.Join(vectorsDir, "00000000.json")
	testVectorData, err := os.ReadFile(testVectorPath)
	if err != nil {
		t.Errorf("Failed to load test vector file: %v", err)
		return
	}

	var initVector TestVector
	if err := json.Unmarshal(testVectorData, &initVector); err != nil {
		t.Errorf("Failed to parse test vector JSON: %v", err)
		return
	}

	initBlock, err := BlockFromJSON(initVector.Block)
	if err != nil {
		t.Errorf("Failed to parse block JSON: %v", err)
		return
	}

	// a. Deserialize pre-state from test vector
	initStateSerialized := initVector.PostState.KeyVals.toMap()
	t.Logf("Stage 2: Converted pre-state key-values to map format (%d entries)", len(initStateSerialized))

	// Create a temporary in-memory PebbleDB repository
	tempDir, err := os.MkdirTemp("", "jam-test-*")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	repo, err := staterepository.NewPebbleStateRepository(tempDir)
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Start transaction for batch operations
	if err := repo.BeginTransaction(); err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Store all key-value pairs into the repository
	batch := repo.GetBatch()
	for k, v := range initStateSerialized {
		// Add state: prefix to match production code
		prefixedKey := append([]byte("state:"), k[:]...)
		if err := batch.Set(prefixedKey, v, nil); err != nil {
			t.Fatalf("Failed to store key-value pair: %v", err)
		}
	}

	blockWithInfo := block.BlockWithInfo{
		Block: initBlock,
		Info: block.BlockInfo{
			PosteriorStateRoot: merklizer.MerklizeState(*repo),
		},
	}

	if err := blockWithInfo.Set(*repo); err != nil {
		t.Fatalf("Failed to store block: %v", err)
	}

	// Commit the transaction
	if err := repo.CommitTransaction(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}
	t.Logf("Stage 3: Stored %d key-value pairs in repository", len(initStateSerialized))

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

	failedTests := 0
	for _, fileName := range fileNames {
		if fileName == "00000000.json" {
			continue
		}
		t.Logf("Processing test vector file: %s", fileName)

		// Create a directory for logs if it doesn't exist
		// logDir := "test_logs"
		// if _, err := os.Stat(logDir); os.IsNotExist(err) {
		// 	err := os.Mkdir(logDir, 0755)
		// 	if err != nil {
		// 		t.Fatalf("Failed to create log directory '%s': %v", logDir, err)
		// 	}
		// }

		// // Initialize file logger for the current test vector
		// logFileName := strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".log"
		// logFilePath := filepath.Join(logDir, logFileName)
		// if err := pvm.InitFileLogger(logFilePath); err != nil {
		// 	t.Errorf("Failed to initialize file logger for %s: %v", logFilePath, err)
		// 	// Decide if you want to continue without logging or skip the test
		// 	// For now, let's log the error and continue
		// }

		// Process each file sequentially
		func() {

			// Load and parse test vector
			testVectorPath := filepath.Join(vectorsDir, fileName)
			testVectorData, err := os.ReadFile(testVectorPath)
			if err != nil {
				t.Errorf("Failed to load test vector file: %v", err)
				failedTests++
				return
			}

			var testVector TestVector
			if err := json.Unmarshal(testVectorData, &testVector); err != nil {
				t.Errorf("Failed to parse test vector JSON: %v", err)
				failedTests++
				return
			}
			t.Logf("Stage 1: Successfully loaded and parsed test vector from %s", fileName)

			// merklizedPreState := merklizer.MerklizeStateRecurser(bitSeqKeyMap)

			// if testVector.PreState.StateRoot != "0x"+hex.EncodeToString(merklizedPreState[:]) {
			// 	t.Fatalf("State root mismatch: expected %s, got %s", testVector.PreState.StateRoot, hex.EncodeToString(merklizedPreState[:]))
			// }

			// b. Convert block to implementation block and run state transition
			testBlock, err := BlockFromJSON(testVector.Block)
			if err != nil {
				t.Errorf("Failed to parse block JSON: %v", err)
				failedTests++
				return
			}
			t.Logf("Stage 8: Successfully converted JSON block to implementation block")

			// Run state transition function
			t.Logf("Stage 9: Running state transition function...")
			fileStart := time.Now()
			if err := LoadStateAndRunSTF(*repo, testBlock); err != nil {
				t.Errorf("Failed to run state transition function: %v", err)
				failedTests++
				return
			}
			fileEnd := time.Now()
			fmt.Printf("Stage 9: State transition completed in %v\n", fileEnd.Sub(fileStart))
			// logf("Stage 10: State transition completed")

			// serializedPostState := StateSerializer(postState)
			// logf("Stage 11: Serialized post-state (%d entries)", len(serializedPostState))

			// merklizedPostState := MerklizeState(postState)
			// expectedStateRoot := testVector.PostState.StateRoot
			// actualStateRoot := hex.EncodeToString(merklizedPostState[:])
			// stateRootMatch := expectedStateRoot == actualStateRoot
			// logf("Stage 12: Merklized post-state (state root match: %v)", stateRootMatch)

			// if !stateRootMatch {
			// 	t.Errorf("State root mismatch: expected %s, got %s", expectedStateRoot, actualStateRoot)
			// 	// Continue execution despite mismatch
			// }

			// Convert test vector's post-state key-values to the format expected by StateDeserializer
			expectedSerializedState := testVector.PostState.KeyVals.toMap()
			t.Logf("Stage 13: Converted expected post-state key-values to map format (%d entries)", len(expectedSerializedState))

			// Read all key-value pairs from the repository after state transition
			actualRepoKvs := make(map[[31]byte][]byte)
			repoIter, err := repo.NewIter(nil)
			if err != nil {
				t.Fatalf("Failed to create iterator: %v", err)
			}
			defer repoIter.Close()
			for repoIter.First(); repoIter.Valid(); repoIter.Next() {
				key := repoIter.Key()

				// Skip non-state keys or keys that are too short to have state: prefix + data
				if len(key) < 6 || !bytes.HasPrefix(key, []byte("state:")) {
					continue
				}

				// Remove the state: prefix for comparison with test vector data
				unprefixedKey := key[len("state:"):]

				var stateKey [31]byte
				copy(stateKey[:], unprefixedKey)

				value := repoIter.Value()
				valueCopy := make([]byte, len(value))
				copy(valueCopy, value)

				actualRepoKvs[stateKey] = valueCopy
			}
			repoIter.Close()
			t.Logf("Read %d key-value pairs from repository after state transition", len(actualRepoKvs))

			// Compare repository contents with expected key-value pairs
			t.Logf("Stage 14: Comparing repository key-values with expected post-state...")

			// Check missing keys in the repo
			for k, expectedValue := range expectedSerializedState {
				actualValue, exists := actualRepoKvs[k]
				if !exists {
					t.Errorf("Key missing in repository: %x", k)
					continue
				}

				// Compare values
				if !bytes.Equal(expectedValue, actualValue) {
					t.Errorf("Value mismatch for key %x:\nExpected: %x\nActual: %x\nDifferences: %s",
						k, expectedValue, actualValue, highlightByteDifferences(expectedValue, actualValue))
				}
			}

			// Check extra keys in the repo
			for k := range actualRepoKvs {
				if _, exists := expectedSerializedState[k]; !exists {
					t.Errorf("Extra key in repository: %x", k)
				}
			}

			// Deserialize the expected state
			// expectedPostState, err := GetState(*repo)
			// if err != nil {
			// 	t.Errorf("Failed to deserialize expected post-state: %v", err)
			// 	failedTests++
			// 	return
			// }
			// t.Logf("Stage 16: Successfully deserialized expected post-state")

			// // Use cmp.Diff for a detailed comparison of the state objects
			// t.Logf("Stage 17: Performing detailed comparison of state objects...")
			// if diff := cmp.Diff(expectedPostState, postState); diff != "" {
			// 	t.Errorf("Post-state mismatch (-expected +actual):\n%s", diff)
			// 	failedTests++
			// 	return
			// }
			// t.Logf("Stage 18: State objects match")

			// merklizedPostState := MerklizeState(postState)
			// expectedStateRoot := testVector.PostState.StateRoot
			// actualStateRoot := "0x" + hex.EncodeToString(merklizedPostState[:])
			// stateRootMatch := expectedStateRoot == actualStateRoot
			// if !stateRootMatch {
			// 	t.Errorf("State root mismatch: expected %s, got %s", expectedStateRoot, actualStateRoot)

			// 	serializedPostState := StateSerializer(postState)
			// 	expectedSerializedPostState := testVector.PostState.KeyVals.toMap()
			// 	if !compareSerializedStatesNoFatal(expectedSerializedPostState, serializedPostState, t) {
			// 		failedTests++
			// 		return
			// 	}
			// }
			// t.Logf("Stage 19: State root match")
			// t.Logf("Successfully processed %s", fileName)

			// Force garbage collection
			runtime.GC()
		}()
	}

	if failedTests > 0 {
		t.Errorf("Tests completed with %d failures", failedTests)
	} else {
		t.Logf("All tests passed successfully")
	}
}

// compareSerializedStatesNoFatal compares two serialized states and reports errors but doesn't fail the test
func compareSerializedStatesNoFatal(expected, actual map[[31]byte][]byte, t *testing.T) bool {
	success := true

	// Check if all expected keys are in the actual state
	for k, expectedValue := range expected {
		actualValue, exists := actual[k]
		if !exists {
			t.Errorf("Key missing in actual state: %x", k)
			success = false
			continue
		}

		// Compare values
		if !bytes.Equal(expectedValue, actualValue) {
			t.Errorf("Value mismatch for key %x:\nExpected: %x\nActual: %x\nDifferences: %s",
				k, expectedValue, actualValue, highlightByteDifferences(expectedValue, actualValue))
			success = false
		}
	}

	// Check if there are any extra keys in the actual state
	for k := range actual {
		if _, exists := expected[k]; !exists {
			t.Errorf("Extra key in actual state: %x", k)
			success = false
		}
	}

	return success
}

func highlightByteDifferences(expected, actual []byte) string {
	var b strings.Builder
	b.WriteString("Differences:\n")

	// Determine the length to compare
	minLen := len(expected)
	if len(actual) < minLen {
		minLen = len(actual)
	}

	// Compare bytes and highlight differences
	for i := 0; i < minLen; i++ {
		if expected[i] != actual[i] {
			b.WriteString(fmt.Sprintf("  Position %d: expected 0x%02x, got 0x%02x\n", i, expected[i], actual[i]))
		}
	}

	// Report if lengths are different
	if len(expected) != len(actual) {
		b.WriteString(fmt.Sprintf("  Length mismatch: expected %d bytes, got %d bytes\n", len(expected), len(actual)))

		// Show extra bytes in expected
		if len(expected) > len(actual) {
			b.WriteString("  Extra bytes in expected:\n  ")
			for i := minLen; i < len(expected); i++ {
				b.WriteString(fmt.Sprintf(" 0x%02x", expected[i]))
			}
			b.WriteString("\n")
		}

		// Show extra bytes in actual
		if len(actual) > len(expected) {
			b.WriteString("  Extra bytes in actual:\n  ")
			for i := minLen; i < len(actual); i++ {
				b.WriteString(fmt.Sprintf(" 0x%02x", actual[i]))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
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

	ticketsMark, err := convertTicketsMark(blockJSON.Header.TicketsMark)
	if err != nil {
		return block.Block{}, err
	}

	// Build the header
	blockHeader := header.Header{
		ParentHash:                   hexToHashMust(blockJSON.Header.Parent),
		PriorStateRoot:               hexToHashMust(blockJSON.Header.ParentStateRoot),
		ExtrinsicHash:                hexToHashMust(blockJSON.Header.ExtrinsicHash),
		TimeSlot:                     types.Timeslot(blockJSON.Header.Slot),
		BandersnatchBlockAuthorIndex: types.ValidatorIndex(blockJSON.Header.AuthorIndex),
		VRFSignature:                 types.BandersnatchVRFSignature(hexToBytes(blockJSON.Header.EntropySource)),
		BlockSeal:                    types.BandersnatchVRFSignature(hexToBytes(blockJSON.Header.Seal)),
		EpochMarker:                  convertEpochMark(blockJSON.Header.EpochMark),
		WinningTicketsMarker:         ticketsMark,
		OffendersMarker:              []types.Ed25519PublicKey{},
	}

	if len(blockJSON.Header.OffendersMark) > 0 {
		panic("Offenders marker not implemented")
	}

	tickets, err := convertTickets(blockJSON.Extrinsic.Tickets)
	if err != nil {
		return block.Block{}, err
	}
	// Convert extrinsic part (simplified for now)
	extrinsics := extrinsics.Extrinsics{
		Guarantees: convertGuarantees(blockJSON.Extrinsic.Guarantees),
		Assurances: convertAssurances(blockJSON.Extrinsic.Assurances),
		Disputes:   convertDisputes(blockJSON.Extrinsic.Disputes),
		Tickets:    tickets,
		Preimages:  convertPreimages(blockJSON.Extrinsic.Preimages),
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
		bitfield, err := bitsequence.CoreBitMaskFromBytesLSB(bytes)
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

func convertTickets(ticketsJSON []Ticket) (extrinsics.Tickets, error) {
	tickets := extrinsics.Tickets{}

	for _, t := range ticketsJSON {
		bytes := hexToBytesMust(t.Signature)
		if len(bytes) != 784 {
			panic("signature wrong length")
		}
		ticketEntryIndex, err := types.NewTicketEntryIndex(t.Attempt)
		if err != nil {
			return nil, err
		}
		tickets = append(tickets, extrinsics.Ticket{
			EntryIndex:    types.GenericNum(ticketEntryIndex),
			ValidityProof: types.BandersnatchRingVRFProof(bytes),
		})
	}

	return tickets, nil
}

func convertPreimages(preimagesJSON []Preimage) extrinsics.Preimages {
	preimages := extrinsics.Preimages{}

	for _, p := range preimagesJSON {
		preimages = append(preimages, extrinsics.Preimage{
			ServiceIndex: types.GenericNum(types.ServiceIndex(p.ServiceIndex)),
			Data:         hexToBytesMust(p.Data),
		})
	}

	return preimages
}

func convertDisputes(disputesJSON Disputes) extrinsics.Disputes {
	if len(disputesJSON.Verdicts) > 0 || len(disputesJSON.Culprits) > 0 || len(disputesJSON.Faults) > 0 {
		panic("disputes not supported")
	}
	return extrinsics.Disputes{
		Verdicts: []extrinsics.Verdict{},
		Culprits: []extrinsics.Culprit{},
		Faults:   []extrinsics.Fault{},
	}
}

func convertTicketsMark(ticketsMarkJSON *[]TicketMark) (*[constants.NumTimeslotsPerEpoch]header.Ticket, error) {
	tickets := [constants.NumTimeslotsPerEpoch]header.Ticket{}

	if ticketsMarkJSON == nil {
		return nil, nil
	}

	for i, t := range *ticketsMarkJSON {
		ticketEntryIndex, err := types.NewTicketEntryIndex(t.Attempt)
		if err != nil {
			return nil, err
		}
		tickets[i] = header.Ticket{
			EntryIndex:                 ticketEntryIndex,
			VerifiablyRandomIdentifier: hexToHashMust(t.ID),
		}
	}

	return &tickets, nil
}

func convertEpochMark(epochMarkJSON *EpochMark) *header.EpochMarker {
	if epochMarkJSON == nil {
		return nil
	}

	validatorKeys := [constants.NumValidators]struct {
		types.BandersnatchPublicKey
		types.Ed25519PublicKey
	}{}

	for i, v := range epochMarkJSON.Validators {
		validatorKeys[i] = struct {
			types.BandersnatchPublicKey
			types.Ed25519PublicKey
		}{
			types.BandersnatchPublicKey(hexToHashMust(v.Bandersnatch)),
			types.Ed25519PublicKey(hexToHashMust(v.Ed25519)),
		}
	}

	return &header.EpochMarker{
		CurrentEpochRandomness: hexToHashMust(epochMarkJSON.Entropy),
		TicketsRandomness:      hexToHashMust(epochMarkJSON.TicketsEntropy),
		ValidatorKeys:          validatorKeys,
	}
}

// hexToBytesMust converts a hex string to bytes, panicking on error
func hexToBytesMust(hexStr string) []byte {
	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string: %s", err))
	}

	return bytes
}

// hexToHashMust panics if the hash cannot be converted
func hexToHashMust(hexStr string) [32]byte {
	hash, err := hexToHash(hexStr)
	if err != nil {
		panic(fmt.Sprintf("invalid hash: %s", err))
	}
	return hash
}

// convertJSONReportToImplReport converts a workreport from the JSON to the implementation's WorkReport type
func convertJSONReportToImplReport(workReportJSON WorkReportJSON) workreport.WorkReport {
	var report workreport.WorkReport

	// Set CoreIndex
	report.CoreIndex = types.GenericNum(workReportJSON.CoreIndex)

	// Convert results
	for _, result := range workReportJSON.Results {
		codeHash := hexToHashMust(string(result.CodeHash))
		payloadHash := hexToHashMust(string(result.PayloadHash))

		workDigest := workreport.WorkDigest{
			ServiceIndex:                 types.ServiceIndex(result.ServiceId),
			ServiceCodeHash:              codeHash,
			PayloadHash:                  payloadHash,
			AccumulateGasLimit:           types.GasValue(result.AccumulateGas),
			WorkResult:                   types.ExecutionExitReason{},
			ActualRefinementGasUsed:      types.GenericGasValue(result.RefineLoad.GasUsed),
			NumSegmentsImportedFrom:      types.GenericNum(result.RefineLoad.Imports),
			NumExtrinsicsUsed:            types.GenericNum(result.RefineLoad.ExtrinsicCount),
			SizeInOctetsOfExtrinsicsUsed: types.GenericNum(result.RefineLoad.ExtrinsicSize),
			NumSegmentsExportedInto:      types.GenericNum(result.RefineLoad.Exports),
		}

		if result.Result.OK != nil {
			// If OK is present, convert hex string to binary
			workDigest.WorkResult = types.NewExecutionExitReasonBlob(hexToBytesMust(string(*result.Result.OK)))
		}

		report.WorkDigests = append(report.WorkDigests, workDigest)
	}

	// Set package spec
	packageSpecHash := hexToHashMust(string(workReportJSON.PackageSpec.Hash))
	erasureRoot := hexToHashMust(string(workReportJSON.PackageSpec.ErasureRoot))
	exportsRoot := hexToHashMust(string(workReportJSON.PackageSpec.ExportsRoot))

	report.WorkPackageSpecification = workreport.AvailabilitySpecification{
		WorkPackageHash:  packageSpecHash,                                     // h
		WorkBundleLength: types.BlobLength(workReportJSON.PackageSpec.Length), // l
		ErasureRoot:      erasureRoot,                                         // u
		SegmentRoot:      exportsRoot,                                         // e - ExportsRoot maps to SegmentRoot
		SegmentCount:     uint16(workReportJSON.PackageSpec.ExportsCount),     // n - ExportsCount maps to SegmentCount
	}

	// Set refinement context
	anchorHash := hexToHashMust(string(workReportJSON.Context.Anchor))
	stateRoot := hexToHashMust(string(workReportJSON.Context.StateRoot))
	beefyRoot := hexToHashMust(string(workReportJSON.Context.BeefyRoot))
	lookupAnchor := hexToHashMust(string(workReportJSON.Context.LookupAnchor))

	// Convert prerequisites to map of [32]byte
	prereqMap := make(map[[32]byte]struct{})
	for _, prereq := range workReportJSON.Context.Prerequisites {
		hash := hexToHashMust(string(prereq))
		prereqMap[hash] = struct{}{}
	}

	report.RefinementContext = workreport.RefinementContext{
		AnchorHeaderHash:              anchorHash,                                              // a
		PosteriorStateRoot:            stateRoot,                                               // s
		PosteriorBEEFYRoot:            beefyRoot,                                               // b
		LookupAnchorHeaderHash:        lookupAnchor,                                            // l
		Timeslot:                      types.Timeslot(workReportJSON.Context.LookupAnchorSlot), // t
		PrerequisiteWorkPackageHashes: prereqMap,                                               // p
	}

	// Set AuthorizerHash (a)
	authorizerHash := hexToHashMust(string(workReportJSON.AuthorizerHash))
	report.AuthorizerHash = authorizerHash

	// Set Output (o) - properly decode the hex string ByteSequence to bytes
	if workReportJSON.AuthOutput != "" {
		output := hexToBytesMust(string(workReportJSON.AuthOutput))
		report.Output = output
	} else {
		report.Output = []byte{}
	}

	// Set SegmentRootLookup (l)
	report.SegmentRootLookup = make(map[[32]byte][32]byte)
	for _, item := range workReportJSON.SegmentRootLookup {
		key := hexToHashMust(string(item.WorkPackageHash))
		val := hexToHashMust(string(item.SegmentTreeRoot))
		report.SegmentRootLookup[key] = val
	}

	// Set IsAuthorizedGasConsumption from AuthGasUsed
	report.IsAuthorizedGasConsumption = types.GenericGasValue(workReportJSON.AuthGasUsed)

	return report
}

// Helper functions for hash conversion
func hexToHash(hexStr string) ([32]byte, error) {
	var result [32]byte

	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}

	// Check length
	if len(hexStr) != 64 {
		return result, fmt.Errorf("invalid hash length: %d", len(hexStr))
	}

	// Convert from hex
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, err
	}

	// Copy to result
	copy(result[:], bytes)
	return result, nil
}

// RefineContext represents a context for refinement
type RefineContext struct {
	Anchor           string   `json:"anchor"`
	StateRoot        string   `json:"state_root"`
	BeefyRoot        string   `json:"beefy_root"`
	LookupAnchor     string   `json:"lookup_anchor"`
	LookupAnchorSlot uint64   `json:"lookup_anchor_slot"`
	Prerequisites    []string `json:"prerequisites"`
}

// WorkExecResult represents the result of work execution (OK or error)
type WorkExecResult struct {
	OK *string `json:"ok,omitempty"`
}

// Import specification
type ImportSpec struct {
	// Add fields if needed
}

// Extrinsic specification
type ExtrinsicSpec struct {
	// Add fields if needed
}

// Authorizer type
type Authorizer string

// WorkReport represents a work report
type WorkReportJSON struct {
	PackageSpec       WorkPackageSpec   `json:"package_spec"`
	Context           RefineContext     `json:"context"`
	CoreIndex         uint64            `json:"core_index"`
	AuthorizerHash    string            `json:"authorizer_hash"`
	AuthOutput        string            `json:"auth_output"`
	SegmentRootLookup SegmentRootLookup `json:"segment_root_lookup"`
	Results           []WorkDigest      `json:"results"`
	AuthGasUsed       uint64            `json:"auth_gas_used"`
}

// RefineLoad represents the load statistics for refinement
type RefineLoad struct {
	GasUsed        uint64 `json:"gas_used"`
	Imports        uint64 `json:"imports"`
	ExtrinsicCount uint64 `json:"extrinsic_count"`
	ExtrinsicSize  uint64 `json:"extrinsic_size"`
	Exports        uint64 `json:"exports"`
}

// WorkDigest represents the result of work execution
type WorkDigest struct {
	ServiceId     uint64         `json:"service_id"`
	CodeHash      string         `json:"code_hash"`
	PayloadHash   string         `json:"payload_hash"`
	AccumulateGas uint64         `json:"accumulate_gas"`
	Result        WorkExecResult `json:"result"`
	RefineLoad    RefineLoad     `json:"refine_load"`
}

// WorkPackageSpec represents a specification of a work package
type WorkPackageSpec struct {
	Hash         string `json:"hash"`
	Length       uint64 `json:"length"`
	ErasureRoot  string `json:"erasure_root"`
	ExportsRoot  string `json:"exports_root"`
	ExportsCount uint64 `json:"exports_count"`
}

// SegmentRootLookupItem represents a lookup item for segment roots
type SegmentRootLookupItem struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

// SegmentRootLookup represents a collection of segment root lookup items
type SegmentRootLookup []SegmentRootLookupItem
