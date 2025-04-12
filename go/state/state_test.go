package state

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/test/asntypes"

	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	"github.com/google/go-cmp/cmp"
)

// TestStateTransitionAccumulation runs accumulation-specific tests with relevant fields
func TestStateTransitionAccumulation(t *testing.T) {
	// List of fields relevant to accumulation based on ASN.1 definition:
	// State ::= SEQUENCE {
	//    slot TimeSlot,               -> MostRecentBlockTimeslot
	//    entropy Entropy,             -> EntropyAccumulator
	//    ready-queue ReadyQueue,      -> AccumulationQueue
	//    accumulated AccumulatedQueue,-> AccumulationHistory
	//    privileges Privileges,       -> PrivilegedServices
	//    accounts SEQUENCE OF AccountsMapEntry -> ServiceAccounts
	// }
	accumulationFields := []string{
		"MostRecentBlockTimeslot", // slot in ASN.1
		// "EntropyAccumulator",      // entropy in ASN.1
		"AccumulationQueue",   // ready-queue in ASN.1
		"AccumulationHistory", // accumulated in ASN.1
		"PrivilegedServices",  // privileges in ASN.1
		"ServiceAccounts",     // accounts in ASN.1
	}

	// Get test directory from environment variable, default to "tiny"
	testDir := os.Getenv("JAM_TEST_VECTOR_DIR")
	if testDir == "" {
		testDir = "tiny"
	}

	// Run test cases with accumulation-related fields
	// The path is relative to the testVectorDir in runStateTransitionTest
	runStateTransitionTest(t, testDir, accumulationFields)
}

// runStateTransitionTest is a helper that runs state transition tests for all JSON files in a directory
// If fieldsToCompare is empty, all fields will be compared
func runStateTransitionTest(t *testing.T, testDir string, fieldsToCompare []string) {
	// Base directory containing the test vectors
	testVectorDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/accumulate"

	// Full path to the test directory
	fullDirPath := filepath.Join(testVectorDir, testDir)

	// Find all JSON files in the directory
	files, err := filepath.Glob(filepath.Join(fullDirPath, "*.json"))
	if err != nil {
		t.Fatalf("Failed to read test directory %s: %v", fullDirPath, err)
	}

	if len(files) == 0 {
		t.Fatalf("No test vectors found in %s", fullDirPath)
	}

	// Run each test file
	for _, file := range files {
		fileName := filepath.Base(file)
		testName := testDir + "/" + fileName

		t.Run(testName, func(t *testing.T) {
			// t.Parallel() // Run tests in parallel

			// Log when a test starts
			t.Logf("Starting test vector: %s", testName)

			// Parse the test vector using our asntypes package
			testCase, err := asntypes.ParseTestCase(file)
			if err != nil {
				t.Fatalf("Failed to parse test case: %v", err)
			}
			t.Logf("✅ Successfully parsed test vector %s", testName)

			// Convert asntypes.State to our implementation's State
			priorState := convertAsnStateToImplState(testCase.PreState)
			t.Logf("✅ Converted prior state from ASN format")

			// Extract posterior timeslot from input
			reportsTimeslot := types.Timeslot(testCase.Input.Slot) // Assuming prior timeslot is one less
			t.Logf("Processing reports for timeslot %d", reportsTimeslot)

			// Add input reports to pending reports in prior state (for dispute testing)
			// This simulates reports that were submitted in a previous block
			reportCount := 0
			for _, asnReport := range testCase.Input.Reports {
				report := convertAsnReportToImplReport(asnReport)
				coreIndex := int(report.CoreIndex)
				reportCount++

				// Only add if there's not already a pending report for this core
				if priorState.PendingReports[coreIndex] == nil {
					priorState.PendingReports[coreIndex] = &PendingReport{
						WorkReport: report,
						Timeslot:   reportsTimeslot,
					}
				}
			}
			t.Logf("✅ Added %d reports to pending reports", reportCount)

			// Build a mock Block with the necessary components
			mockBlock := buildMockBlockFromTestVector(types.Timeslot(testCase.Input.Slot))
			t.Logf("✅ Created mock block for timeslot %d", mockBlock.Header.TimeSlot)

			// Run the full state transition function
			t.Logf("Running state transition function...")
			actualState := StateTransitionFunction(priorState, mockBlock)
			t.Logf("✅ State transition completed")

			// Convert the expected post-state from asntypes.State to our implementation's State
			expectedState := convertAsnStateToImplState(testCase.PostState)
			t.Logf("✅ Converted expected post-state from ASN format")

			// Compare the expected and actual states based on provided fields
			t.Logf("Comparing states based on %d fields...", len(fieldsToCompare))
			compareStatesSelective(t, expectedState, actualState, fieldsToCompare)

			// If we got here without failing, the test passed!
			t.Logf("✅ TEST PASSED: %s", testName)
		})
	}
}

// buildMockBlockFromTestVector creates a mock Block from a test vector
func buildMockBlockFromTestVector(posteriorTimeslot types.Timeslot) block.Block {
	// Create a minimal valid header
	mockHeader := header.Header{
		TimeSlot:       posteriorTimeslot,
		PriorStateRoot: [32]byte{}, // We can leave this empty for now
		// Add other required fields with default/empty values
	}

	// // Process all reports in the test vector input
	// for _, asnReport := range testCase.Input.Reports {
	// 	// Convert report to implementation type
	// 	report := convertAsnReportToImplReport(asnReport)

	// 	// Add to guarantees - these are the actual work reports validators have validated
	// 	mockGuarantee := extrinsics.Guarantee{
	// 		WorkReport: report,
	// 		Timeslot:   posteriorTimeslot, // Use the current timeslot for the guarantee
	// 		Credentials: []extrinsics.Credential{
	// 			{
	// 				ValidatorIndex: 0,                        // Using validator index 0 for simplicity in tests
	// 				Signature:      types.Ed25519Signature{}, // Empty signature for tests
	// 			},
	// 		},
	// 	}
	// 	mockGuarantees = append(mockGuarantees, mockGuarantee)
	// }

	// Create the block
	mockBlock := block.Block{
		Header: mockHeader,
		Extrinsics: extrinsics.Extrinsics{
			Assurances: makeMockAssurances(),
			Guarantees: extrinsics.Guarantees{},
			Preimages:  extrinsics.Preimages{},
			Disputes:   extrinsics.Disputes{},
			Tickets:    extrinsics.Tickets{},
		},
	}

	return mockBlock
}

// makeMockAssurances creates assurances for all validators with all cores marked as available
func makeMockAssurances() extrinsics.Assurances {
	// For test purposes, we'll create assurances for all validators with all cores marked as available

	// Create a bit sequence with all bits set to 1
	coreContributions := bitsequence.NewZeros(constants.NumCores)
	// Set all bits to 1
	for i := 0; i < constants.NumCores; i++ {
		coreContributions.SetBitAt(i, true)
	}

	var assurances extrinsics.Assurances
	for validatorIndex := 0; validatorIndex < constants.NumValidators; validatorIndex++ {
		// Create an assurance with all bits set
		assurance := extrinsics.Assurance{
			ParentHash:                    [32]byte{}, // Would be set to the actual parent hash in production
			CoreAvailabilityContributions: *coreContributions,
			ValidatorIndex:                types.ValidatorIndex(validatorIndex),
			Signature:                     types.Ed25519Signature{}, // Empty signature for tests
		}

		// Append the new assurance
		assurances = append(assurances, assurance)
	}

	return assurances
}

// hexToHash converts a hex string (with or without 0x prefix) to a [32]byte array
func hexToHash(hexStr string) [32]byte {
	var hash [32]byte

	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// Handle empty string case
	if hexStr == "" {
		return hash
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Errorf("failed to decode hex string: %v", err))
	}

	// Ensure correct length
	if len(decoded) != 32 {
		panic(fmt.Errorf("expected 32 bytes, got %d", len(decoded)))
	}

	copy(hash[:], decoded)
	return hash
}

// hexToBytes converts a hex string (with or without 0x prefix) to a byte slice
func hexToBytes(hexStr string) []byte {
	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// Handle empty string case
	if hexStr == "" {
		return []byte{}
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(fmt.Errorf("failed to decode hex string: %v", err))
	}

	return decoded
}

// createEmptyState creates a fully initialized State with proper zero values and non-nil fields
func createEmptyState() State {
	// Initialize with zero values but ensure all maps/slices are properly initialized
	state := State{
		ServiceAccounts:            make(serviceaccount.ServiceAccounts),
		AccumulationQueue:          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{},
		AccumulationHistory:        [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}{},
		EntropyAccumulator:         [4][32]byte{},
		RecentBlocks:               make([]RecentBlock, 0),
		SafroleBasicState:          SafroleBasicState{},
		ValidatorKeysetsStaging:    types.ValidatorKeysets{},
		ValidatorKeysetsActive:     types.ValidatorKeysets{},
		ValidatorKeysetsPriorEpoch: types.ValidatorKeysets{},
		PendingReports:             [constants.NumCores]*PendingReport{},
		AuthorizerQueue:            [constants.NumCores][constants.AuthorizerQueueLength][32]byte{},
		PrivilegedServices:         types.PrivilegedServices{},
		Disputes:                   types.Disputes{},
		ValidatorStatistics:        [2][constants.NumValidators]SingleValidatorStatistics{},
		MostRecentBlockTimeslot:    0,
	}

	// Initialize maps in AccumulationHistory
	for i := range state.AccumulationHistory {
		state.AccumulationHistory[i] = make(map[[32]byte]struct{})
	}

	// Initialize AuthorizersPool with empty (but non-nil) slices
	state.AuthorizersPool = [constants.NumCores][][32]byte{}
	for i := 0; i < constants.NumCores; i++ {
		state.AuthorizersPool[i] = make([][32]byte, 0)
	}

	return state
}

// convertAsnStateToImplState converts a state from the ASN types to the implementation's State type
func convertAsnStateToImplState(asnState asntypes.State) State {
	// Create a fully initialized state with proper zero values
	state := createEmptyState()

	// Set the timeslot
	state.MostRecentBlockTimeslot = types.Timeslot(asnState.Slot)

	// Set entropy from ASN state
	entropyHash := hexToHash(string(asnState.Entropy))
	state.EntropyAccumulator[0] = entropyHash

	// Convert ready queue
	for idx, queueItem := range asnState.ReadyQueue {
		if idx >= constants.NumTimeslotsPerEpoch {
			continue // Skip if index is out of bounds
		}

		w := make([]workreport.WorkReportWithWorkPackageHashes, 0)
		for _, readyRecord := range queueItem {
			workPackageHashes := make(map[[32]byte]struct{})
			for _, dep := range readyRecord.Dependencies {
				hash := hexToHash(string(dep))
				workPackageHashes[hash] = struct{}{}
			}

			w = append(w, workreport.WorkReportWithWorkPackageHashes{
				WorkReport:        convertAsnReportToImplReport(readyRecord.Report),
				WorkPackageHashes: workPackageHashes,
			})
		}
		state.AccumulationQueue[idx] = w
	}

	// Convert accumulated queue
	for idx, accItem := range asnState.Accumulated {
		if idx >= constants.NumTimeslotsPerEpoch {
			continue // Skip if index is out of bounds
		}

		workPackageHashes := make(map[[32]byte]struct{})
		for _, hashStr := range accItem {
			hash := hexToHash(string(hashStr))
			workPackageHashes[hash] = struct{}{}
		}
		state.AccumulationHistory[idx] = workPackageHashes
	}

	// Process accounts
	for _, account := range asnState.Accounts {
		// Create a new service account
		serviceAccount := serviceaccount.ServiceAccount{
			Balance:                        types.Balance(account.Data.Service.Balance),
			MinimumGasForAccumulate:        types.GasValue(account.Data.Service.MinItemGas),
			MinimumGasForOnTransfer:        types.GasValue(account.Data.Service.MinMemoGas),
			PreimageLookup:                 make(map[[32]byte][]byte),
			PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
		}

		// Set code hash
		codeHash := hexToHash(string(account.Data.Service.CodeHash))
		serviceAccount.CodeHash = codeHash

		// Add preimages
		for _, preimage := range account.Data.Preimages {
			hashArray := hexToHash(string(preimage.Hash))
			// Properly decode hex string to binary
			serviceAccount.PreimageLookup[hashArray] = hexToBytes(string(preimage.Blob))
		}

		// Add the service account to the state
		state.ServiceAccounts[types.ServiceIndex(account.ID)] = &serviceAccount
	}

	return state
}

// convertAsnReportToImplReport converts a workreport from the ASN types to the implementation's WorkReport type
func convertAsnReportToImplReport(asnReport asntypes.WorkReport) workreport.WorkReport {
	var report workreport.WorkReport

	// Set CoreIndex
	report.CoreIndex = types.CoreIndex(asnReport.CoreIndex)

	// Convert results
	for _, result := range asnReport.Results {
		codeHash := hexToHash(string(result.CodeHash))
		payloadHash := hexToHash(string(result.PayloadHash))

		workResult := workreport.WorkResult{
			ServiceIndex:           types.ServiceIndex(result.ServiceId),
			ServiceCodeHash:        codeHash,
			PayloadHash:            payloadHash,
			GasPrioritizationRatio: types.GasValue(result.AccumulateGas),
		}

		if result.Result.OK != nil {
			// If OK is present, convert hex string to binary
			workResult.WorkOutput = types.NewExecutionExitReasonBlob(hexToBytes(string(*result.Result.OK)))
		}

		report.WorkResults = append(report.WorkResults, workResult)
	}

	// Set package spec
	packageSpecHash := hexToHash(string(asnReport.PackageSpec.Hash))
	erasureRoot := hexToHash(string(asnReport.PackageSpec.ErasureRoot))
	exportsRoot := hexToHash(string(asnReport.PackageSpec.ExportsRoot))

	report.WorkPackageSpecification = workreport.AvailabilitySpecification{
		WorkPackageHash:  packageSpecHash,                                // h
		WorkBundleLength: types.BlobLength(asnReport.PackageSpec.Length), // l
		ErasureRoot:      erasureRoot,                                    // u
		SegmentRoot:      exportsRoot,                                    // e - ExportsRoot maps to SegmentRoot
		SegmentCount:     uint64(asnReport.PackageSpec.ExportsCount),     // n - ExportsCount maps to SegmentCount
	}

	// Set refinement context
	anchorHash := hexToHash(string(asnReport.Context.Anchor))
	stateRoot := hexToHash(string(asnReport.Context.StateRoot))
	beefyRoot := hexToHash(string(asnReport.Context.BeefyRoot))
	lookupAnchor := hexToHash(string(asnReport.Context.LookupAnchor))

	// Convert prerequisites to map of [32]byte
	prereqMap := make(map[[32]byte]struct{})
	for _, prereq := range asnReport.Context.Prerequisites {
		hash := hexToHash(string(prereq))
		prereqMap[hash] = struct{}{}
	}

	report.RefinementContext = workreport.RefinementContext{
		AnchorHeaderHash:              anchorHash,                                         // a
		PosteriorStateRoot:            stateRoot,                                          // s
		PosteriorBEEFYRoot:            beefyRoot,                                          // b
		LookupAnchorHeaderHash:        lookupAnchor,                                       // l
		Timeslot:                      types.Timeslot(asnReport.Context.LookupAnchorSlot), // t
		PrerequisiteWorkPackageHashes: prereqMap,                                          // p
	}

	// Set AuthorizerHash (a)
	authorizerHash := hexToHash(string(asnReport.AuthorizerHash))
	report.AuthorizerHash = authorizerHash

	// Set Output (o) - properly decode the hex string ByteSequence to bytes
	if asnReport.AuthOutput != "" {
		output := hexToBytes(string(asnReport.AuthOutput))
		report.Output = output
	} else {
		report.Output = []byte{}
	}

	// Set SegmentRootLookup (l)
	report.SegmentRootLookup = make(map[[32]byte][32]byte)
	for _, item := range asnReport.SegmentRootLookup {
		key := hexToHash(string(item.WorkPackageHash))
		val := hexToHash(string(item.SegmentTreeRoot))
		report.SegmentRootLookup[key] = val
	}

	return report
}

// compareStatesSelective compares specific fields between two State objects
// If fields is nil or empty, all fields are compared
func compareStatesSelective(t *testing.T, expected, actual State, fields []string) {
	if len(fields) == 0 {
		// Compare entire state if no fields specified
		if diff := cmp.Diff(expected, actual); diff != "" {
			t.Errorf("States don't match (-expected +actual):\n%s", diff)
		}
		return
	}

	// Check each field individually to provide more focused comparison
	// This avoids issues with complex filtering in cmp.FilterPath
	for _, fieldName := range fields {
		// Use reflection to get the field values
		expectedVal := reflect.ValueOf(expected).FieldByName(fieldName)
		actualVal := reflect.ValueOf(actual).FieldByName(fieldName)

		if !expectedVal.IsValid() || !actualVal.IsValid() {
			t.Errorf("Field %s does not exist in State struct", fieldName)
			continue
		}

		// Compare just this individual field
		if diff := cmp.Diff(expectedVal.Interface(), actualVal.Interface()); diff != "" {
			t.Errorf("Field %s doesn't match (-expected +actual):\n%s", fieldName, diff)
		}
	}
}
