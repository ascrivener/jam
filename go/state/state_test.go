package state

import (
	"encoding/hex"
	"fmt"
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

	// Define test cases to run
	testCases := []struct {
		subdir   string
		filename string
	}{
		// {"tiny", "accumulate_ready_queued_reports-1.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-1.json"},
		{"tiny", "no_available_reports-1.json"},
		// Add more test cases as needed
	}

	// Run test cases with accumulation-related fields
	runStateTransitionTest(t, testCases, accumulationFields)
}

// runStateTransitionTest is a helper that runs state transition tests with specified test cases and fields to compare
// If fieldsToCompare is empty, all fields will be compared
func runStateTransitionTest(t *testing.T, testCases []struct {
	subdir   string
	filename string
}, fieldsToCompare []string) {
	// Base directory containing the test vectors
	testVectorDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/accumulate"

	if len(testCases) == 0 {
		t.Fatalf("No test cases provided")
	}

	for _, tc := range testCases {
		testName := tc.subdir + "/" + tc.filename
		t.Run(testName, func(t *testing.T) {
			// Full path to the test vector
			testVectorPath := filepath.Join(testVectorDir, tc.subdir, tc.filename)

			// Parse the test vector using our asntypes package
			testCase, err := asntypes.ParseTestCase(testVectorPath)
			if err != nil {
				t.Fatalf("Failed to parse test case: %v", err)
			}

			// Convert asntypes.State to our implementation's State
			priorState := convertAsnStateToImplState(testCase.PreState)

			// Extract posterior timeslot from input
			reportsTimeslot := types.Timeslot(testCase.Input.Slot) // Assuming prior timeslot is one less

			// Add input reports to pending reports in prior state (for dispute testing)
			// This simulates reports that were submitted in a previous block
			for _, asnReport := range testCase.Input.Reports {
				report := convertAsnReportToImplReport(asnReport)
				coreIndex := int(report.CoreIndex)

				// Only add if there's not already a pending report for this core
				if priorState.PendingReports[coreIndex] == nil {
					priorState.PendingReports[coreIndex] = &PendingReport{
						WorkReport: report,
						Timeslot:   reportsTimeslot,
					}
				}
			}

			// Build a mock Block with the necessary components
			mockBlock := buildMockBlockFromTestVector(testCase, types.Timeslot(testCase.Input.Slot))

			// Run the full state transition function
			actualState := StateTransitionFunction(priorState, mockBlock)

			// Convert the expected post-state from asntypes.State to our implementation's State
			expectedState := convertAsnStateToImplState(testCase.PostState)

			// Compare the expected and actual states based on provided fields
			compareStatesSelective(t, expectedState, actualState, fieldsToCompare)
		})
	}
}

// buildMockBlockFromTestVector creates a mock Block from a test vector
func buildMockBlockFromTestVector(testCase *asntypes.TestCase, posteriorTimeslot types.Timeslot) block.Block {
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
func hexToHash(hexStr string) ([32]byte, error) {
	var hash [32]byte

	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// Handle empty string case
	if hexStr == "" {
		return hash, nil
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return hash, fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Ensure correct length
	if len(decoded) != 32 {
		return hash, fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}

	copy(hash[:], decoded)
	return hash, nil
}

// hexToBytes converts a hex string (with or without 0x prefix) to a byte slice
func hexToBytes(hexStr string) ([]byte, error) {
	// Remove 0x prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}

	// Handle empty string case
	if hexStr == "" {
		return []byte{}, nil
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	return decoded, nil
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
	entropyHash, _ := hexToHash(string(asnState.Entropy))
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
				hash, _ := hexToHash(string(dep))
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
			hash, _ := hexToHash(string(hashStr))
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
		codeHash, _ := hexToHash(string(account.Data.Service.CodeHash))
		serviceAccount.CodeHash = codeHash

		// Add preimages
		for _, preimage := range account.Data.Preimages {
			hashArray, _ := hexToHash(string(preimage.Hash))
			serviceAccount.PreimageLookup[hashArray] = []byte(preimage.Blob)
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
		codeHash, _ := hexToHash(string(result.CodeHash))
		payloadHash, _ := hexToHash(string(result.PayloadHash))

		workResult := workreport.WorkResult{
			ServiceIndex:           types.ServiceIndex(result.ServiceId),
			ServiceCodeHash:        codeHash,
			PayloadHash:            payloadHash,
			GasPrioritizationRatio: types.GasValue(result.AccumulateGas),
		}

		if result.Result.OK != nil {
			// If OK is present, convert to blob
			workResult.WorkOutput = types.NewExecutionExitReasonBlob([]byte(*result.Result.OK))
		}

		report.WorkResults = append(report.WorkResults, workResult)
	}

	// Set package spec
	packageSpecHash, _ := hexToHash(string(asnReport.PackageSpec.Hash))
	erasureRoot, _ := hexToHash(string(asnReport.PackageSpec.ErasureRoot))
	exportsRoot, _ := hexToHash(string(asnReport.PackageSpec.ExportsRoot))

	report.WorkPackageSpecification = workreport.AvailabilitySpecification{
		WorkPackageHash:  packageSpecHash,                                // h
		WorkBundleLength: types.BlobLength(asnReport.PackageSpec.Length), // l
		ErasureRoot:      erasureRoot,                                    // u
		SegmentRoot:      exportsRoot,                                    // e - ExportsRoot maps to SegmentRoot
		SegmentCount:     uint64(asnReport.PackageSpec.ExportsCount),     // n - ExportsCount maps to SegmentCount
	}

	// Set refinement context
	anchorHash, _ := hexToHash(string(asnReport.Context.Anchor))
	stateRoot, _ := hexToHash(string(asnReport.Context.StateRoot))
	beefyRoot, _ := hexToHash(string(asnReport.Context.BeefyRoot))
	lookupAnchor, _ := hexToHash(string(asnReport.Context.LookupAnchor))

	// Convert prerequisites to map of [32]byte
	prereqMap := make(map[[32]byte]struct{})
	for _, prereq := range asnReport.Context.Prerequisites {
		hash, _ := hexToHash(string(prereq))
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
	authorizerHash, _ := hexToHash(string(asnReport.AuthorizerHash))
	report.AuthorizerHash = authorizerHash

	// Set Output (o) - properly decode the hex string ByteSequence to bytes
	if asnReport.AuthOutput != "" {
		output, _ := hexToBytes(string(asnReport.AuthOutput))
		report.Output = output
	} else {
		report.Output = []byte{}
	}

	// Set SegmentRootLookup (l)
	report.SegmentRootLookup = make(map[[32]byte][32]byte)
	for _, item := range asnReport.SegmentRootLookup {
		key, _ := hexToHash(string(item.WorkPackageHash))
		val, _ := hexToHash(string(item.SegmentTreeRoot))
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
