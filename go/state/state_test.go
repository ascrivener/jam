package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	// Import other necessary packages from your jam implementation
)

// TestVector represents the JSON structure of test vectors
type TestVector struct {
	Input     interface{} `json:"input"`
	PreState  interface{} `json:"pre_state"`
	Output    interface{} `json:"output"`
	PostState interface{} `json:"post_state"`
}

// LoadTestVector loads a test vector from a JSON file
func LoadTestVector(filePath string) (*TestVector, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading test vector file: %w", err)
	}

	var testVector TestVector
	if err := json.Unmarshal(data, &testVector); err != nil {
		return nil, fmt.Errorf("error unmarshaling test vector: %w", err)
	}

	return &testVector, nil
}

// StateJSON represents the structure of the state field in test vectors
type StateJSON struct {
	Slot        types.Timeslot  `json:"slot"`
	Entropy     string          `json:"entropy"`
	ReadyQueue  [][]interface{} `json:"ready_queue"`
	Accumulated [][]interface{} `json:"accumulated"`
	Privileges  struct {
		Bless     int           `json:"bless"`
		Assign    int           `json:"assign"`
		Designate int           `json:"designate"`
		AlwaysAcc []interface{} `json:"always_acc"`
	} `json:"privileges"`
	Accounts []struct {
		ID   int `json:"id"`
		Data struct {
			Service struct {
				Balance    float64 `json:"balance"`
				MinItemGas float64 `json:"min_item_gas"`
				MinMemoGas float64 `json:"min_memo_gas"`
				CodeHash   string  `json:"code_hash"`
			} `json:"service"`
			Preimages []struct {
				Hash string `json:"hash"`
				Blob string `json:"blob"`
			} `json:"preimages"`
		} `json:"data"`
	} `json:"accounts"`
}

// hexToBytes converts a hex string to byte array
func hexToBytes(hexStr string) []byte {
	// Remove "0x" prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	s, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return s
}

// ConvertJSONToState converts a JSON pre_state to a Go State struct
func ConvertJSONToState(stateJSON StateJSON) (State, error) {
	var state State

	// Set the MostRecentBlockTimeslot
	state.MostRecentBlockTimeslot = stateJSON.Slot

	// Initialize empty service accounts map
	state.ServiceAccounts = make(serviceaccount.ServiceAccounts)

	// Initialize empty accumulation history and queue
	state.AccumulationHistory = AccumulationHistory{}
	state.AccumulationQueue = [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}

	// Process each account in the JSON
	for _, account := range stateJSON.Accounts {
		// Create a new service account
		serviceAccount := serviceaccount.ServiceAccount{
			Balance:                        types.Balance(account.Data.Service.Balance),
			MinimumGasForAccumulate:        types.GasValue(account.Data.Service.MinItemGas),
			MinimumGasForOnTransfer:        types.GasValue(account.Data.Service.MinMemoGas),
			PreimageLookup:                 make(map[[32]byte][]byte),
			PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
		}

		// Set code hash
		codeHashBytes := hexToBytes(account.Data.Service.CodeHash)
		copy(serviceAccount.CodeHash[:], codeHashBytes)

		// Add preimages to the service account
		for _, preimage := range account.Data.Preimages {
			// Convert hash to byte array
			var hashArray [32]byte
			hashBytes := hexToBytes(preimage.Hash)
			copy(hashArray[:], hashBytes[:32])

			// Convert blob to bytes
			blobBytes := hexToBytes(preimage.Blob)

			// Add to service account
			serviceAccount.PreimageLookup[hashArray] = blobBytes
		}

		// Add the service account to the state
		state.ServiceAccounts[types.ServiceIndex(account.ID)] = &serviceAccount
	}

	// Initialize empty privileged services
	state.PrivilegedServices = types.PrivilegedServices{
		ManagerServiceIndex:             types.ServiceIndex(stateJSON.Privileges.Bless),
		AssignServiceIndex:              types.ServiceIndex(stateJSON.Privileges.Assign),
		DesignateServiceIndex:           types.ServiceIndex(stateJSON.Privileges.Designate),
		AlwaysAccumulateServicesWithGas: make(map[types.ServiceIndex]types.GasValue),
	}

	// Set up entropy accumulator from the stateJSON
	// The JSON only provides a single entropy value, but our State uses a [4][32]byte array
	entropyBytes := hexToBytes(stateJSON.Entropy)
	if len(entropyBytes) == 32 {
		// Copy the entropy value to all elements of our entropy accumulator
		copy(state.EntropyAccumulator[0][:], entropyBytes)
		copy(state.EntropyAccumulator[1][:], entropyBytes)
		copy(state.EntropyAccumulator[2][:], entropyBytes)
		copy(state.EntropyAccumulator[3][:], entropyBytes)
	}

	// TODO: Parse AlwaysAcc from stateJSON.Privileges.AlwaysAcc

	// Initialize empty arrays and slices for other fields
	state.AuthorizersPool = [constants.NumCores][][32]byte{}
	state.RecentBlocks = []RecentBlock{}
	state.SafroleBasicState = SafroleBasicState{}
	state.ValidatorKeysetsStaging = types.ValidatorKeysets{}
	state.ValidatorKeysetsActive = types.ValidatorKeysets{}
	state.ValidatorKeysetsPriorEpoch = types.ValidatorKeysets{}
	state.PendingReports = [constants.NumCores]*PendingReport{}
	state.AuthorizerQueue = [constants.NumCores][constants.AuthorizerQueueLength][32]byte{}
	state.Disputes = types.Disputes{}
	state.ValidatorStatistics = [2][constants.NumValidators]SingleValidatorStatistics{}

	return state, nil
}

// TestAccumulateWithTestVectors tests the accumulate functionality using test vectors
func TestAccumulateWithTestVectors(t *testing.T) {
	// Path to the test vector
	testVectorPath := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/accumulate/tiny/no_available_reports-1.json"

	// Load the test vector
	testVector, err := LoadTestVector(testVectorPath)
	if err != nil {
		t.Fatalf("Failed to load test vector: %v", err)
	}

	// Convert the generic testVector.PreState into your implementation's State type
	var preStateJSON StateJSON
	jsonData, _ := json.Marshal(testVector.PreState)
	err = json.Unmarshal(jsonData, &preStateJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal pre-state JSON: %v", err)
	}

	preState, err := ConvertJSONToState(preStateJSON)
	if err != nil {
		t.Fatalf("Failed to convert pre-state JSON to State: %v", err)
	}

	// Parse work reports from the test vector input
	var workReports []workreport.WorkReport
	if inputMap, ok := testVector.Input.(map[string]interface{}); ok {
		if reports, ok := inputMap["reports"].([]interface{}); ok {
			for _, r := range reports {
				reportMap, ok := r.(map[string]interface{})
				if !ok {
					continue
				}

				// Create a work report - you'll need to adapt this to your specific structure
				report := workreport.WorkReport{}

				// Example of parsing core_index
				if coreIdx, ok := reportMap["core_index"].(float64); ok {
					report.CoreIndex = types.CoreIndex(coreIdx)
				}

				// Example of parsing authorizer_hash
				if authHash, ok := reportMap["authorizer_hash"].(string); ok && strings.HasPrefix(authHash, "0x") {
					authBytes, _ := hex.DecodeString(authHash[2:])
					copy(report.AuthorizerHash[:], authBytes)
				}

				// Parse work package specification and other fields as needed
				// This is simplified - you'll need to adapt to your actual JSON structure

				workReports = append(workReports, report)
			}
		}
	}

	// Parse posterior timeslot from input
	posteriorTimeslot := types.Timeslot(0)
	if inputMap, ok := testVector.Input.(map[string]interface{}); ok {
		if slot, ok := inputMap["slot"].(float64); ok {
			posteriorTimeslot = types.Timeslot(slot)
		}
	}

	// Create a dummy header with the posterior timeslot for entropy calculation
	dummyHeader := header.Header{
		TimeSlot: posteriorTimeslot,
		// We need a VRF signature, but test vectors may not provide one.
		// For now, use an empty signature - in a real test you might need to extract this from the test vector
		VRFSignature: types.BandersnatchVRFSignature{},
	}

	// Compute posterior entropy accumulator
	posteriorEntropyAccumulator := computeEntropyAccumulator(
		dummyHeader,
		preState.MostRecentBlockTimeslot,
		preState.EntropyAccumulator,
	)

	// Call accumulateAndIntegrate with the parsed inputs
	accumulationStateComponents, _, _, _ := accumulateAndIntegrate(
		&preState,
		posteriorTimeslot,
		workReports,
		[]workreport.WorkReportWithWorkPackageHashes{}, // Empty for test vectors as discussed
		posteriorEntropyAccumulator,                    // Pass the computed posterior entropy accumulator
	)

	// Create the actual state object from scratch using only the computation results
	actualState := State{
		// Only include fields that should be compared and affected by accumulation
		ServiceAccounts:         accumulationStateComponents.ServiceAccounts,
		ValidatorKeysetsStaging: accumulationStateComponents.UpcomingValidatorKeysets,
		AuthorizerQueue:         accumulationStateComponents.AuthorizersQueue,
		PrivilegedServices:      accumulationStateComponents.PrivilegedServices,
		MostRecentBlockTimeslot: posteriorTimeslot,
	}

	// Convert post-state JSON to a Go state object for comparison (expected state)
	var postStateJSON StateJSON
	if postStateMap, ok := testVector.PostState.(map[string]interface{}); ok {
		postStateBytes, err := json.Marshal(postStateMap)
		if err != nil {
			t.Fatalf("Failed to marshal post-state: %v", err)
		}

		if err := json.Unmarshal(postStateBytes, &postStateJSON); err != nil {
			t.Fatalf("Failed to unmarshal post-state JSON: %v", err)
		}
	} else {
		t.Fatalf("Post-state is not a map")
	}

	expectedState, err := ConvertJSONToState(postStateJSON)
	if err != nil {
		t.Fatalf("Failed to convert post-state JSON to State: %v", err)
	}

	// Compare the expected and actual states
	compareStates(t, expectedState, actualState)
}

// compareStates compares relevant fields between two State objects and reports differences
func compareStates(t *testing.T, expected, actual State) {
	// 1. Compare service accounts
	for serviceIndex, expectedAccount := range expected.ServiceAccounts {
		actualAccount, exists := actual.ServiceAccounts[serviceIndex]
		if !exists {
			t.Errorf("Service account %d exists in expected state but not in actual state", serviceIndex)
			continue
		}

		// Compare account balance
		if actualAccount.Balance != expectedAccount.Balance {
			t.Errorf("Service %d balance mismatch: expected %d, got %d",
				serviceIndex, expectedAccount.Balance, actualAccount.Balance)
		}

		// Compare gas thresholds
		if actualAccount.MinimumGasForAccumulate != expectedAccount.MinimumGasForAccumulate {
			t.Errorf("Service %d MinimumGasForAccumulate mismatch: expected %d, got %d",
				serviceIndex, expectedAccount.MinimumGasForAccumulate, actualAccount.MinimumGasForAccumulate)
		}

		if actualAccount.MinimumGasForOnTransfer != expectedAccount.MinimumGasForOnTransfer {
			t.Errorf("Service %d MinimumGasForOnTransfer mismatch: expected %d, got %d",
				serviceIndex, expectedAccount.MinimumGasForOnTransfer, actualAccount.MinimumGasForOnTransfer)
		}

		// Compare code hash
		if actualAccount.CodeHash != expectedAccount.CodeHash {
			t.Errorf("Service %d code hash mismatch: expected %x, got %x",
				serviceIndex, expectedAccount.CodeHash, actualAccount.CodeHash)
		}

		// Compare preimage lookup sizes
		if len(actualAccount.PreimageLookup) != len(expectedAccount.PreimageLookup) {
			t.Errorf("Service %d preimage lookup size mismatch: expected %d, got %d",
				serviceIndex, len(expectedAccount.PreimageLookup), len(actualAccount.PreimageLookup))
		}
	}

	// Check for accounts in actual that aren't in expected
	for serviceIndex := range actual.ServiceAccounts {
		if _, exists := expected.ServiceAccounts[serviceIndex]; !exists {
			t.Errorf("Service account %d exists in actual state but not in expected state", serviceIndex)
		}
	}

	// 2. Compare MostRecentBlockTimeslot
	if expected.MostRecentBlockTimeslot != actual.MostRecentBlockTimeslot {
		t.Errorf("MostRecentBlockTimeslot mismatch: expected %d, got %d",
			expected.MostRecentBlockTimeslot, actual.MostRecentBlockTimeslot)
	}

	// 3. Compare ValidatorKeysetsStaging
	// For a simple comparison, just check if they have the same number of elements
	if len(expected.ValidatorKeysetsStaging) != len(actual.ValidatorKeysetsStaging) {
		t.Errorf("ValidatorKeysetsStaging length mismatch: expected %d, got %d",
			len(expected.ValidatorKeysetsStaging), len(actual.ValidatorKeysetsStaging))
	}
	// For a more detailed comparison, you'd need to compare individual validators

	// 4. Compare AuthorizerQueue
	// For simplicity, just compare the first element of each core's queue
	for coreIdx := range expected.AuthorizerQueue {
		if len(actual.AuthorizerQueue) <= coreIdx {
			continue
		}

		// Compare first element if it exists
		if len(expected.AuthorizerQueue[coreIdx]) > 0 && len(actual.AuthorizerQueue[coreIdx]) > 0 {
			if expected.AuthorizerQueue[coreIdx][0] != actual.AuthorizerQueue[coreIdx][0] {
				t.Errorf("AuthorizerQueue mismatch for core %d", coreIdx)
			}
		}
	}

	// 5. Compare privileges
	if expected.PrivilegedServices.ManagerServiceIndex != actual.PrivilegedServices.ManagerServiceIndex {
		t.Errorf("Manager service index mismatch: expected %d, got %d",
			expected.PrivilegedServices.ManagerServiceIndex, actual.PrivilegedServices.ManagerServiceIndex)
	}

	if expected.PrivilegedServices.AssignServiceIndex != actual.PrivilegedServices.AssignServiceIndex {
		t.Errorf("Assign service index mismatch: expected %d, got %d",
			expected.PrivilegedServices.AssignServiceIndex, actual.PrivilegedServices.AssignServiceIndex)
	}

	if expected.PrivilegedServices.DesignateServiceIndex != actual.PrivilegedServices.DesignateServiceIndex {
		t.Errorf("Designate service index mismatch: expected %d, got %d",
			expected.PrivilegedServices.DesignateServiceIndex, actual.PrivilegedServices.DesignateServiceIndex)
	}
}
