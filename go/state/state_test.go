package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

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

// PreStateJSON represents the structure of the pre_state field in test vectors
type PreStateJSON struct {
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
		ID   int         `json:"id"`
		Data interface{} `json:"data"`
	} `json:"accounts"`
}

// hexToBytes converts a hex string to byte array
func hexToBytes(hexStr string) ([]byte, error) {
	// Remove "0x" prefix if present
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}

// ConvertJSONToState converts a JSON pre_state to a Go State struct
func ConvertJSONToState(preStateJSON PreStateJSON) (State, error) {
	var state State

	// Set the MostRecentBlockTimeslot
	state.MostRecentBlockTimeslot = preStateJSON.Slot

	// Convert entropy string to EntropyAccumulator
	entropyBytes, err := hexToBytes(preStateJSON.Entropy)
	if err != nil {
		return state, fmt.Errorf("failed to convert entropy hex string: %w", err)
	}

	// Create entropy array and populate EntropyAccumulator
	var entropyArray [32]byte
	copy(entropyArray[:], entropyBytes)

	// For simplicity, we'll set all 4 elements of EntropyAccumulator to the same value
	// In a more complete implementation, you'd need to parse these correctly from the test vector
	for i := 0; i < 4; i++ {
		state.EntropyAccumulator[i] = entropyArray
	}

	// Initialize empty accumulation queue and history
	state.AccumulationQueue = [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}
	state.AccumulationHistory = AccumulationHistory{}
	for i := 0; i < constants.NumTimeslotsPerEpoch; i++ {
		state.AccumulationHistory[i] = make(map[[32]byte]struct{})
	}

	// Initialize service accounts
	state.ServiceAccounts = serviceaccount.ServiceAccounts{}

	// Process accounts from the JSON
	for _, account := range preStateJSON.Accounts {
		// Try to convert the Data field to a map
		accountData, ok := account.Data.(map[string]interface{})
		if !ok {
			return state, fmt.Errorf("failed to parse account data for ID %d", account.ID)
		}

		// Extract service data
		serviceData, ok := accountData["service"].(map[string]interface{})
		if !ok {
			return state, fmt.Errorf("failed to parse service data for account ID %d", account.ID)
		}

		// Create a new service account
		serviceAccount := &serviceaccount.ServiceAccount{
			StorageDictionary:              make(map[[32]byte][]byte),
			PreimageLookup:                 make(map[[32]byte][]byte),
			PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
		}

		// Parse code hash
		codeHashStr, ok := serviceData["code_hash"].(string)
		if ok {
			codeHashBytes, err := hexToBytes(codeHashStr)
			if err != nil {
				return state, fmt.Errorf("failed to parse code_hash for account ID %d: %w", account.ID, err)
			}
			copy(serviceAccount.CodeHash[:], codeHashBytes)
		}

		// Parse balance
		if balance, ok := serviceData["balance"].(float64); ok {
			serviceAccount.Balance = types.Balance(balance)
		}

		// Parse minimum gas values
		if minItemGas, ok := serviceData["min_item_gas"].(float64); ok {
			serviceAccount.MinimumGasForAccumulate = types.GasValue(minItemGas)
		}

		if minMemoGas, ok := serviceData["min_memo_gas"].(float64); ok {
			serviceAccount.MinimumGasForOnTransfer = types.GasValue(minMemoGas)
		}

		// Process preimages if available
		if preimages, ok := accountData["preimages"].([]interface{}); ok {
			for _, preimage := range preimages {
				preimageMap, ok := preimage.(map[string]interface{})
				if !ok {
					continue
				}

				hashStr, ok := preimageMap["hash"].(string)
				if !ok {
					continue
				}

				blobStr, ok := preimageMap["blob"].(string)
				if !ok {
					continue
				}

				hashBytes, err := hexToBytes(hashStr)
				if err != nil {
					return state, fmt.Errorf("failed to parse preimage hash: %w", err)
				}

				blobBytes, err := hexToBytes(blobStr)
				if err != nil {
					return state, fmt.Errorf("failed to parse preimage blob: %w", err)
				}

				var hashArray [32]byte
				copy(hashArray[:], hashBytes)

				serviceAccount.PreimageLookup[hashArray] = blobBytes
			}
		}

		// Add the service account to the state
		state.ServiceAccounts[types.ServiceIndex(account.ID)] = serviceAccount
	}

	// Initialize empty privileged services
	state.PrivilegedServices = types.PrivilegedServices{
		ManagerServiceIndex:             types.ServiceIndex(preStateJSON.Privileges.Bless),
		AssignServiceIndex:              types.ServiceIndex(preStateJSON.Privileges.Assign),
		DesignateServiceIndex:           types.ServiceIndex(preStateJSON.Privileges.Designate),
		AlwaysAccumulateServicesWithGas: make(map[types.ServiceIndex]types.GasValue),
	}

	// TODO: Parse AlwaysAcc from preStateJSON.Privileges.AlwaysAcc

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

	// TODO: For a complete implementation, parse all fields from the test vector JSON
	// This would require understanding the exact format of the JSON and how it maps to your Go types

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
	var preStateJSON PreStateJSON
	jsonData, _ := json.Marshal(testVector.PreState)
	err = json.Unmarshal(jsonData, &preStateJSON)
	if err != nil {
		t.Fatalf("Failed to unmarshal pre-state JSON: %v", err)
	}
	state, err := ConvertJSONToState(preStateJSON)
	if err != nil {
		t.Fatalf("Failed to convert pre-state JSON to State: %v", err)
	}
	fmt.Println(state)

	// TODO: Convert the testVector.Input into the appropriate input type

	// TODO: Call your state transition function with the converted inputs
	// Example: result := StateTransitionFunction(preState, input)

	// TODO: Compare the actual result with the expected output
	// assert.Equal(t, expectedOutput, actualOutput)
}
