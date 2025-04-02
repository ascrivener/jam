package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	"github.com/google/go-cmp/cmp"
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
	Slot       types.Timeslot `json:"slot"`
	Entropy    string         `json:"entropy"`
	ReadyQueue [][]struct {
		Report       WorkReportJSON `json:"report"`
		Dependencies []string       `json:"dependencies"`
	} `json:"ready_queue"`
	Accumulated [][]string `json:"accumulated"`
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

type WorkReportJSON struct {
	PackageSpec struct {
		Hash         string `json:"hash"`
		Length       int    `json:"length"`
		ErasureRoot  string `json:"erasure_root"`
		ExportsRoot  string `json:"exports_root"`
		ExportsCount int    `json:"exports_count"`
	} `json:"package_spec"`
	Context struct {
		Anchor           string   `json:"anchor"`
		StateRoot        string   `json:"state_root"`
		BeefyRoot        string   `json:"beefy_root"`
		LookupAnchor     string   `json:"lookup_anchor"`
		LookupAnchorSlot int      `json:"lookup_anchor_slot"`
		Prerequisites    []string `json:"prerequisites"`
	} `json:"context"`
	CoreIndex         int        `json:"core_index"`
	AuthorizerHash    string     `json:"authorizer_hash"`
	AuthOutput        string     `json:"auth_output"`
	SegmentRootLookup []struct{} `json:"segment_root_lookup"`
	Results           []struct {
		ServiceID     int    `json:"service_id"`
		CodeHash      string `json:"code_hash"`
		PayloadHash   string `json:"payload_hash"`
		AccumulateGas int    `json:"accumulate_gas"`
		Result        struct {
			OK string `json:"ok"`
		} `json:"result"`
		RefineLoad struct {
			GasUsed        int `json:"gas_used"`
			Imports        int `json:"imports"`
			ExtrinsicCount int `json:"extrinsic_count"`
			ExtrinsicSize  int `json:"extrinsic_size"`
			Exports        int `json:"exports"`
		} `json:"refine_load"`
	} `json:"results"`
	AuthGasUsed int `json:"auth_gas_used"`
}

func hexToHash(hexStr string) [32]byte {
	var hashArray [32]byte
	hashBytes := hexToBytes(hexStr)
	copy(hashArray[:], hashBytes[:32])
	return hashArray
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

	// Initialize empty accumulation queue with empty slices (not nil)
	state.AccumulationQueue = [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes{}

	for idx, r := range stateJSON.ReadyQueue {
		w := make([]workreport.WorkReportWithWorkPackageHashes, 0)
		for _, workReportWithWorkPackageHashesJSON := range r {
			workPackageHashes := make(map[[32]byte]struct{})
			for _, dep := range workReportWithWorkPackageHashesJSON.Dependencies {
				workPackageHashes[hexToHash(dep)] = struct{}{}
			}
			w = append(w, workreport.WorkReportWithWorkPackageHashes{
				WorkReport:        ConvertJSONToReport(workReportWithWorkPackageHashesJSON.Report),
				WorkPackageHashes: workPackageHashes,
			})
		}
		state.AccumulationQueue[idx] = w
	}

	// Initialize empty accumulation history with empty maps (not nil)
	state.AccumulationHistory = [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}{}

	for idx, accumulatedWorkPackagesHashesForTimeslot := range stateJSON.Accumulated {
		workPackageHashes := make(map[[32]byte]struct{})
		for _, accumulatedWorkPackageHash := range accumulatedWorkPackagesHashesForTimeslot {
			workPackageHashes[hexToHash(accumulatedWorkPackageHash)] = struct{}{}
		}
		state.AccumulationHistory[idx] = workPackageHashes
	}

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

func ConvertJSONToReport(reportJSON WorkReportJSON) workreport.WorkReport {
	var workReport workreport.WorkReport

	workReport.WorkPackageSpecification = workreport.AvailabilitySpecification{
		WorkPackageHash:  hexToHash(reportJSON.PackageSpec.Hash),
		WorkBundleLength: types.BlobLength(reportJSON.PackageSpec.Length),
		ErasureRoot:      hexToHash(reportJSON.PackageSpec.ErasureRoot),
		SegmentRoot:      hexToHash(reportJSON.PackageSpec.ExportsRoot),
		SegmentCount:     uint64(reportJSON.PackageSpec.ExportsCount),
	}

	prerequisiteWorkPackageHashes := make(map[[32]byte]struct{})

	for _, prerequisite := range reportJSON.Context.Prerequisites {
		prerequisiteWorkPackageHashes[hexToHash(prerequisite)] = struct{}{}
	}

	workReport.RefinementContext = workreport.RefinementContext{
		AnchorHeaderHash:              hexToHash(reportJSON.Context.Anchor),
		PosteriorStateRoot:            hexToHash(reportJSON.Context.StateRoot),
		PosteriorBEEFYRoot:            hexToHash(reportJSON.Context.BeefyRoot),
		LookupAnchorHeaderHash:        hexToHash(reportJSON.Context.LookupAnchor),
		Timeslot:                      types.Timeslot(reportJSON.Context.LookupAnchorSlot),
		PrerequisiteWorkPackageHashes: make(map[[32]byte]struct{}),
	}

	workReport.CoreIndex = types.CoreIndex(reportJSON.CoreIndex)

	workReport.AuthorizerHash = hexToHash(reportJSON.AuthorizerHash)

	workReport.Output = hexToBytes(reportJSON.AuthOutput)

	workReport.SegmentRootLookup = make(map[[32]byte][32]byte)

	workReport.WorkResults = make([]workreport.WorkResult, 0)

	for _, result := range reportJSON.Results {
		workResult := workreport.WorkResult{
			ServiceIndex:           types.ServiceIndex(result.ServiceID),
			ServiceCodeHash:        hexToHash(result.CodeHash),
			PayloadHash:            hexToHash(result.PayloadHash),
			GasPrioritizationRatio: types.GasValue(result.AccumulateGas),
			WorkOutput:             types.NewExecutionExitReasonBlob(hexToBytes(result.Result.OK)),
		}

		workReport.WorkResults = append(workReport.WorkResults, workResult)
	}

	return workReport
}

// TestAccumulateWithTestVectors tests the accumulate functionality using test vectors
func TestAccumulateWithTestVectors(t *testing.T) {
	// Base directory containing the test vectors
	testVectorDir := "/Users/adamscrivener/Projects/Jam/jam-test-vectors/accumulate"

	// Define a list of subdirectories and their test files to run
	testCases := []struct {
		subdir   string
		filename string
	}{
		{"tiny", "no_available_reports-1.json"},
		// {"tiny", "process_one_immediate_report-1.json"},
		// {"tiny", "accumulate_ready_queued_reports-1.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-1.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-2.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-3.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-4.json"},
		// {"tiny", "enqueue_and_unlock_chain_wraps-5.json"},
		// {"tiny", "one_available_report-1.json"},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		testName := tc.subdir + "/" + tc.filename
		t.Run(testName, func(t *testing.T) {
			// Full path to the test vector
			testVectorPath := filepath.Join(testVectorDir, tc.subdir, tc.filename)

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

			// Parse posterior timeslot from input
			posteriorTimeslot := types.Timeslot(0)
			if inputMap, ok := testVector.Input.(map[string]interface{}); ok {
				if posteriorTimeslotFloat, ok := inputMap["slot"].(float64); ok {
					posteriorTimeslot = types.Timeslot(posteriorTimeslotFloat)
				}
			}

			// Parse work reports from input
			var workReports []workreport.WorkReport
			if inputMap, ok := testVector.Input.(map[string]interface{}); ok {
				if reportsArray, ok := inputMap["reports"].([]interface{}); ok {
					// Parse each work report
					for _, reportInterface := range reportsArray {
						// Convert report to JSON and then to WorkReport
						var reportJSON WorkReportJSON
						jsonData, _ := json.Marshal(reportInterface)
						err = json.Unmarshal(jsonData, &reportJSON)
						if err != nil {
							t.Fatalf("Failed to unmarshal report JSON: %v", err)
						}

						report := ConvertJSONToReport(reportJSON)
						workReports = append(workReports, report)
					}
				}
			}

			// Compute a posterior entropy accumulator
			// For test vectors, we use a dummy header to compute it
			// dummyHeader := header.Header{
			// 	ParentHash: [32]byte{},
			// 	TimeSlot:   posteriorTimeslot,
			// }

			// posteriorEntropyAccumulator := computeEntropyAccumulator(
			// 	dummyHeader,
			// 	preState.MostRecentBlockTimeslot,
			// 	preState.EntropyAccumulator,
			// )

			// Call accumulateAndIntegrate with the parsed inputs
			accumulationStateComponents, _, posteriorAccumulationQueue, posteriorAccumulationHistory := accumulateAndIntegrate(
				&preState,
				posteriorTimeslot,
				workReports,
				[]workreport.WorkReportWithWorkPackageHashes{}, // Empty for test vectors as discussed
				preState.EntropyAccumulator,                    // Pass the computed posterior entropy accumulator
			)

			// Create the actual state object from scratch using only the computation results
			actualState := State{
				// Only include fields that should be compared and affected by accumulation
				ServiceAccounts:            accumulationStateComponents.ServiceAccounts,
				ValidatorKeysetsStaging:    accumulationStateComponents.UpcomingValidatorKeysets,
				PrivilegedServices:         accumulationStateComponents.PrivilegedServices,
				MostRecentBlockTimeslot:    posteriorTimeslot,
				AccumulationQueue:          posteriorAccumulationQueue,
				AccumulationHistory:        posteriorAccumulationHistory,
				AuthorizersPool:            [constants.NumCores][][32]byte{},
				RecentBlocks:               []RecentBlock{},
				SafroleBasicState:          SafroleBasicState{},
				EntropyAccumulator:         preState.EntropyAccumulator,
				ValidatorKeysetsActive:     types.ValidatorKeysets{},
				ValidatorKeysetsPriorEpoch: types.ValidatorKeysets{},
				PendingReports:             [constants.NumCores]*PendingReport{},
				AuthorizerQueue:            [constants.NumCores][constants.AuthorizerQueueLength][32]byte{},
				Disputes:                   types.Disputes{},
				ValidatorStatistics:        [2][constants.NumValidators]SingleValidatorStatistics{},
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
		})
	}
}

// compareStates compares two State objects and reports differences
func compareStates(t *testing.T, expected, actual State) {
	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("States don't match (-expected +actual):\n%s", diff)
	}
}

// compareReports compares two WorkReport objects and reports differences
func compareReports(t *testing.T, expected, actual workreport.WorkReport) {
	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("WorkReports don't match (-expected +actual):\n%s", diff)
	}
}
