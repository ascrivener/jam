package state

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/validatorstatistics"
	"github.com/ascrivener/jam/workreport"
	"github.com/cockroachdb/pebble"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                                               // α
	RecentBlocks               []RecentBlock                                                                // β
	SafroleBasicState          SafroleBasicState                                                            // γ
	ServiceAccounts            serviceaccount.ServiceAccounts                                               // δ
	EntropyAccumulator         [4][32]byte                                                                  // η
	ValidatorKeysetsStaging    types.ValidatorKeysets                                                       // ι
	ValidatorKeysetsActive     types.ValidatorKeysets                                                       // κ
	ValidatorKeysetsPriorEpoch types.ValidatorKeysets                                                       // λ
	PendingReports             [constants.NumCores]*PendingReport                                           // ρ
	MostRecentBlockTimeslot    types.Timeslot                                                               // τ
	AuthorizerQueue            [constants.NumCores][constants.AuthorizerQueueLength][32]byte                // φ
	PrivilegedServices         types.PrivilegedServices                                                     // χ
	Disputes                   types.Disputes                                                               // ψ
	ValidatorStatistics        validatorstatistics.ValidatorStatistics                                      // π
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes // ϑ
	AccumulationHistory        AccumulationHistory                                                          // ξ
}

type PendingReport struct {
	WorkReport workreport.WorkReport
	Timeslot   types.Timeslot
}

type AccumulationHistory [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{}

func (a AccumulationHistory) ToUnionSet() map[[32]byte]struct{} {
	set := make(map[[32]byte]struct{})
	for _, accumulationSet := range a {
		for key := range accumulationSet {
			set[key] = struct{}{}
		}
	}
	return set
}

// ShiftLeft shifts all elements so that a[i] = a[i+1] and fills the last element with the provided map.
// If newLast is nil, an empty map will be created.
func (a *AccumulationHistory) ShiftLeft(newLast map[[32]byte]struct{}) {
	for i := range (*a)[:len(*a)-1] {
		(*a)[i] = (*a)[i+1]
	}

	// Set the last element to the provided map or create an empty one
	if newLast == nil {
		(*a)[len(*a)-1] = make(map[[32]byte]struct{})
	} else {
		(*a)[len(*a)-1] = newLast
	}
}

func MerklizeState(leaves map[[31]byte][]byte) [32]byte {
	bitSeqKeyMap := make(map[bitsequence.BitSeqKey]merklizer.StateKV)
	for k, v := range leaves {
		bitSeqKeyMap[bitsequence.FromBytes(k[:]).Key()] = merklizer.StateKV{
			OriginalKey: k,
			Value:       v,
		}
	}

	return merklizer.MerklizeStateRecurser(bitSeqKeyMap)
}

func GetState(repo staterepository.PebbleStateRepository) (State, error) {
	state := State{
		ServiceAccounts: make(map[types.ServiceIndex]*serviceaccount.ServiceAccount),
	}

	// Deserialize static state components
	components := []struct {
		key    [31]byte
		target interface{}
	}{
		{staterepository.MakeComponentKey(1), &state.AuthorizersPool},
		{staterepository.MakeComponentKey(2), &state.AuthorizerQueue},
		{staterepository.MakeComponentKey(3), &state.RecentBlocks},
		{staterepository.MakeComponentKey(4), &state.SafroleBasicState},
		{staterepository.MakeComponentKey(5), &state.Disputes},
		{staterepository.MakeComponentKey(6), &state.EntropyAccumulator},
		{staterepository.MakeComponentKey(7), &state.ValidatorKeysetsStaging},
		{staterepository.MakeComponentKey(8), &state.ValidatorKeysetsActive},
		{staterepository.MakeComponentKey(9), &state.ValidatorKeysetsPriorEpoch},
		{staterepository.MakeComponentKey(10), &state.PendingReports},
		{staterepository.MakeComponentKey(11), &state.MostRecentBlockTimeslot},
		{staterepository.MakeComponentKey(12), &state.PrivilegedServices},
		{staterepository.MakeComponentKey(13), &state.ValidatorStatistics},
		{staterepository.MakeComponentKey(14), &state.AccumulationQueue},
		{staterepository.MakeComponentKey(15), &state.AccumulationHistory},
	}

	// Deserialize each basic component
	for _, component := range components {
		value, closer, err := repo.Get(component.key[:])
		if err == pebble.ErrNotFound {
			// If we're starting fresh, just continue with default values
			continue
		} else if err != nil {
			return State{}, fmt.Errorf("failed to get component: %w", err)
		}

		// Make a copy of the value since it's only valid until closer.Close()
		dataCopy := make([]byte, len(value))
		copy(dataCopy, value)
		closer.Close()

		if err := serializer.Deserialize(dataCopy, component.target); err != nil {
			return State{}, fmt.Errorf("failed to deserialize component: %w", err)
		}
	}

	// Load service accounts (just metadata, not storage)
	if err := state.loadServiceAccounts(repo); err != nil {
		return State{}, err
	}

	return state, nil
}

// loadServiceAccounts loads all service account metadata (not storage)
func (state *State) loadServiceAccounts(repo staterepository.PebbleStateRepository) error {
	// Service accounts have keys starting with 255
	serviceAccountPrefix := []byte{255}
	iter, err := repo.NewIter(&pebble.IterOptions{
		LowerBound: serviceAccountPrefix,
		UpperBound: append(append([]byte{}, serviceAccountPrefix...), 0xFF),
	})
	if err != nil {
		return err
	}
	defer iter.Close()

	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()

		// Check the pattern [255, n_0, 0, n_1, 0, n_2, 0, n_3, 0, 0...]
		// Only proceed if the zero bytes are in the right places
		if key[0] != 255 || key[2] != 0 || key[4] != 0 || key[6] != 0 || key[8] != 0 {
			continue
		}

		// Check that all remaining bytes are zeros
		validKey := true
		for i := 9; i < len(key); i++ {
			if key[i] != 0 {
				validKey = false
				break
			}
		}

		if !validKey {
			continue
		}

		// Extract service index from key using little endian [n0,n1,n2,n3]
		serviceIndex := uint64(key[1]) |
			uint64(key[3])<<8 |
			uint64(key[5])<<16 |
			uint64(key[7])<<24

		// Copy the value since it's only valid until iter is closed
		value := make([]byte, len(iter.Value()))
		copy(value, iter.Value())

		var serviceAccountData struct {
			CodeHash                 [32]byte       // c
			Balance                  types.Balance  // b
			MinimumGasForAccumulate  types.GasValue // g
			MinimumGasForOnTransfer  types.GasValue // m
			TotalOctetsUsedInStorage uint64         // o
			TotalItemsUsedInStorage  uint32         // i
		}

		// Deserialize account
		if err := serializer.Deserialize(value, &serviceAccountData); err != nil {
			return fmt.Errorf("failed to deserialize service account %d: %w", serviceIndex, err)
		}

		// Add to state
		state.ServiceAccounts[types.ServiceIndex(serviceIndex)] = &serviceaccount.ServiceAccount{
			ServiceIndex:             types.ServiceIndex(serviceIndex),
			CodeHash:                 serviceAccountData.CodeHash,
			Balance:                  serviceAccountData.Balance,
			MinimumGasForAccumulate:  serviceAccountData.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:  serviceAccountData.MinimumGasForOnTransfer,
			TotalOctetsUsedInStorage: serviceAccountData.TotalOctetsUsedInStorage,
			TotalItemsUsedInStorage:  serviceAccountData.TotalItemsUsedInStorage,
		}
	}

	return nil
}

// SetState stores the entire blockchain state
func (state *State) Set(repo staterepository.PebbleStateRepository) error {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Store static state components
	components := []struct {
		key    [31]byte
		source interface{}
	}{
		{staterepository.MakeComponentKey(1), state.AuthorizersPool},
		{staterepository.MakeComponentKey(2), state.AuthorizerQueue},
		{staterepository.MakeComponentKey(3), state.RecentBlocks},
		{staterepository.MakeComponentKey(4), state.SafroleBasicState},
		{staterepository.MakeComponentKey(5), state.Disputes},
		{staterepository.MakeComponentKey(6), state.EntropyAccumulator},
		{staterepository.MakeComponentKey(7), state.ValidatorKeysetsStaging},
		{staterepository.MakeComponentKey(8), state.ValidatorKeysetsActive},
		{staterepository.MakeComponentKey(9), state.ValidatorKeysetsPriorEpoch},
		{staterepository.MakeComponentKey(10), state.PendingReports},
		{staterepository.MakeComponentKey(11), state.MostRecentBlockTimeslot},
		{staterepository.MakeComponentKey(12), state.PrivilegedServices},
		{staterepository.MakeComponentKey(13), state.ValidatorStatistics},
		{staterepository.MakeComponentKey(14), state.AccumulationQueue},
		{staterepository.MakeComponentKey(15), state.AccumulationHistory},
	}

	// Serialize and store each basic component
	for _, component := range components {
		data := serializer.Serialize(component.source)
		if err := batch.Set(component.key[:], data, nil); err != nil {
			return fmt.Errorf("failed to store component: %w", err)
		}
	}

	// Store service accounts
	for serviceIndex, account := range state.ServiceAccounts {
		key := staterepository.StateKeyConstructor(255, serviceIndex)
		var serviceAccountData = struct {
			CodeHash                 [32]byte       // c
			Balance                  types.Balance  // b
			MinimumGasForAccumulate  types.GasValue // g
			MinimumGasForOnTransfer  types.GasValue // m
			TotalOctetsUsedInStorage uint64         // o
			TotalItemsUsedInStorage  uint32         // i
		}{
			CodeHash:                 account.CodeHash,
			Balance:                  account.Balance,
			MinimumGasForAccumulate:  account.MinimumGasForAccumulate,
			MinimumGasForOnTransfer:  account.MinimumGasForOnTransfer,
			TotalOctetsUsedInStorage: account.TotalOctetsUsedInStorage,
			TotalItemsUsedInStorage:  account.TotalItemsUsedInStorage,
		}
		data := serializer.Serialize(serviceAccountData)
		if err := batch.Set(key[:], data, nil); err != nil {
			return fmt.Errorf("failed to store service account %d: %w", serviceIndex, err)
		}
	}

	// If we created our own batch, commit it
	if ownBatch {
		return batch.Commit(pebble.Sync)
	}

	return nil
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

// hexToHashMust panics if the hash cannot be converted
func hexToHashMust(hexStr string) [32]byte {
	hash, err := hexToHash(hexStr)
	if err != nil {
		panic(fmt.Sprintf("invalid hash: %s", err))
	}
	return hash
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
type WorkReport struct {
	PackageSpec       WorkPackageSpec   `json:"package_spec"`
	Context           RefineContext     `json:"context"`
	CoreIndex         uint64            `json:"core_index"`
	AuthorizerHash    string            `json:"authorizer_hash"`
	AuthOutput        string            `json:"auth_output"`
	SegmentRootLookup SegmentRootLookup `json:"segment_root_lookup"`
	Results           []WorkDigest      `json:"results"`
	AuthGasUsed       uint64            `json:"auth_gas_used"`
}

// convertJSONReportToImplReport converts a workreport from the JSON to the implementation's WorkReport type
func convertJSONReportToImplReport(workReportJSON WorkReport) workreport.WorkReport {
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
