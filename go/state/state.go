package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/pvm"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/validatorstatistics"
	"github.com/ascrivener/jam/workreport"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                                               // α
	RecentActivity             RecentActivity                                                               // β
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
	AccumulationOutputLog      []pvm.BEEFYCommitment                                                        // θ
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

func MerklizeState(s State) [32]byte {
	serializedState := StateSerializer(s)
	bitSeqKeyMap := make(map[bitsequence.BitSeqKey]merklizer.StateKV)
	for k, v := range serializedState {
		bitSeqKeyMap[bitsequence.FromBytes(k[:]).Key()] = merklizer.StateKV{
			OriginalKey: k,
			Value:       v,
		}
	}

	return merklizer.MerklizeStateRecurser(bitSeqKeyMap)
}

// JSON representation of SafroleBasicState
type Gamma struct {
	GammaK []ValidatorKeysetJSON `json:"gamma_k"`
	GammaZ string                `json:"gamma_z"`
	GammaS struct {
		Keys []string `json:"keys"`
	} `json:"gamma_s"`
	GammaA []string `json:"gamma_a"`
}

// Disputes JSON structure
type DisputesJSON struct {
	Good      []json.RawMessage `json:"good"`
	Bad       []json.RawMessage `json:"bad"`
	Wonky     []json.RawMessage `json:"wonky"`
	Offenders []json.RawMessage `json:"offenders"`
}

type ValidatorKeysetJSON struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
	Bls          string `json:"bls"`
	Metadata     string `json:"metadata"`
}

// ValidatorKeysetJSONToKeyset converts a ValidatorKeysetJSON to a types.ValidatorKeyset
func ValidatorKeysetJSONToKeyset(keysetJSON ValidatorKeysetJSON) types.ValidatorKeyset {
	// Convert each component to bytes
	bandersnatchBytes := hexToHashMust(keysetJSON.Bandersnatch)
	ed25519Bytes := hexToHashMust(keysetJSON.Ed25519)
	blsBytes := hexToBytesMust(keysetJSON.Bls)
	metadataBytes := hexToBytesMust(keysetJSON.Metadata)

	// Create a ValidatorKeyset by concatenating components
	var keyset types.ValidatorKeyset

	// Copy bytes into the keyset
	copy(keyset[:32], bandersnatchBytes[:])
	copy(keyset[32:64], ed25519Bytes[:])
	copy(keyset[64:208], blsBytes)
	copy(keyset[208:336], metadataBytes)

	return keyset
}

// PrivilegedServicesJSON represents the JSON structure of privileged services
type PrivilegedServicesJSON struct {
	ChiM int         `json:"chi_m"` // ManagerServiceIndex
	ChiA int         `json:"chi_a"` // AssignServiceIndex
	ChiV int         `json:"chi_v"` // DesignateServiceIndex
	ChiG interface{} `json:"chi_g"` // AlwaysAccumulateServicesWithGas - can be null
}

// ValidatorStatEntry represents a single validator statistics entry in JSON
type ValidatorStatEntry struct {
	Blocks        int `json:"blocks"`
	Tickets       int `json:"tickets"`
	PreImages     int `json:"pre_images"`
	PreImagesSize int `json:"pre_images_size"`
	Guarantees    int `json:"guarantees"`
	Assurances    int `json:"assurances"`
}

// CoreStatEntry represents a single core statistics entry in JSON
type CoreStatEntry struct {
	GasUsed        int `json:"gas_used"`
	Imports        int `json:"imports"`
	ExtrinsicCount int `json:"extrinsic_count"`
	ExtrinsicSize  int `json:"extrinsic_size"`
	Exports        int `json:"exports"`
	BundleSize     int `json:"bundle_size"`
	DaLoad         int `json:"da_load"`
	Popularity     int `json:"popularity"`
}

// ServiceStatRecord represents a service statistics record
type ServiceStatRecord struct {
	ProvidedCount      int `json:"provided_count"`
	ProvidedSize       int `json:"provided_size"`
	RefinementCount    int `json:"refinement_count"`
	RefinementGasUsed  int `json:"refinement_gas_used"`
	Imports            int `json:"imports"`
	Exports            int `json:"exports"`
	ExtrinsicSize      int `json:"extrinsic_size"`
	ExtrinsicCount     int `json:"extrinsic_count"`
	AccumulateCount    int `json:"accumulate_count"`
	AccumulateGasUsed  int `json:"accumulate_gas_used"`
	OnTransfersCount   int `json:"on_transfers_count"`
	OnTransfersGasUsed int `json:"on_transfers_gas_used"`
}

// ServiceStat represents a service statistics entry
type ServiceStat struct {
	ID     int               `json:"id"`
	Record ServiceStatRecord `json:"record"`
}

// ValidatorStatisticsJSON represents the JSON structure of validator statistics
type ValidatorStatisticsJSON struct {
	ValsCurrent []ValidatorStatEntry `json:"vals_current"`
	ValsLast    []ValidatorStatEntry `json:"vals_last"`
	Cores       []CoreStatEntry      `json:"cores"`
	Services    []ServiceStat        `json:"services"`
}

// ServiceDataJSON represents the service data in an account
type ServiceDataJSON struct {
	CodeHash   string `json:"code_hash"` // Hex string with 0x prefix
	Balance    int64  `json:"balance"`
	MinItemGas int    `json:"min_item_gas"`
	MinMemoGas int    `json:"min_memo_gas"`
	Bytes      int    `json:"bytes"`
	Items      int    `json:"items"`
}

// PreimageJSON represents a preimage in an account
type PreimageJSON struct {
	Hash string `json:"hash"` // Hex string with 0x prefix
	Blob string `json:"blob"` // Hex string with 0x prefix
}

// KeyInfoJSON represents key information in lookup_meta
type KeyInfoJSON struct {
	Hash   string `json:"hash"` // Hex string with 0x prefix
	Length int    `json:"length"`
}

// LookupMetaEntryJSON represents a lookup_meta entry
type LookupMetaEntryJSON struct {
	Key   KeyInfoJSON `json:"key"`
	Value []int       `json:"value"`
}

// AccountDataJSON represents the data field in an account
type AccountDataJSON struct {
	Service    ServiceDataJSON       `json:"service"`
	Preimages  []PreimageJSON        `json:"preimages"`
	LookupMeta []LookupMetaEntryJSON `json:"lookup_meta"`
	Storage    map[string]string     `json:"storage"` // Can be null
}

// AccountJSON represents a single account
type AccountJSON struct {
	ID   int             `json:"id"`
	Data AccountDataJSON `json:"data"`
}

// BlockMMR represents a Merkle Mountain Range for a block
type BlockMMR struct {
	Peaks []*string `json:"peaks"`
}

// ReportedEntry represents an entry in the "reported" array in the RecentBlocks JSON
type ReportedEntry struct {
	Hash        string `json:"hash"`
	ExportsRoot string `json:"exports_root"`
}

// RecentBlockJSON represents a single block in the RecentBlocks list in JSON format
type RecentBlockJSON struct {
	HeaderHash string          `json:"header_hash"`
	MMR        BlockMMR        `json:"mmr"`
	StateRoot  string          `json:"state_root"`
	Reported   []ReportedEntry `json:"reported"`
}

// PendingReportJSON represents a work report with timeout from the Greek JSON
type PendingReportJSON struct {
	Report  WorkReport `json:"report"`
	Timeout uint64     `json:"timeout"`
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
