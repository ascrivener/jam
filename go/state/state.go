package state

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/sealingkeysequence"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/validatorstatistics"
	"github.com/ascrivener/jam/workreport"
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

// ValidatorStatisticsJSON represents the JSON structure of validator statistics
type ValidatorStatisticsJSON struct {
	ValsCurrent []ValidatorStatEntry `json:"vals_current"`
	ValsLast    []ValidatorStatEntry `json:"vals_last"`
	Cores       []CoreStatEntry      `json:"cores"`
	Services    interface{}          `json:"services"` // Can be null in JSON
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
	Storage    interface{}           `json:"storage"` // Can be null
}

// AccountJSON represents a single account
type AccountJSON struct {
	ID   int             `json:"id"`
	Data AccountDataJSON `json:"data"`
}

// BlockMMR represents a Merkle Mountain Range for a block
type BlockMMR struct {
	Peaks []string `json:"peaks"`
}

// RecentBlock represents a single block in the RecentBlocks list
type RecentBlockJSON struct {
	HeaderHash string   `json:"header_hash"`
	MMR        BlockMMR `json:"mmr"`
	StateRoot  string   `json:"state_root"`
	Reported   []string `json:"reported"`
}

// StateFromGreekJSON parses a JSON representation of a state (using Greek letter field names)
// and returns a proper Go State struct
func StateFromGreekJSON(jsonData []byte) (State, error) {
	// Define a struct with JSON field names matching the Greek letters in the input
	type JSONState struct {
		Alpha    [][]string             `json:"alpha"`    // AuthorizersPool
		Varphi   [][]string             `json:"varphi"`   // AuthorizerQueue
		Beta     []RecentBlockJSON      `json:"beta"`     // RecentBlocks
		Gamma    Gamma                  `json:"gamma"`    // SafroleBasicState
		Psi      DisputesJSON           `json:"psi"`      // Disputes
		Eta      []string               `json:"eta"`      // EntropyAccumulator
		Iota     []ValidatorKeysetJSON  `json:"iota"`     // ValidatorKeysetsStaging
		Kappa    []ValidatorKeysetJSON  `json:"kappa"`    // ValidatorKeysetsActive
		Lambda   []ValidatorKeysetJSON  `json:"lambda"`   // ValidatorKeysetsPriorEpoch
		Rho      []json.RawMessage      `json:"rho"`      // PendingReports
		Tau      uint64                 `json:"tau"`      // MostRecentBlockTimeslot
		Chi      PrivilegedServicesJSON `json:"chi"`      // PrivilegedServices
		Pi       json.RawMessage        `json:"pi"`       // ValidatorStatistics
		Theta    [][]json.RawMessage    `json:"theta"`    // AccumulationQueue
		Xi       [][]json.RawMessage    `json:"xi"`       // AccumulationHistory
		Accounts []AccountJSON          `json:"accounts"` // ServiceAccounts
	}

	// Parse the JSON into our intermediate struct
	var jsonState JSONState
	if err := json.Unmarshal(jsonData, &jsonState); err != nil {
		return State{}, fmt.Errorf("failed to parse state JSON: %w", err)
	}

	// Create the actual state
	state := State{}

	// Process fields in the same order as in JSONState struct

	// 1. Alpha -> AuthorizersPool
	if jsonState.Alpha != nil {
		// Initialize the fixed-size array with a composite literal
		var authorizersPool [constants.NumCores][][32]byte
		for i := range jsonState.Alpha {
			authorizersPool[i] = make([][32]byte, len(jsonState.Alpha[i]))
			for j, hashStr := range jsonState.Alpha[i] {
				authorizersPool[i][j] = hexToHashMust(hashStr)
			}
		}
		state.AuthorizersPool = authorizersPool
	}

	// 2. Varphi -> AuthorizerQueue
	if jsonState.Varphi != nil {
		for i := range jsonState.Varphi {
			for j, hashStr := range jsonState.Varphi[i] {
				state.AuthorizerQueue[i][j] = hexToHashMust(hashStr)
			}
		}
	}

	// 3. Beta -> RecentBlocks
	state.RecentBlocks = make([]RecentBlock, len(jsonState.Beta))
	for i, blockJSON := range jsonState.Beta {
		// Convert header hash
		headerHash := hexToHashMust(blockJSON.HeaderHash)

		// Convert state root
		stateRoot := hexToHashMust(blockJSON.StateRoot)

		// Convert MMR
		mmrPeaks := make(merklizer.MMRRange, len(blockJSON.MMR.Peaks))
		if len(blockJSON.MMR.Peaks) > 0 {
			for j, peak := range blockJSON.MMR.Peaks {
				hash := hexToHashMust(peak)
				mmrPeaks[j] = &hash
			}
		}

		// Convert reported hashes to work package hashes map
		workPackageHashes := make(map[[32]byte][32]byte)
		for _, _ = range blockJSON.Reported {
			panic("not impelmented")
		}

		state.RecentBlocks[i] = RecentBlock{
			HeaderHash:            headerHash,
			AccumulationResultMMR: mmrPeaks,
			StateRoot:             stateRoot,
			WorkPackageHashes:     workPackageHashes,
		}
	}

	// 4. Gamma -> SafroleBasicState
	// Initialize with empty values
	state.SafroleBasicState = SafroleBasicState{
		ValidatorKeysetsPending:    types.ValidatorKeysets{},
		EpochTicketSubmissionsRoot: types.BandersnatchRingRoot{},
		SealingKeySequence:         sealingkeysequence.SealingKeySequence{},
		TicketAccumulator:          []ticket.Ticket{},
	}

	// Convert gamma_k (yk) to ValidatorKeysetsPending
	if len(jsonState.Gamma.GammaK) > 0 {
		// Fill in ValidatorKeysets with data from GammaK
		for i, gammaK := range jsonState.Gamma.GammaK {
			state.SafroleBasicState.ValidatorKeysetsPending[i] = ValidatorKeysetJSONToKeyset(gammaK)
		}
	}

	// Convert gamma_z (yz) to EpochTicketSubmissionsRoot
	if jsonState.Gamma.GammaZ != "" {
		// Convert the hex string to BandersnatchRingRoot
		hash := hexToBytesMust(jsonState.Gamma.GammaZ)
		var ringRoot types.BandersnatchRingRoot
		copy(ringRoot[:], hash[:])
		state.SafroleBasicState.EpochTicketSubmissionsRoot = ringRoot
	}

	// Convert gamma_s (ys) to SealingKeySequence
	if len(jsonState.Gamma.GammaS.Keys) > 0 {
		// Create BandersnatchPublicKey array from keys
		var keys [constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey

		// Parse keys from the JSON
		for i, key := range jsonState.Gamma.GammaS.Keys {
			keyBytes := hexToBytesMust(key)
			copy(keys[i][:], keyBytes)
		}

		// Create SealingKeySequence using constructor
		state.SafroleBasicState.SealingKeySequence = sealingkeysequence.NewBandersnatchKeysSeries(keys)
	} else {
		return State{}, fmt.Errorf("No keys found in GammaS. Seal key tickets not implemented yet")
	}

	// Convert gamma_a (ya) to TicketAccumulator
	if len(jsonState.Gamma.GammaA) > 0 {
		return State{}, fmt.Errorf("ticket accumulator not implemented yet")
	}

	// 5. Psi -> Disputes
	if len(jsonState.Psi.Good) > 0 {
		return State{}, fmt.Errorf("good disputes not implemented yet")
	}
	if len(jsonState.Psi.Bad) > 0 {
		return State{}, fmt.Errorf("bad disputes not implemented yet")
	}
	if len(jsonState.Psi.Wonky) > 0 {
		return State{}, fmt.Errorf("wonky disputes not implemented yet")
	}
	if len(jsonState.Psi.Offenders) > 0 {
		return State{}, fmt.Errorf("offender disputes not implemented yet")
	}

	// If we get here, all arrays are empty, so we can safely use an empty Disputes
	state.Disputes = types.Disputes{
		WorkReportHashesGood:  make(map[[32]byte]struct{}),
		WorkReportHashesBad:   make(map[[32]byte]struct{}),
		WorkReportHashesWonky: make(map[[32]byte]struct{}),
		ValidatorPunishes:     make(map[types.Ed25519PublicKey]struct{}),
	}

	// 6. Eta -> EntropyAccumulator
	if len(jsonState.Eta) != 4 {
		return State{}, fmt.Errorf("invalid length of EntropyAccumulator")
	}
	for i, hashStr := range jsonState.Eta {
		hash, err := hexToHash(hashStr)
		if err != nil {
			return State{}, fmt.Errorf("invalid hash in EntropyAccumulator[%d]: %w", i, err)
		}
		state.EntropyAccumulator[i] = hash
	}

	// 7. Iota -> ValidatorKeysetsStaging
	if len(jsonState.Iota) != constants.NumValidators {
		return State{}, fmt.Errorf("invalid length of ValidatorKeysetsStaging")
	}
	state.ValidatorKeysetsStaging = types.ValidatorKeysets{}
	for i, keysetJSON := range jsonState.Iota {
		state.ValidatorKeysetsStaging[i] = ValidatorKeysetJSONToKeyset(keysetJSON)
	}

	// 8. Kappa -> ValidatorKeysetsActive
	if len(jsonState.Kappa) != constants.NumValidators {
		return State{}, fmt.Errorf("invalid length of ValidatorKeysetsActive")
	}
	state.ValidatorKeysetsActive = types.ValidatorKeysets{}
	for i, keysetJSON := range jsonState.Kappa {
		state.ValidatorKeysetsActive[i] = ValidatorKeysetJSONToKeyset(keysetJSON)
	}

	// 9. Lambda -> ValidatorKeysetsPriorEpoch
	if len(jsonState.Lambda) != constants.NumValidators {
		return State{}, fmt.Errorf("invalid length of ValidatorKeysetsPriorEpoch")
	}
	state.ValidatorKeysetsPriorEpoch = types.ValidatorKeysets{}
	for i, keysetJSON := range jsonState.Lambda {
		state.ValidatorKeysetsPriorEpoch[i] = ValidatorKeysetJSONToKeyset(keysetJSON)
	}

	// 10. Rho -> PendingReports
	if len(jsonState.Rho) != constants.NumCores {
		return State{}, fmt.Errorf("invalid length of PendingReports")
	}
	for i, reportJSON := range jsonState.Rho {
		if string(reportJSON) != "null" {
			return State{}, fmt.Errorf("pending report not implemented yet")
		}
		state.PendingReports[i] = nil
	}

	// 11. Tau -> MostRecentBlockTimeslot
	state.MostRecentBlockTimeslot = types.Timeslot(jsonState.Tau)

	// 12. Chi -> PrivilegedServices
	state.PrivilegedServices = types.PrivilegedServices{
		ManagerServiceIndex:             types.ServiceIndex(jsonState.Chi.ChiM),
		AssignServiceIndex:              types.ServiceIndex(jsonState.Chi.ChiA),
		DesignateServiceIndex:           types.ServiceIndex(jsonState.Chi.ChiV),
		AlwaysAccumulateServicesWithGas: map[types.ServiceIndex]types.GasValue{},
	}

	// 13. Pi -> ValidatorStatistics
	if len(jsonState.Pi) > 0 && string(jsonState.Pi) != "null" {
		var stats ValidatorStatisticsJSON
		if err := json.Unmarshal(jsonState.Pi, &stats); err != nil {
			return State{}, fmt.Errorf("failed to parse validator statistics: %w", err)
		}

		// Initialize the validator statistics structure
		state.ValidatorStatistics = validatorstatistics.ValidatorStatistics{
			AccumulatorStatistics:   [constants.NumValidators]validatorstatistics.SingleValidatorStatistics{},
			PreviousEpochStatistics: [constants.NumValidators]validatorstatistics.SingleValidatorStatistics{},
			CoreStatistics:          [constants.NumCores]validatorstatistics.CoreStatistics{},
			ServiceStatistics:       make(map[types.ServiceIndex]validatorstatistics.ServiceStatistics),
		}

		// Copy vals_current -> AccumulatorStatistics
		for i, valCurrent := range stats.ValsCurrent {
			if i >= constants.NumValidators {
				break
			}
			state.ValidatorStatistics.AccumulatorStatistics[i] = validatorstatistics.SingleValidatorStatistics{
				BlocksProduced:         uint32(valCurrent.Blocks),
				TicketsIntroduced:      uint32(valCurrent.Tickets),
				PreimagesIntroduced:    uint32(valCurrent.PreImages),
				OctetsIntroduced:       uint32(valCurrent.PreImagesSize),
				ReportsGuaranteed:      uint32(valCurrent.Guarantees),
				AvailabilityAssurances: uint32(valCurrent.Assurances),
			}
		}

		// Copy vals_last -> PreviousEpochStatistics
		for i, valLast := range stats.ValsLast {
			if i >= constants.NumValidators {
				break
			}
			state.ValidatorStatistics.PreviousEpochStatistics[i] = validatorstatistics.SingleValidatorStatistics{
				BlocksProduced:         uint32(valLast.Blocks),
				TicketsIntroduced:      uint32(valLast.Tickets),
				PreimagesIntroduced:    uint32(valLast.PreImages),
				OctetsIntroduced:       uint32(valLast.PreImagesSize),
				ReportsGuaranteed:      uint32(valLast.Guarantees),
				AvailabilityAssurances: uint32(valLast.Assurances),
			}
		}

		// Copy cores -> CoreStatistics
		for i, core := range stats.Cores {
			if i >= constants.NumCores {
				break
			}
			state.ValidatorStatistics.CoreStatistics[i] = validatorstatistics.CoreStatistics{
				OctetsIntroduced: validatorstatistics.ValidatorStatisticsNum(core.DaLoad),
				AvailabilityContributionsInAssurancesExtrinsic: validatorstatistics.ValidatorStatisticsNum(core.Popularity),
				NumSegmentsImportedFrom:                        validatorstatistics.ValidatorStatisticsNum(core.Imports),
				NumSegmentsExportedInto:                        validatorstatistics.ValidatorStatisticsNum(core.Exports),
				SizeInOctetsOfExtrinsicsUsed:                   validatorstatistics.ValidatorStatisticsNum(core.ExtrinsicSize),
				NumExtrinsicsUsed:                              validatorstatistics.ValidatorStatisticsNum(core.ExtrinsicCount),
				WorkBundleLength:                               validatorstatistics.ValidatorStatisticsNum(core.BundleSize),
				ActualRefinementGasUsed:                        validatorstatistics.ValidatorStatisticsGasValue(core.GasUsed),
			}
		}

		// Services is null in the example, so we leave the empty map initialized above
	}

	// 14. Theta -> AccumulationQueue
	if len(jsonState.Theta) != constants.NumTimeslotsPerEpoch {
		return State{}, fmt.Errorf("invalid length of AccumulationQueue")
	}

	// Initialize with empty arrays
	for i := 0; i < constants.NumTimeslotsPerEpoch; i++ {
		state.AccumulationQueue[i] = []workreport.WorkReportWithWorkPackageHashes{}
	}

	// Check that all arrays are empty as expected
	for _, queueSlot := range jsonState.Theta {
		if len(queueSlot) > 0 {
			return State{}, fmt.Errorf("non-empty accumulation queue not supported yet")
		}
	}

	// 15. Xi -> AccumulationHistory
	if len(jsonState.Xi) != constants.NumTimeslotsPerEpoch {
		return State{}, fmt.Errorf("invalid length of AccumulationHistory")
	}

	// Initialize AccumulationHistory with empty maps
	state.AccumulationHistory = AccumulationHistory{}
	for i := 0; i < constants.NumTimeslotsPerEpoch; i++ {
		state.AccumulationHistory[i] = map[[32]byte]struct{}{}
	}

	// Check that all arrays are empty as expected
	for _, historySlot := range jsonState.Xi {
		if len(historySlot) > 0 {
			return State{}, fmt.Errorf("non-empty accumulation history not supported yet")
		}
	}

	// 16. Accounts -> ServiceAccounts
	if jsonState.Accounts != nil {
		state.ServiceAccounts = make(serviceaccount.ServiceAccounts)

		for _, account := range jsonState.Accounts {
			// Create a new service account
			serviceAcc := &serviceaccount.ServiceAccount{
				StorageDictionary:              make(map[[32]byte][]byte),
				PreimageLookup:                 make(map[[32]byte][]byte),
				PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
			}

			// Convert code hash from hex string to [32]byte
			codeHash, err := hexToHash(account.Data.Service.CodeHash)
			if err != nil {
				return State{}, fmt.Errorf("invalid code hash in account %d: %w", account.ID, err)
			}
			serviceAcc.CodeHash = codeHash

			// Convert other service fields
			serviceAcc.Balance = types.Balance(account.Data.Service.Balance)
			serviceAcc.MinimumGasForAccumulate = types.GasValue(account.Data.Service.MinItemGas)
			serviceAcc.MinimumGasForOnTransfer = types.GasValue(account.Data.Service.MinMemoGas)

			// Process preimages
			for _, preimage := range account.Data.Preimages {
				// Convert hash from hex string to [32]byte
				hash, err := hexToHash(preimage.Hash)
				if err != nil {
					return State{}, fmt.Errorf("invalid preimage hash in account %d: %w", account.ID, err)
				}

				// Convert blob from hex string to []byte
				blob := hexToBytesMust(preimage.Blob)

				serviceAcc.PreimageLookup[hash] = blob
			}

			// Process lookup metadata entries
			for _, lookupEntry := range account.Data.LookupMeta {
				// Convert key hash from hex string to [32]byte
				keyHash, err := hexToHash(lookupEntry.Key.Hash)
				if err != nil {
					return State{}, fmt.Errorf("invalid lookup meta key hash in account %d: %w", account.ID, err)
				}

				// Create historical status key
				histKey := serviceaccount.PreimageLookupHistoricalStatusKey{
					Preimage:   keyHash,
					BlobLength: types.BlobLength(lookupEntry.Key.Length),
				}

				// Convert value array to timeslots
				timeslots := make([]types.Timeslot, len(lookupEntry.Value))
				for i, val := range lookupEntry.Value {
					timeslots[i] = types.Timeslot(val)
				}

				// Add to historical status map
				serviceAcc.PreimageLookupHistoricalStatus[histKey] = timeslots
			}

			// Check if storage is not null and not empty
			if account.Data.Storage != nil {
				// Check if it's actually empty (could be JSON null but parsed as empty map)
				if m, ok := account.Data.Storage.(map[string]interface{}); !ok || len(m) > 0 {
					return State{}, fmt.Errorf("storage not implemented yet for account %d", account.ID)
				}
			}

			// Add to service accounts map with service index as key
			state.ServiceAccounts[types.ServiceIndex(account.ID)] = serviceAcc
		}
	}

	return state, nil
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
