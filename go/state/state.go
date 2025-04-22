package state

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
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
	ValidatorStatistics        ValidatorStatistics                                                          // π
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes // ϑ
	AccumulationHistory        AccumulationHistory                                                          // ξ
}

type PendingReport struct {
	WorkReport workreport.WorkReport
	Timeslot   types.Timeslot
}

type ValidatorStatistics struct {
	AccumulatorStatistics   [constants.NumValidators]SingleValidatorStatistics // V
	PreviousEpochStatistics [constants.NumValidators]SingleValidatorStatistics // L
	CoreStatistics          [constants.NumCores]CoreStatistics                 // C
	ServiceStatistics       map[types.ServiceIndex]ServiceStatistics           // S
}

type SingleValidatorStatistics struct {
	BlocksProduced         uint32 // b
	TicketsIntroduced      uint32 // t
	PreimagesIntroduced    uint32 // p
	OctetsIntroduced       uint32 // d
	ReportsGuaranteed      uint32 // g
	AvailabilityAssurances uint32 // a
}

type CoreStatistics struct {
	OctetsIntroduced                               uint64         // d
	AvailabilityContributionsInAssurancesExtrinsic uint64         // p
	NumSegmentsImportedFrom                        uint64         // i
	NumSegmentsExportedInto                        uint64         // e
	SizeInOctetsOfExtrinsicsUsed                   uint64         // z
	NumExtrinsicsUsed                              uint64         // x
	WorkBundleLength                               uint64         // b
	ActualRefinementGasUsed                        types.GasValue // u
}

type ServiceStatistics struct {
	PreimageExtrinsicSize struct {
		ExtrinsicCount    uint64
		TotalSizeInOctets uint64
	} // p
	ActualRefinementGasUsed struct {
		WorkReportCount uint64
		Amount          types.GasValue
	} // u
	NumSegmentsImportedFrom      uint64 // i
	NumSegmentsExportedInto      uint64 // e
	SizeInOctetsOfExtrinsicsUsed uint64 // z
	NumExtrinsicsUsed            uint64 // x
	AccumulationStatistics       struct {
		WorkItemsAccumulated                  uint64
		AmountOfGasUsedThroughoutAccumulation types.GasValue
	} // a
	DeferredTransferStatistics struct {
		NumTransfers            uint64
		TotalGasUsedInTransfers types.GasValue
	} // t
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
	bitSeqKeyMap := make(map[bitsequence.BitSeqKey][]byte)
	for k, v := range serializedState {
		bitSeqKeyMap[bitsequence.FromBytes(k[:]).Key()] = v
	}

	return merklizer.MerklizeStateRecurser(bitSeqKeyMap)
}
