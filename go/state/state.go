package state

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                                               // 8.2
	RecentBlocks               []RecentBlock                                                                // 7.1
	SafroleBasicState          SafroleBasicState                                                            // 6.3
	ServiceAccounts            ServiceAccounts                                                              // 9.2
	EntropyAccumulator         [4][32]byte                                                                  // 6.21
	ValidatorKeysetsStaging    types.ValidatorKeysets                                                       // 6.7
	ValidatorKeysetsActive     types.ValidatorKeysets                                                       // 6.7
	ValidatorKeysetsPriorEpoch types.ValidatorKeysets                                                       // 6.7
	PendingReports             [constants.NumCores]*PendingReport                                           // 11.1
	MostRecentBlockTimeslot    types.Timeslot                                                               // 6.1
	AuthorizerQueue            [constants.NumCores][constants.AuthorizerQueueLength][32]byte                // 8.1
	PrivilegedServices         PrivilegedServices                                                           // 9.9
	Disputes                   types.Disputes                                                               // 10.1
	ValidatorStatistics        [2][constants.NumValidators]SingleValidatorStatistics                        // 13.1
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]workreport.WorkReportWithWorkPackageHashes // 12.3
	AccumulationHistory        AccumulationHistory                                                          // 12.1
}

type PrivilegedServices struct {
	ManagerServiceIndex             types.ServiceIndex                    // m
	AssignServiceIndex              types.ServiceIndex                    // a
	DesignateServiceIndex           types.ServiceIndex                    // v
	AlwaysAccumulateServicesWithGas map[types.ServiceIndex]types.GasValue // z
}

type PendingReport struct {
	WorkReport workreport.WorkReport
	Timeslot   types.Timeslot
}

type SingleValidatorStatistics struct {
	BlocksProduced         uint64
	TicketsIntroduced      uint64
	PreimagesIntroduced    uint64
	OctetsIntroduced       uint64
	ReportsGuaranteed      uint64
	AvailabilityAssurances uint64
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
