package state

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                                // 8.2
	RecentBlocks               []RecentBlock                                                 // 7.1
	SafroleBasicState          SafroleBasicState                                             // 6.3
	ServiceAccounts            ServiceAccounts                                               // 9.2
	EntropyAccumulator         [4][32]byte                                                   // 6.21
	ValidatorKeysetsStaging    [constants.NumValidators]types.ValidatorKeyset                // 6.7
	ValidatorKeysetsActive     [constants.NumValidators]types.ValidatorKeyset                // 6.7
	ValidatorKeysetsPriorEpoch [constants.NumValidators]types.ValidatorKeyset                // 6.7
	PendingReports             [constants.NumCores]*PendingReport                            // 11.1
	MostRecentBlockTimeslot    types.Timeslot                                                // 6.1
	AuthorizerQueue            [constants.NumCores][constants.AuthorizerQueueLength][32]byte // 8.1
	PrivilegedServices         PrivilegedServices                                            // 9.9
	Disputes                   Disputes                                                      //10.1
	ValidatorStatistics        [2][constants.NumValidators]SingleValidatorStatistics         // 13.1
	AccumulationQueue          [constants.NumTimeslotsPerEpoch][]struct {
		WorkReport        workreport.WorkReport
		WorkPackageHashes map[[32]byte]struct{}
	} // 12.3
	AccumulationHistory [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{} // 12.1
}

type PrivilegedServices struct {
	ManagerServiceIndex             types.ServiceIndex
	AssignServiceIndex              types.ServiceIndex
	DesignateServiceIndex           types.ServiceIndex
	AlwaysAccumulateServicesWithGas map[types.ServiceIndex]types.GasValue
}

type Disputes struct {
	WorkReportHashesGood  map[[32]byte]struct{}
	WorkReportHashesBad   map[[32]byte]struct{}
	WorkReportHashesWonky map[[32]byte]struct{}
	ValidatorPunishes     map[types.Ed25519PublicKey]struct{}
}

func (d Disputes) PunishEd25519Key(key types.Ed25519PublicKey) bool {
	punish := false
	for posteriorValidatorPunish, _ := range d.ValidatorPunishes {
		if key == posteriorValidatorPunish {
			punish = true
		}
	}
	return punish
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
