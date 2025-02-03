package state

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

type State struct {
	AuthorizersPool            [constants.NumCores][][32]byte                 // 8.2
	RecentBlocks               []RecentBlock                                  // 7.1
	SafroleBasicState          SafroleBasicState                              // 6.3
	PriorServiceAccountState   map[types.ServiceIndex]ServiceAccount          // 9.2
	EntropyAccumulator         [4][32]byte                                    // 6.21
	ValidatorKeysetsStaging    [constants.NumValidators]types.ValidatorKeyset // 6.7
	ValidatorKeysetsActive     [constants.NumValidators]types.ValidatorKeyset // 6.7
	ValidatorKeysetsPriorEpoch [constants.NumValidators]types.ValidatorKeyset // 6.7
	PendingReports             [constants.NumCores]*struct {
		WorkReport workreport.WorkReport
		Timeslot   types.Timeslot
	} // 11.1
	MostRecentBlockTimeslot types.Timeslot                                                // 6.1
	AuthorizerQueue         [constants.NumCores][constants.AuthorizerQueueLength][32]byte // 8.1
	Disputes                struct {
		WorkReportHashesGood  [][32]byte
		WorkReportHashesBad   [][32]byte
		WorkReportHashesWonky [][32]byte
		ValidatorPunishes     []types.Ed25519PublicKey
	} // 10.1
	PrivilegedServices struct {
		ManagerServiceIndex             types.ServiceIndex
		AssignServiceIndex              types.ServiceIndex
		DesignateServiceIndex           types.ServiceIndex
		AlwaysAccumulateServicesWithGas map[types.ServiceIndex]types.GasValue
	} // 9.9
	ValidatorStatistics [2][constants.NumValidators]struct {
		BlocksProduced         uint64
		TicketsIntroduced      uint64
		PreimagesIntroduced    uint64
		OctetsIntroduced       uint64
		ReportsGuaranteed      uint64
		AvailabilityAssurances uint64
	} // 13.1
	AccumulationQueue [constants.NumTimeslotsPerEpoch][]struct {
		WorkReport        workreport.WorkReport
		WorkPackageHashes map[[32]byte]struct{}
	} // 12.3
	AccumulationHistory [constants.NumTimeslotsPerEpoch]map[[32]byte]struct{} // 12.1
}
