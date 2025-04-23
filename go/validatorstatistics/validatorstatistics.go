package validatorstatistics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

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

type ValidatorStatisticsNum uint64

type ValidatorStatisticsGasValue types.GasValue

type CoreStatistics struct {
	OctetsIntroduced                               ValidatorStatisticsNum      // d
	AvailabilityContributionsInAssurancesExtrinsic ValidatorStatisticsNum      // p
	NumSegmentsImportedFrom                        ValidatorStatisticsNum      // i
	NumSegmentsExportedInto                        ValidatorStatisticsNum      // e
	SizeInOctetsOfExtrinsicsUsed                   ValidatorStatisticsNum      // z
	NumExtrinsicsUsed                              ValidatorStatisticsNum      // x
	WorkBundleLength                               ValidatorStatisticsNum      // b
	ActualRefinementGasUsed                        ValidatorStatisticsGasValue // u
}

type AccumulationStatistics map[types.ServiceIndex]ServiceAccumulationStatistics

type TransferStatistics map[types.ServiceIndex]ServiceTransferStatistics

type ServiceAccumulationStatistics struct {
	NumberOfWorkItems ValidatorStatisticsNum
	GasUsed           ValidatorStatisticsGasValue
}

type ServiceTransferStatistics struct {
	NumberOfTransfers ValidatorStatisticsNum
	GasUsed           ValidatorStatisticsGasValue
}

type ServiceStatistics struct {
	PreimageExtrinsicSize struct {
		ExtrinsicCount    ValidatorStatisticsNum
		TotalSizeInOctets ValidatorStatisticsNum
	} // p
	ActualRefinementGasUsed struct {
		WorkReportCount ValidatorStatisticsNum
		Amount          ValidatorStatisticsGasValue
	} // r
	NumSegmentsImportedFrom      ValidatorStatisticsNum // i
	NumSegmentsExportedInto      ValidatorStatisticsNum // e
	SizeInOctetsOfExtrinsicsUsed ValidatorStatisticsNum // z
	NumExtrinsicsUsed            ValidatorStatisticsNum // x
	AccumulationStatistics       ServiceAccumulationStatistics
	DeferredTransferStatistics   ServiceTransferStatistics
}
