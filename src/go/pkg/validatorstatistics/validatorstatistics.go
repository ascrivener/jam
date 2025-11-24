package validatorstatistics

import (
	"jam/pkg/constants"
	"jam/pkg/types"
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

type CoreStatistics struct {
	OctetsIntroduced                               types.GenericNum // d
	AvailabilityContributionsInAssurancesExtrinsic types.GenericNum // p
	NumSegmentsImportedFrom                        types.GenericNum // i
	NumSegmentsExportedInto                        types.GenericNum // e
	SizeInOctetsOfExtrinsicsUsed                   types.GenericNum // z
	NumExtrinsicsUsed                              types.GenericNum // x
	WorkBundleLength                               types.GenericNum // b
	ActualRefinementGasUsed                        types.GenericNum // u
}

type AccumulationStatistics map[types.ServiceIndex]ServiceAccumulationStatistics

type TransferStatistics map[types.ServiceIndex]ServiceTransferStatistics

type ServiceAccumulationStatistics struct {
	NumberOfWorkItems types.GenericNum
	GasUsed           types.GenericNum
}

type ServiceTransferStatistics struct {
	NumberOfTransfers types.GenericNum
	GasUsed           types.GenericNum
}

type ServiceStatistics struct {
	PreimageExtrinsicSize struct {
		ExtrinsicCount    types.GenericNum
		TotalSizeInOctets types.GenericNum
	} // p
	ActualRefinementGasUsed struct {
		WorkReportCount types.GenericNum
		Amount          types.GenericNum
	} // r
	NumSegmentsImportedFrom      types.GenericNum              // i
	NumSegmentsExportedInto      types.GenericNum              // e
	SizeInOctetsOfExtrinsicsUsed types.GenericNum              // z
	NumExtrinsicsUsed            types.GenericNum              // x
	AccumulationStatistics       ServiceAccumulationStatistics // a
}
