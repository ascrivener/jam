package pvm

import (
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

func SingleServiceAccumulation(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, serviceIndex types.ServiceIndex, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DefferredTransfer, *[32]byte, types.SignedGasValue) {
	var gas types.GasValue
	operandTuples := make([]OperandTuple, 0)
	if g, ok := freeAccumulationServices[serviceIndex]; ok {
		gas = g
	}
	for _, report := range workReports {
		for _, workResult := range report.WorkResults {
			if workResult.ServiceIndex == serviceIndex {
				gas += workResult.GasPrioritizationRatio
				operandTuples = append(operandTuples, OperandTuple{
					WorkPackageHash:       report.WorkPackageSpecification.WorkPackageHash,
					SegmentRoot:           report.WorkPackageSpecification.SegmentRoot,
					AuthorizerHash:        report.AuthorizerHash,
					WorkReportOutput:      report.Output,
					WorkResultPayloadHash: workResult.PayloadHash,
					ExecutionExitReason:   workResult.WorkOutput,
				})
			}
		}
	}
	return Accumulate(accumulationStateComponents, timeslot, serviceIndex, gas, operandTuples, posteriorEntropyAccumulator)
}
