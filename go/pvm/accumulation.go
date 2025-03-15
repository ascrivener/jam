package pvm

import (
	"sort"
	"sync"

	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

func SingleServiceAccumulation(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, serviceIndex types.ServiceIndex, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, *[32]byte, types.GasValue) {
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

type AccumulationOutputPairing struct {
	ServiceIndex   types.ServiceIndex
	PreimageResult [32]byte
}

func ParallelizedAccumulation(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (types.GasValue, AccumulationStateComponents, []DeferredTransfer, map[AccumulationOutputPairing]struct{}) {
	// Calculate total work results across all reports
	totalWorkResults := 0
	for _, report := range workReports {
		totalWorkResults += len(report.WorkResults)
	}

	// Collect all service indices to process, including the privileged ones
	// Allocate capacity for: all free accumulation services + all work results + 3 privileged services
	serviceIndices := make([]types.ServiceIndex, 0, len(freeAccumulationServices)+totalWorkResults+3)

	// Add regular service indices
	for idx := range freeAccumulationServices {
		serviceIndices = append(serviceIndices, idx)
	}
	for _, report := range workReports {
		for _, workResult := range report.WorkResults {
			serviceIndices = append(serviceIndices, workResult.ServiceIndex)
		}
	}

	// Add privileged service indices
	managerServiceIndex := accumulationStateComponents.PrivilegedServices.ManagerServiceIndex
	designateServiceIndex := accumulationStateComponents.PrivilegedServices.DesignateServiceIndex
	assignServiceIndex := accumulationStateComponents.PrivilegedServices.AssignServiceIndex

	serviceIndices = append(serviceIndices, managerServiceIndex, designateServiceIndex, assignServiceIndex)

	// Sort service indices for deterministic processing order
	sort.Slice(serviceIndices, func(i, j int) bool {
		return serviceIndices[i] < serviceIndices[j]
	})

	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalGasUsed types.GasValue
	accumulationOutputPairings := make(map[AccumulationOutputPairing]struct{})
	n := make(state.ServiceAccounts)

	// m will store the union of (original keys - result keys) for all service indices
	// This represents all keys that were present in the original set but missing in at least one result
	m := make(map[types.ServiceIndex]struct{})

	// Keep track of original keys for reference
	originalKeys := make(map[types.ServiceIndex]struct{})
	for serviceIndex := range accumulationStateComponents.ServiceAccounts {
		originalKeys[serviceIndex] = struct{}{}
	}

	// Map to store deferred transfers by service index
	transfersByServiceIndex := make(map[types.ServiceIndex][]DeferredTransfer)

	// Map to store state components by service index (for privileged services)
	privilegedStateComponents := make(map[types.ServiceIndex]AccumulationStateComponents)

	for _, sIndex := range serviceIndices {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()
			accumulationStateComponentsResult, deferredTransfersResult, preimageResult, gasUsed := SingleServiceAccumulation(accumulationStateComponents, timeslot, workReports, freeAccumulationServices, sIndex, posteriorEntropyAccumulator)
			mu.Lock()
			totalGasUsed += gasUsed

			// Store result for privileged services
			if sIndex == managerServiceIndex || sIndex == designateServiceIndex || sIndex == assignServiceIndex {
				privilegedStateComponents[sIndex] = accumulationStateComponentsResult
			}

			if preimageResult != nil {
				accumulationOutputPairings[AccumulationOutputPairing{
					ServiceIndex:   sIndex,
					PreimageResult: *preimageResult,
				}] = struct{}{}
			}
			transfersByServiceIndex[sIndex] = deferredTransfersResult

			// Add relevant service accounts to n
			for serviceIndex, serviceAccount := range accumulationStateComponentsResult.ServiceAccounts {
				_, ok := accumulationStateComponents.ServiceAccounts[serviceIndex]
				if serviceIndex == sIndex || !ok {
					n[serviceIndex] = serviceAccount
				}
			}

			// For each original key, check if it's missing in this result
			// If missing, add it to m (the union of missing keys)
			for origKey := range originalKeys {
				if _, exists := accumulationStateComponentsResult.ServiceAccounts[origKey]; !exists {
					m[origKey] = struct{}{}
				}
			}

			mu.Unlock()
		}(sIndex)
	}
	wg.Wait()

	// Now combine the deferred transfers in service index order
	deferredTransfers := make([]DeferredTransfer, 0)
	for _, sIndex := range serviceIndices {
		if transfers, ok := transfersByServiceIndex[sIndex]; ok {
			deferredTransfers = append(deferredTransfers, transfers...)
		}
	}

	// Create final service accounts:
	// 1. Start with original service accounts
	// 2. Union with n (accounts from individual service processing)
	// 3. Remove keys in m (keys that disappeared in at least one result)
	finalServiceAccounts := make(state.ServiceAccounts)

	// First, add all original accounts
	for serviceIndex, serviceAccount := range accumulationStateComponents.ServiceAccounts {
		finalServiceAccounts[serviceIndex] = serviceAccount
	}

	// Then add/override with accounts from n
	for serviceIndex, serviceAccount := range n {
		finalServiceAccounts[serviceIndex] = serviceAccount
	}

	// Finally, remove any keys in m (keys that disappeared in at least one result)
	for serviceIndex := range m {
		delete(finalServiceAccounts, serviceIndex)
	}

	// Get the components from privileged services
	var upcomingValidatorKeysets types.ValidatorKeysets
	var authorizersQueue [341][80][32]byte
	var privilegedServices state.PrivilegedServices

	if components, ok := privilegedStateComponents[designateServiceIndex]; ok {
		upcomingValidatorKeysets = components.UpcomingValidatorKeysets
	} else {
		upcomingValidatorKeysets = accumulationStateComponents.UpcomingValidatorKeysets
	}

	if components, ok := privilegedStateComponents[assignServiceIndex]; ok {
		authorizersQueue = components.AuthorizersQueue
	} else {
		authorizersQueue = accumulationStateComponents.AuthorizersQueue
	}

	if components, ok := privilegedStateComponents[managerServiceIndex]; ok {
		privilegedServices = components.PrivilegedServices
	} else {
		privilegedServices = accumulationStateComponents.PrivilegedServices
	}

	return totalGasUsed, AccumulationStateComponents{
		ServiceAccounts:          finalServiceAccounts,
		UpcomingValidatorKeysets: upcomingValidatorKeysets,
		AuthorizersQueue:         authorizersQueue,
		PrivilegedServices:       privilegedServices,
	}, deferredTransfers, accumulationOutputPairings
}

func OuterAccumulation(gas types.GasValue, timeslot types.Timeslot, workReports []workreport.WorkReport, accumulationStateComponents *AccumulationStateComponents, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (int, AccumulationStateComponents, []DeferredTransfer, map[AccumulationOutputPairing]struct{}) {
	// Initialize return values
	totalProcessedReports := 0
	currentStateComponents := *accumulationStateComponents
	allDeferredTransfers := make([]DeferredTransfer, 0)
	allOutputPairings := make(map[AccumulationOutputPairing]struct{})

	// Remaining gas for processing
	remainingGas := gas

	// Start index for the next batch of reports to process
	startIdx := 0

	// Continue processing batches until we run out of gas or reports
	for startIdx < len(workReports) && remainingGas > 0 {
		// Calculate how many reports we can process with current gas
		batchEndIdx := startIdx
		gasPrioritizationRatioSum := types.GasValue(0)

		for ; batchEndIdx < len(workReports); batchEndIdx++ {
			batchGas := types.GasValue(0)
			for _, report := range workReports[batchEndIdx].WorkResults {
				batchGas += report.GasPrioritizationRatio
			}

			if gasPrioritizationRatioSum+batchGas > remainingGas {
				break
			}
			gasPrioritizationRatioSum += batchGas
		}

		// If we can't process even one report, break
		if batchEndIdx == startIdx {
			break
		}

		// Process this batch
		batchGasUsed, newStateComponents, batchTransfers, batchPairings := ParallelizedAccumulation(
			&currentStateComponents,
			timeslot,
			workReports[startIdx:batchEndIdx],
			freeAccumulationServices,
			posteriorEntropyAccumulator,
		)

		// Update our state for the next iteration
		remainingGas -= batchGasUsed
		currentStateComponents = newStateComponents
		allDeferredTransfers = append(allDeferredTransfers, batchTransfers...)

		// Merge the output pairings
		for pairing := range batchPairings {
			allOutputPairings[pairing] = struct{}{}
		}

		// Update the count of reports processed
		totalProcessedReports += (batchEndIdx - startIdx)

		// Move to next batch
		startIdx = batchEndIdx

		// Reset free accumulation services as they should only be applied once
		freeAccumulationServices = make(map[types.ServiceIndex]types.GasValue)
	}

	return totalProcessedReports, currentStateComponents, allDeferredTransfers, allOutputPairings
}
