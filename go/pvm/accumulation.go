package pvm

import (
	"sort"
	"sync"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

func SingleServiceAccumulation(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, serviceIndex types.ServiceIndex, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, *[32]byte, types.GasValue, PreimageProvisions) {
	var gas types.GasValue
	operandTuples := make([]OperandTuple, 0)
	if g, ok := freeAccumulationServices[serviceIndex]; ok {
		gas = g
	}
	for _, report := range workReports {
		for _, workDigest := range report.WorkDigests {
			if workDigest.ServiceIndex == serviceIndex {
				gas += workDigest.AccumulateGasLimit
				operandTuples = append(operandTuples, OperandTuple{
					WorkPackageHash:       report.WorkPackageSpecification.WorkPackageHash,
					SegmentRoot:           report.WorkPackageSpecification.SegmentRoot,
					AuthorizerHash:        report.AuthorizerHash,
					WorkReportOutput:      report.Output,
					WorkResultPayloadHash: workDigest.PayloadHash,
					GasLimit:              types.GenericGasValue(workDigest.AccumulateGasLimit),
					ExecutionExitReason:   workDigest.WorkResult,
				})
			}
		}
	}
	return Accumulate(accumulationStateComponents, timeslot, serviceIndex, gas, operandTuples, posteriorEntropyAccumulator)
}

type BEEFYCommitment struct {
	ServiceIndex   types.ServiceIndex
	PreimageResult [32]byte
}

func ParallelizedAccumulation(accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, map[BEEFYCommitment]struct{}, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}) {
	// Use a map to collect unique service indices to process
	serviceIndicesMap := make(map[types.ServiceIndex]struct{})

	// Add regular service indices
	for idx := range freeAccumulationServices {
		serviceIndicesMap[idx] = struct{}{}
	}
	for _, report := range workReports {
		for _, workDigest := range report.WorkDigests {
			serviceIndicesMap[workDigest.ServiceIndex] = struct{}{}
		}
	}

	// Add privileged service indices
	managerServiceIndex := accumulationStateComponents.PrivilegedServices.ManagerServiceIndex
	designateServiceIndex := accumulationStateComponents.PrivilegedServices.DesignateServiceIndex
	assignServiceIndices := accumulationStateComponents.PrivilegedServices.AssignServiceIndices

	serviceIndicesMap[managerServiceIndex] = struct{}{}
	serviceIndicesMap[designateServiceIndex] = struct{}{}
	for _, idx := range assignServiceIndices {
		serviceIndicesMap[idx] = struct{}{}
	}

	// Convert map keys to a slice for deterministic processing order
	serviceIndices := make([]types.ServiceIndex, 0, len(serviceIndicesMap))
	for idx := range serviceIndicesMap {
		serviceIndices = append(serviceIndices, idx)
	}

	// Sort service indices for deterministic processing order
	sort.Slice(serviceIndices, func(i, j int) bool {
		return serviceIndices[i] < serviceIndices[j]
	})

	var wg sync.WaitGroup
	var mu sync.Mutex
	var serviceGasUsage []struct {
		ServiceIndex types.ServiceIndex
		GasUsed      types.GasValue
	}
	accumulationOutputPairings := make(map[BEEFYCommitment]struct{})
	n := make(serviceaccount.ServiceAccounts)

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

	// Map to store preimage provisions by service index
	allPreimageProvisions := make(PreimageProvisions)

	// Store manager result for later processing
	var managerResult AccumulationStateComponents

	// Initialize state components for privileged services
	var posteriorUpcomingValidatorKeysets types.ValidatorKeysets
	var posteriorAuthorizersQueue [constants.NumCores][constants.AuthorizerQueueLength][32]byte

	for _, sIndex := range serviceIndices {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()
			accumulationStateComponentsResult, deferredTransfersResult, preimageResult, gasUsed, preimageProvisions := SingleServiceAccumulation(accumulationStateComponents, timeslot, workReports, freeAccumulationServices, sIndex, posteriorEntropyAccumulator)
			mu.Lock()
			serviceGasUsage = append(serviceGasUsage, struct {
				ServiceIndex types.ServiceIndex
				GasUsed      types.GasValue
			}{
				ServiceIndex: sIndex,
				GasUsed:      gasUsed,
			})

			// For manager service, just store the result for later processing
			if sIndex == managerServiceIndex {
				// Store result for processing after parallel phase
				managerResult = accumulationStateComponentsResult
			}
			// For non-manager services, process as usual
			if sIndex == designateServiceIndex {
				posteriorUpcomingValidatorKeysets = accumulationStateComponentsResult.UpcomingValidatorKeysets
			}

			for coreIndex := range constants.NumCores {
				assignServiceIndex := accumulationStateComponentsResult.PrivilegedServices.AssignServiceIndices[coreIndex]
				if sIndex == assignServiceIndex {
					posteriorAuthorizersQueue[coreIndex] = accumulationStateComponentsResult.AuthorizersQueue[coreIndex]
				}
			}

			if preimageResult != nil {
				accumulationOutputPairings[BEEFYCommitment{
					ServiceIndex:   sIndex,
					PreimageResult: *preimageResult,
				}] = struct{}{}
			}
			transfersByServiceIndex[sIndex] = deferredTransfersResult

			for k, v := range preimageProvisions {
				allPreimageProvisions[k] = v
			}

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

	// Now process manager service
	posteriorPrivilegedServices := ResolveManagerAccumulationResultPrivilegedServices(
		accumulationStateComponents,
		timeslot,
		workReports,
		freeAccumulationServices,
		managerResult.PrivilegedServices,
		posteriorEntropyAccumulator,
	)

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
	finalServiceAccounts := make(serviceaccount.ServiceAccounts)

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

	// Provisions preimage integration done below

	for preimageProvision := range allPreimageProvisions {
		serviceAccount, ok := finalServiceAccounts[preimageProvision.ServiceIndex]
		if !ok {
			continue
		}
		blob := []byte(preimageProvision.BlobString)
		preimage := blake2b.Sum256(blob)
		preimageLookupHistoricalStatusKey := serviceaccount.PreimageLookupHistoricalStatusKeyFromFullKey(preimage, types.BlobLength(len(blob)))
		serviceAccount.PreimageLookupHistoricalStatus[preimageLookupHistoricalStatusKey] = []types.Timeslot{timeslot}
		serviceAccount.PreimageLookup[serviceaccount.PreimageLookupKeyFromFullKey(preimage)] = types.Blob(blob)
	}

	return AccumulationStateComponents{
		ServiceAccounts:          finalServiceAccounts,
		UpcomingValidatorKeysets: posteriorUpcomingValidatorKeysets,
		AuthorizersQueue:         posteriorAuthorizersQueue,
		PrivilegedServices:       posteriorPrivilegedServices,
	}, deferredTransfers, accumulationOutputPairings, serviceGasUsage
}

// ProcessPrivilegedServices processes the privileged services based on the manager result
// and returns the updated privileged services configuration.
// This function handles the designate service and assign services in parallel.
func ResolveManagerAccumulationResultPrivilegedServices(
	accumulationStateComponents *AccumulationStateComponents,
	timeslot types.Timeslot,
	workReports []workreport.WorkReport,
	freeAccumulationServices map[types.ServiceIndex]types.GasValue,
	managerPrivilegedServices types.PrivilegedServices,
	posteriorEntropyAccumulator [4][32]byte,
) types.PrivilegedServices {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var designateServiceResult AccumulationStateComponents
	var assignServiceIndices [constants.NumCores]types.ServiceIndex

	// Process designate service in parallel
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _, _, _, _ := SingleServiceAccumulation(
			accumulationStateComponents,
			timeslot,
			workReports,
			freeAccumulationServices,
			managerPrivilegedServices.DesignateServiceIndex,
			posteriorEntropyAccumulator,
		)
		mu.Lock()
		designateServiceResult = result
		mu.Unlock()
	}()

	// Process assign services in parallel
	for coreIndex := range constants.NumCores {
		wg.Add(1)
		go func(coreIdx types.CoreIndex) {
			defer wg.Done()
			assignResult, _, _, _, _ := SingleServiceAccumulation(
				accumulationStateComponents,
				timeslot,
				workReports,
				freeAccumulationServices,
				managerPrivilegedServices.AssignServiceIndices[coreIdx],
				posteriorEntropyAccumulator,
			)

			mu.Lock()
			assignServiceIndices[coreIdx] = assignResult.PrivilegedServices.AssignServiceIndices[coreIdx]
			mu.Unlock()
		}(types.CoreIndex(coreIndex))
	}

	// Wait for all parallel processing to complete
	wg.Wait()

	// Return the updated privileged services configuration
	return types.PrivilegedServices{
		ManagerServiceIndex:             managerPrivilegedServices.ManagerServiceIndex,
		DesignateServiceIndex:           designateServiceResult.PrivilegedServices.DesignateServiceIndex,
		AssignServiceIndices:            assignServiceIndices,
		AlwaysAccumulateServicesWithGas: managerPrivilegedServices.AlwaysAccumulateServicesWithGas,
	}
}

func OuterAccumulation(gas types.GasValue, timeslot types.Timeslot, workReports []workreport.WorkReport, accumulationStateComponents *AccumulationStateComponents, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (int, AccumulationStateComponents, []DeferredTransfer, map[BEEFYCommitment]struct{}, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}) {
	// Initialize return values
	totalProcessedReports := 0
	currentStateComponents := *accumulationStateComponents
	allDeferredTransfers := make([]DeferredTransfer, 0)
	allOutputPairings := make(map[BEEFYCommitment]struct{})
	allServiceGasUsage := make([]struct {
		ServiceIndex types.ServiceIndex
		GasUsed      types.GasValue
	}, 0)

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
			for _, report := range workReports[batchEndIdx].WorkDigests {
				batchGas += report.AccumulateGasLimit
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
		newStateComponents, batchTransfers, batchPairings, batchServiceGasUsage := ParallelizedAccumulation(
			&currentStateComponents,
			timeslot,
			workReports[startIdx:batchEndIdx],
			freeAccumulationServices,
			posteriorEntropyAccumulator,
		)

		// Update our state for the next iteration
		var batchGasUsed types.GasValue
		for _, serviceGas := range batchServiceGasUsage {
			batchGasUsed += serviceGas.GasUsed
		}
		remainingGas -= batchGasUsed
		currentStateComponents = newStateComponents
		allDeferredTransfers = append(allDeferredTransfers, batchTransfers...)
		allServiceGasUsage = append(allServiceGasUsage, batchServiceGasUsage...)

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

	return totalProcessedReports, currentStateComponents, allDeferredTransfers, allOutputPairings, allServiceGasUsage
}
