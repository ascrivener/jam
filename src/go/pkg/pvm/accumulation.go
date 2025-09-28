package pvm

import (
	"bytes"
	"sort"
	"sync"

	"jam/pkg/constants"
	"jam/pkg/errors"
	"jam/pkg/serviceaccount"
	"jam/pkg/types"
	"jam/pkg/workreport"

	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

func SingleServiceAccumulation(batch *pebble.Batch, accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, serviceIndex types.ServiceIndex, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, *[32]byte, types.GasValue, PreimageProvisions, error) {
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
					GasLimit:              types.GenericNum(workDigest.AccumulateGasLimit),
					ExecutionExitReason:   workDigest.WorkResult,
				})
			}
		}
	}
	return Accumulate(batch, accumulationStateComponents, timeslot, serviceIndex, gas, operandTuples, posteriorEntropyAccumulator)
}

type BEEFYCommitment struct {
	ServiceIndex   types.ServiceIndex
	PreimageResult [32]byte
}

func ParallelizedAccumulation(batch *pebble.Batch, accumulationStateComponents *AccumulationStateComponents, timeslot types.Timeslot, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []DeferredTransfer, map[BEEFYCommitment]struct{}, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}, error) {
	// Use a map to collect unique service indices to process
	originalServiceIndicesMap := make(map[types.ServiceIndex]struct{})

	// Add regular service indices
	for idx := range freeAccumulationServices {
		originalServiceIndicesMap[idx] = struct{}{}
	}
	for _, report := range workReports {
		for _, workDigest := range report.WorkDigests {
			originalServiceIndicesMap[workDigest.ServiceIndex] = struct{}{}
		}
	}

	// Add privileged service indices
	serviceIndicesMapWithPrivileged := make(map[types.ServiceIndex]struct{})
	for idx := range originalServiceIndicesMap {
		serviceIndicesMapWithPrivileged[idx] = struct{}{}
	}
	managerServiceIndex := accumulationStateComponents.PrivilegedServices.ManagerServiceIndex
	designateServiceIndex := accumulationStateComponents.PrivilegedServices.DesignateServiceIndex
	assignServiceIndices := accumulationStateComponents.PrivilegedServices.AssignServiceIndices

	serviceIndicesMapWithPrivileged[managerServiceIndex] = struct{}{}
	serviceIndicesMapWithPrivileged[designateServiceIndex] = struct{}{}
	for _, idx := range assignServiceIndices {
		serviceIndicesMapWithPrivileged[idx] = struct{}{}
	}

	// Convert map keys to a slice for deterministic processing order
	serviceIndicesWithPrivileged := make([]types.ServiceIndex, 0, len(serviceIndicesMapWithPrivileged))
	for idx := range serviceIndicesMapWithPrivileged {
		serviceIndicesWithPrivileged = append(serviceIndicesWithPrivileged, idx)
	}

	// Sort service indices for deterministic processing order
	sort.Slice(serviceIndicesWithPrivileged, func(i, j int) bool {
		return serviceIndicesWithPrivileged[i] < serviceIndicesWithPrivileged[j]
	})

	var wg sync.WaitGroup
	var mu sync.Mutex
	var serviceGasUsage []struct {
		ServiceIndex types.ServiceIndex
		GasUsed      types.GasValue
	}
	accumulationOutputPairings := make(map[BEEFYCommitment]struct{})
	n := make(serviceaccount.ServiceAccounts)

	// Collect errors from goroutines
	var accumulationErrors []error

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

	resultsByServiceIndex := make(map[types.ServiceIndex]AccumulationStateComponents)

	newServiceIndexCollisionDetected := false

	for _, sIndex := range serviceIndicesWithPrivileged {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()
			components, transfers, preimageResult, gasUsed, provisions, err := SingleServiceAccumulation(
				batch,
				accumulationStateComponents,
				timeslot,
				workReports,
				freeAccumulationServices,
				sIndex,
				posteriorEntropyAccumulator,
			)
			if err != nil {
				mu.Lock()
				accumulationErrors = append(accumulationErrors, err)
				mu.Unlock()
				return
			}
			mu.Lock()

			resultsByServiceIndex[sIndex] = components
			if _, exists := originalServiceIndicesMap[sIndex]; exists {

				if preimageResult != nil {
					accumulationOutputPairings[BEEFYCommitment{
						ServiceIndex:   sIndex,
						PreimageResult: *preimageResult,
					}] = struct{}{}
				}

				// Record gas usage
				serviceGasUsage = append(serviceGasUsage, struct {
					ServiceIndex types.ServiceIndex
					GasUsed      types.GasValue
				}{
					ServiceIndex: sIndex,
					GasUsed:      gasUsed,
				})

				// Store preimage provisions
				for k, v := range provisions {
					allPreimageProvisions[k] = v
				}

				// Store transfers by service index
				transfersByServiceIndex[sIndex] = transfers

				// Add relevant service accounts to n
				for serviceIndex, serviceAccount := range components.ServiceAccounts {
					_, ok := accumulationStateComponents.ServiceAccounts[serviceIndex]
					if serviceIndex == sIndex || !ok {
						n[serviceIndex] = serviceAccount
					}
				}

				// For each original key, check if it's missing in this result
				// If missing, add it to m (the union of missing keys)
				for origKey := range originalKeys {
					if _, exists := components.ServiceAccounts[origKey]; !exists {
						m[origKey] = struct{}{}
					}
				}
			}

			mu.Unlock()
		}(sIndex)
	}
	wg.Wait()

	// Process special service results after all parallel work is complete

	// Process manager result - ensure it exists before using
	managerResult := resultsByServiceIndex[managerServiceIndex]

	// Process designate service
	posteriorUpcomingValidatorKeysets := resultsByServiceIndex[designateServiceIndex].UpcomingValidatorKeysets

	// Process assign services
	var posteriorAuthorizersQueue [constants.NumCores][constants.AuthorizerQueueLength][32]byte
	for coreIndex, assignServiceIndex := range assignServiceIndices {
		posteriorAuthorizersQueue[coreIndex] = resultsByServiceIndex[assignServiceIndex].AuthorizersQueue[coreIndex]
	}

	// Check if any errors occurred during accumulation
	if len(accumulationErrors) > 0 {
		return AccumulationStateComponents{}, nil, nil, nil, accumulationErrors[0]
	}

	if newServiceIndexCollisionDetected {
		return AccumulationStateComponents{}, nil, nil, nil, errors.ProtocolErrorf("new service index collision detected")
	}

	// Now process manager service
	posteriorPrivilegedServices, err := ResolveManagerAccumulationResultPrivilegedServices(
		batch,
		accumulationStateComponents,
		timeslot,
		workReports,
		freeAccumulationServices,
		managerResult.PrivilegedServices,
		posteriorEntropyAccumulator,
		resultsByServiceIndex, // Pass existing results
	)

	if err != nil {
		return AccumulationStateComponents{}, nil, nil, nil, err
	}

	// Now combine the deferred transfers in service index order
	deferredTransfers := make([]DeferredTransfer, 0)
	for _, sIndex := range serviceIndicesWithPrivileged {
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
		if err := serviceAccount.SetPreimageLookupHistoricalStatus(batch, uint32(len(blob)), preimage, []types.Timeslot{timeslot}); err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
		if err := serviceAccount.SetPreimageForHash(batch, preimage, blob); err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
	}

	return AccumulationStateComponents{
		ServiceAccounts:          finalServiceAccounts,
		UpcomingValidatorKeysets: posteriorUpcomingValidatorKeysets,
		AuthorizersQueue:         posteriorAuthorizersQueue,
		PrivilegedServices:       posteriorPrivilegedServices,
	}, deferredTransfers, accumulationOutputPairings, serviceGasUsage, nil
}

// ResolveManagerAccumulationResultPrivilegedServices processes the privileged services based on the manager result
// and returns the updated privileged services configuration.
// This function handles the designate service and assign services in parallel.
func ResolveManagerAccumulationResultPrivilegedServices(
	batch *pebble.Batch,
	accumulationStateComponents *AccumulationStateComponents,
	timeslot types.Timeslot,
	workReports []workreport.WorkReport,
	freeAccumulationServices map[types.ServiceIndex]types.GasValue,
	managerPrivilegedServices types.PrivilegedServices,
	posteriorEntropyAccumulator [4][32]byte,
	existingResults map[types.ServiceIndex]AccumulationStateComponents, // Reuse existing results
) (types.PrivilegedServices, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Collect unique service indices to avoid redundant computation
	uniqueServiceIndices := make(map[types.ServiceIndex]struct{})
	uniqueServiceIndices[managerPrivilegedServices.DesignateServiceIndex] = struct{}{}
	for _, idx := range managerPrivilegedServices.AssignServiceIndices {
		uniqueServiceIndices[idx] = struct{}{}
	}

	// Map to store results by service index (start with existing results)
	resultsByServiceIndex := make(map[types.ServiceIndex]AccumulationStateComponents)
	for k, v := range existingResults {
		resultsByServiceIndex[k] = v
	}

	var accumulationErrors []error

	// Only process service indices that
	// 1. don't already have results
	// 2. exist in accumulation state components
	for serviceIndex := range uniqueServiceIndices {
		if _, exists := resultsByServiceIndex[serviceIndex]; !exists {
			if _, exists := accumulationStateComponents.ServiceAccounts[serviceIndex]; !exists {
				continue
			}
			wg.Add(1)
			go func(sIndex types.ServiceIndex) {
				defer wg.Done()
				result, _, _, _, _, err := SingleServiceAccumulation(
					batch,
					accumulationStateComponents,
					timeslot,
					workReports,
					freeAccumulationServices,
					sIndex,
					posteriorEntropyAccumulator,
				)
				if err != nil {
					mu.Lock()
					accumulationErrors = append(accumulationErrors, err)
					mu.Unlock()
					return
				}
				mu.Lock()
				resultsByServiceIndex[sIndex] = result
				mu.Unlock()
			}(serviceIndex)
		}
	}

	// Wait for all parallel processing to complete
	wg.Wait()

	// Extract results for designate service
	designateServiceIndex := managerPrivilegedServices.DesignateServiceIndex
	if _, exists := resultsByServiceIndex[managerPrivilegedServices.DesignateServiceIndex]; exists {
		designateServiceIndex = resultsByServiceIndex[managerPrivilegedServices.DesignateServiceIndex].PrivilegedServices.DesignateServiceIndex
	}

	// Extract results for assign service
	assignServiceIndices := managerPrivilegedServices.AssignServiceIndices
	for coreIdx, serviceIndex := range managerPrivilegedServices.AssignServiceIndices {
		assignServiceIndices[coreIdx] = resultsByServiceIndex[serviceIndex].PrivilegedServices.AssignServiceIndices[types.CoreIndex(coreIdx)]
	}

	// Check if any errors occurred during accumulation
	if len(accumulationErrors) > 0 {
		return types.PrivilegedServices{}, accumulationErrors[0]
	}

	// Return the updated privileged services configuration
	return types.PrivilegedServices{
		ManagerServiceIndex:             managerPrivilegedServices.ManagerServiceIndex,
		DesignateServiceIndex:           designateServiceIndex,
		AssignServiceIndices:            assignServiceIndices,
		AlwaysAccumulateServicesWithGas: managerPrivilegedServices.AlwaysAccumulateServicesWithGas,
	}, nil
}

func OuterAccumulation(batch *pebble.Batch, gas types.GasValue, timeslot types.Timeslot, workReports []workreport.WorkReport, accumulationStateComponents *AccumulationStateComponents, freeAccumulationServices map[types.ServiceIndex]types.GasValue, posteriorEntropyAccumulator [4][32]byte) (int, AccumulationStateComponents, []DeferredTransfer, []BEEFYCommitment, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}, error) {
	// Initialize return values
	totalProcessedReports := 0
	currentStateComponents := *accumulationStateComponents
	allDeferredTransfers := make([]DeferredTransfer, 0)
	allOutputPairings := make(map[BEEFYCommitment]struct{}, 0)
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
		newStateComponents, batchTransfers, batchPairings, batchServiceGasUsage, err := ParallelizedAccumulation(
			batch,
			&currentStateComponents,
			timeslot,
			workReports[startIdx:batchEndIdx],
			freeAccumulationServices,
			posteriorEntropyAccumulator,
		)

		if err != nil {
			return -1, AccumulationStateComponents{}, nil, nil, nil, err
		}

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
		for commitment := range batchPairings {
			allOutputPairings[commitment] = struct{}{}
		}

		// Update the count of reports processed
		totalProcessedReports += (batchEndIdx - startIdx)

		// Move to next batch
		startIdx = batchEndIdx

		// Reset free accumulation services as they should only be applied once
		freeAccumulationServices = make(map[types.ServiceIndex]types.GasValue)
	}

	// Convert back to slice and sort
	allOutputPairingsSlice := make([]BEEFYCommitment, 0, len(allOutputPairings))
	for commitment := range allOutputPairings {
		allOutputPairingsSlice = append(allOutputPairingsSlice, commitment)
	}

	sort.Slice(allOutputPairingsSlice, func(i, j int) bool {
		if allOutputPairingsSlice[i].ServiceIndex != allOutputPairingsSlice[j].ServiceIndex {
			return allOutputPairingsSlice[i].ServiceIndex < allOutputPairingsSlice[j].ServiceIndex
		}
		return bytes.Compare(allOutputPairingsSlice[i].PreimageResult[:], allOutputPairingsSlice[j].PreimageResult[:]) < 0
	})

	return totalProcessedReports, currentStateComponents, allDeferredTransfers, allOutputPairingsSlice, allServiceGasUsage, nil
}
