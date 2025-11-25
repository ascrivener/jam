package pvm

import (
	"bytes"
	"sort"
	"sync"

	"jam/pkg/constants"
	"jam/pkg/serviceaccount"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"jam/pkg/workreport"

	"golang.org/x/crypto/blake2b"
)

func SingleServiceAccumulation(tx *staterepository.TrackedTx, accumulationStateComponents *AccumulationStateComponents, deferredTransfers []types.DeferredTransfer, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, serviceIndex types.ServiceIndex, timeslot types.Timeslot, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []types.DeferredTransfer, *[32]byte, types.GasValue, PreimageProvisions, error) {
	var gas types.GasValue
	if g, ok := freeAccumulationServices[serviceIndex]; ok {
		gas = g
	}
	accumulationInputs := make([]types.AccumulationInput, 0)
	for _, transfer := range deferredTransfers {
		if transfer.ReceiverServiceIndex == serviceIndex {
			gas += transfer.GasLimit
			accumulationInputs = append(accumulationInputs, types.NewAccumulationInputFromDeferredTransfer(transfer))
		}
	}
	for _, report := range workReports {
		for _, workDigest := range report.WorkDigests {
			if workDigest.ServiceIndex == serviceIndex {
				gas += workDigest.AccumulateGasLimit
				accumulationInputs = append(accumulationInputs, types.NewAccumulationInputFromOperandTuple(types.OperandTuple{
					WorkPackageHash:       report.WorkPackageSpecification.WorkPackageHash,
					SegmentRoot:           report.WorkPackageSpecification.SegmentRoot,
					AuthorizerHash:        report.AuthorizerHash,
					WorkReportOutput:      report.Output,
					WorkResultPayloadHash: workDigest.PayloadHash,
					GasLimit:              types.GenericNum(workDigest.AccumulateGasLimit),
					ExecutionExitReason:   workDigest.WorkResult,
				}))
			}
		}
	}
	return Accumulate(tx, accumulationStateComponents, timeslot, serviceIndex, gas, accumulationInputs, posteriorEntropyAccumulator)
}

type BEEFYCommitment struct {
	ServiceIndex   types.ServiceIndex
	PreimageResult [32]byte
}

func ParallelizedAccumulation(tx *staterepository.TrackedTx, accumulationStateComponents *AccumulationStateComponents, deferredTransfers []types.DeferredTransfer, workReports []workreport.WorkReport, freeAccumulationServices map[types.ServiceIndex]types.GasValue, timeslot types.Timeslot, posteriorEntropyAccumulator [4][32]byte) (AccumulationStateComponents, []types.DeferredTransfer, map[BEEFYCommitment]struct{}, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}, error) {
	// Use a map to collect unique service indices to process
	baseServiceIndices := make(map[types.ServiceIndex]struct{})

	// Add regular service indices
	for idx := range freeAccumulationServices {
		baseServiceIndices[idx] = struct{}{}
	}
	for _, report := range workReports {
		for _, workDigest := range report.WorkDigests {
			baseServiceIndices[workDigest.ServiceIndex] = struct{}{}
		}
	}
	for _, transfer := range deferredTransfers {
		baseServiceIndices[transfer.ReceiverServiceIndex] = struct{}{}
	}

	// Add privileged service indices
	// Convert map keys to a slice for deterministic processing order
	allServiceIndices := make(map[types.ServiceIndex]struct{}, len(baseServiceIndices))
	for idx := range baseServiceIndices {
		allServiceIndices[idx] = struct{}{}
	}
	allServiceIndices[accumulationStateComponents.PrivilegedServices.ManagerServiceIndex] = struct{}{}
	for _, idx := range accumulationStateComponents.PrivilegedServices.AssignServiceIndices {
		allServiceIndices[idx] = struct{}{}
	}
	allServiceIndices[accumulationStateComponents.PrivilegedServices.DesignateServiceIndex] = struct{}{}
	allServiceIndices[accumulationStateComponents.PrivilegedServices.RegistrarServiceIndex] = struct{}{}

	var wg sync.WaitGroup
	var mu sync.Mutex
	serviceGasUsage := make([]struct {
		ServiceIndex types.ServiceIndex
		GasUsed      types.GasValue
	}, 0)
	accumulationOutputPairings := make(map[BEEFYCommitment]struct{})

	// Collect errors from goroutines
	var accumulationErrors []error

	// Map to store deferred transfers by service index
	allTransfers := make([]struct {
		ServiceIndex types.ServiceIndex
		Transfers    []types.DeferredTransfer
	}, 0)

	// Map to store preimage provisions by service index
	allPreimageProvisions := make(PreimageProvisions)

	resultsByServiceIndex := make(map[types.ServiceIndex]AccumulationStateComponents)

	var childTransactions []*staterepository.TrackedTx
	var childTxMutex sync.Mutex

	for sIndex := range allServiceIndices {
		wg.Add(1)
		go func(sIndex types.ServiceIndex) {
			defer wg.Done()

			// Create child transaction for this goroutine
			childTx := tx.CreateChild()

			// Store child transaction for later merging
			childTxMutex.Lock()
			childTransactions = append(childTransactions, childTx)
			childTxMutex.Unlock()

			components, transfers, preimageResult, gasUsed, provisions, err := SingleServiceAccumulation(
				childTx, // Use child transaction instead of parent
				accumulationStateComponents,
				deferredTransfers,
				workReports,
				freeAccumulationServices,
				sIndex,
				timeslot,
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
			if _, exists := baseServiceIndices[sIndex]; exists {

				// Record gas usage
				serviceGasUsage = append(serviceGasUsage, struct {
					ServiceIndex types.ServiceIndex
					GasUsed      types.GasValue
				}{
					ServiceIndex: sIndex,
					GasUsed:      gasUsed,
				})

				if preimageResult != nil {
					accumulationOutputPairings[BEEFYCommitment{
						ServiceIndex:   sIndex,
						PreimageResult: *preimageResult,
					}] = struct{}{}
				}

				// Store preimage provisions
				for k, v := range provisions {
					allPreimageProvisions[k] = v
				}

				// Store transfers by service index
				allTransfers = append(allTransfers, struct {
					ServiceIndex types.ServiceIndex
					Transfers    []types.DeferredTransfer
				}{
					ServiceIndex: sIndex,
					Transfers:    transfers,
				})

			}

			mu.Unlock()
		}(sIndex)
	}
	wg.Wait()

	// Check if any errors occurred during accumulation
	if len(accumulationErrors) > 0 {
		return AccumulationStateComponents{}, nil, nil, nil, accumulationErrors[0]
	}

	// Merge all child transactions back into parent after concurrent processing
	for _, childTx := range childTransactions {
		if err := tx.Apply(childTx); err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
	}

	// sort service gas usage by service index
	sort.Slice(serviceGasUsage, func(i, j int) bool {
		return serviceGasUsage[i].ServiceIndex < serviceGasUsage[j].ServiceIndex
	})

	// sort all transfers by service index and then flatten
	sort.Slice(allTransfers, func(i, j int) bool {
		return allTransfers[i].ServiceIndex < allTransfers[j].ServiceIndex
	})
	allTransfersOrdered := make([]types.DeferredTransfer, 0)
	for _, transfer := range allTransfers {
		allTransfersOrdered = append(allTransfersOrdered, transfer.Transfers...)
	}

	managerResult := resultsByServiceIndex[accumulationStateComponents.PrivilegedServices.ManagerServiceIndex]

	designateServiceResult := resultsByServiceIndex[accumulationStateComponents.PrivilegedServices.DesignateServiceIndex]

	// Process designate service
	posteriorDesignateServiceIndex := R(accumulationStateComponents.PrivilegedServices.DesignateServiceIndex, managerResult.PrivilegedServices.DesignateServiceIndex, designateServiceResult.PrivilegedServices.DesignateServiceIndex)

	var posteriorAssignServiceIndices [constants.NumCores]types.ServiceIndex
	posteriorAuthorizersQueue := [constants.NumCores][constants.AuthorizerQueueLength][32]byte{}
	for coreIndex := range posteriorAssignServiceIndices {
		// Process assign services
		assignServiceIndex := accumulationStateComponents.PrivilegedServices.AssignServiceIndices[types.CoreIndex(coreIndex)]
		assignServiceResult := resultsByServiceIndex[assignServiceIndex]
		posteriorAssignServiceIndices[coreIndex] = R(assignServiceIndex, managerResult.PrivilegedServices.AssignServiceIndices[types.CoreIndex(coreIndex)], assignServiceResult.PrivilegedServices.AssignServiceIndices[types.CoreIndex(coreIndex)])

		// Process authorizers queue
		posteriorAuthorizersQueue[coreIndex] = assignServiceResult.AuthorizersQueue[coreIndex]
	}

	// Process registrar service
	registrarServiceResult := resultsByServiceIndex[accumulationStateComponents.PrivilegedServices.RegistrarServiceIndex]
	posteriorRegistrarServiceIndex := R(accumulationStateComponents.PrivilegedServices.RegistrarServiceIndex, managerResult.PrivilegedServices.RegistrarServiceIndex, registrarServiceResult.PrivilegedServices.RegistrarServiceIndex)

	posteriorPrivilegedServices := types.PrivilegedServices{
		ManagerServiceIndex:             managerResult.PrivilegedServices.ManagerServiceIndex,
		DesignateServiceIndex:           posteriorDesignateServiceIndex,
		AssignServiceIndices:            posteriorAssignServiceIndices,
		RegistrarServiceIndex:           posteriorRegistrarServiceIndex,
		AlwaysAccumulateServicesWithGas: managerResult.PrivilegedServices.AlwaysAccumulateServicesWithGas,
	}

	// Process designate service
	posteriorUpcomingValidatorKeysets := designateServiceResult.UpcomingValidatorKeysets

	// Provisions preimage integration done below

	for preimageProvision := range allPreimageProvisions {
		serviceAccount, exists, err := serviceaccount.GetServiceAccount(tx, preimageProvision.ServiceIndex)
		if err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
		if !exists {
			continue
		}
		blob := []byte(preimageProvision.BlobString)
		preimage := blake2b.Sum256(blob)
		preimageLookupHistoricalStatus, exists, err := serviceAccount.GetPreimageLookupHistoricalStatus(tx, uint32(len(blob)), preimage)
		if err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
		if !exists || len(preimageLookupHistoricalStatus) > 0 {
			continue
		}
		if err := serviceAccount.SetPreimageLookupHistoricalStatus(tx, uint32(len(blob)), preimage, []types.Timeslot{timeslot}); err != nil {
			return AccumulationStateComponents{}, nil, nil, nil, err
		}
		serviceAccount.SetPreimageForHash(tx, preimage, blob)
	}

	return AccumulationStateComponents{
		UpcomingValidatorKeysets: posteriorUpcomingValidatorKeysets,
		AuthorizersQueue:         posteriorAuthorizersQueue,
		PrivilegedServices:       posteriorPrivilegedServices,
	}, allTransfersOrdered, accumulationOutputPairings, serviceGasUsage, nil
}

func R(o, a, b types.ServiceIndex) types.ServiceIndex {
	if a == o {
		return b
	}
	return a
}

func OuterAccumulation(tx *staterepository.TrackedTx, gas types.GasValue, workReports []workreport.WorkReport, accumulationStateComponents *AccumulationStateComponents, freeAccumulationServices map[types.ServiceIndex]types.GasValue, timeslot types.Timeslot, posteriorEntropyAccumulator [4][32]byte) (int, AccumulationStateComponents, []BEEFYCommitment, []struct {
	ServiceIndex types.ServiceIndex
	GasUsed      types.GasValue
}, error) {
	// Initialize return values
	totalProcessedReports := 0
	currentStateComponents := *accumulationStateComponents
	allOutputPairings := make(map[BEEFYCommitment]struct{}, 0)
	allServiceGasUsage := make([]struct {
		ServiceIndex types.ServiceIndex
		GasUsed      types.GasValue
	}, 0)

	// Remaining gas for processing
	remainingGas := gas

	// Start index for the next batch of reports to process
	startIdx := 0

	deferredTransfers := make([]types.DeferredTransfer, 0)

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

		reportsProcessed := batchEndIdx - startIdx

		// If we can't process any reports, break
		if reportsProcessed+len(deferredTransfers)+len(freeAccumulationServices) == 0 {
			break
		}

		// Process this batch
		newStateComponents, newDeferredTransfers, batchPairings, batchServiceGasUsage, err := ParallelizedAccumulation(
			tx,
			&currentStateComponents,
			deferredTransfers,
			workReports[startIdx:batchEndIdx],
			freeAccumulationServices,
			timeslot,
			posteriorEntropyAccumulator,
		)

		if err != nil {
			return -1, AccumulationStateComponents{}, nil, nil, err
		}

		deferredTransfers = newDeferredTransfers

		for _, serviceGas := range batchServiceGasUsage {
			remainingGas -= serviceGas.GasUsed
		}
		currentStateComponents = newStateComponents
		allServiceGasUsage = append(allServiceGasUsage, batchServiceGasUsage...)

		// Merge the output pairings
		for commitment := range batchPairings {
			allOutputPairings[commitment] = struct{}{}
		}

		// Update the count of reports processed
		totalProcessedReports += reportsProcessed

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

	return totalProcessedReports, currentStateComponents, allOutputPairingsSlice, allServiceGasUsage, nil
}
