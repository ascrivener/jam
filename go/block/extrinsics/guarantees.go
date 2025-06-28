package extrinsics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
	"golang.org/x/crypto/blake2b"
)

// todo: validate guarantees 11.4
type Guarantees []Guarantee

// 11.26
func (g Guarantees) ReporterValidatorKeysets(posteriorEntropyAccumulator [4][32]byte, posteriorTimeSlot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, posteriorDisputes types.Disputes) map[types.Ed25519PublicKey]struct{} {

	reportersKeysets := make(map[types.Ed25519PublicKey]struct{}, 0)
	for _, guarantee := range g {
		guarantorAssignments := guarantee.GuarantorAssignments(posteriorEntropyAccumulator, posteriorTimeSlot, posteriorValidatorKeysetsActive, posteriorValidatorKeysetsPriorEpoch, posteriorDisputes)
		for _, credentials := range guarantee.Credentials {
			reportersKeysets[guarantorAssignments.ValidatorKeysets[credentials.ValidatorIndex].ToEd25519PublicKey()] = struct{}{}
		}
	}

	return reportersKeysets
}

type Guarantee struct {
	WorkReport  workreport.WorkReport
	Timeslot    types.Timeslot
	Credentials []Credential // only 2 or 3?
}

// TODO: define G and G*

type Credential struct {
	ValidatorIndex types.ValidatorIndex
	Signature      types.Ed25519Signature
}

type GuarantorAssignments struct {
	CoreIndices      [constants.NumValidators]types.CoreIndex
	ValidatorKeysets [constants.NumValidators]types.ValidatorKeyset
}

// x
func (g Guarantees) RefinementContexts() []workreport.RefinementContext {
	contexts := make([]workreport.RefinementContext, 0)
	for _, guarantee := range g {
		contexts = append(contexts, guarantee.WorkReport.RefinementContext)
	}
	return contexts
}

// p
func (g Guarantees) WorkPackageHashes() map[[32]byte]struct{} {
	hashes := make(map[[32]byte]struct{}, 0)
	for _, guarantee := range g {
		hashes[guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash] = struct{}{}
	}
	return hashes
}

func (g Guarantee) GuarantorAssignments(posteriorEntropyAccumulator [4][32]byte, posteriorTimeSlot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets, posteriorDisputes types.Disputes) GuarantorAssignments {
	if posteriorTimeSlot.CoreAssignmentRotationIndex() == g.Timeslot.CoreAssignmentRotationIndex() {
		coreIndices := permute(posteriorEntropyAccumulator[2], posteriorTimeSlot)
		validatorKeysets := posteriorValidatorKeysetsActive.KeyNullifier(posteriorDisputes)
		return GuarantorAssignments{
			CoreIndices:      coreIndices,
			ValidatorKeysets: validatorKeysets,
		}
	} else {
		var keySets types.ValidatorKeysets
		var entropy [32]byte
		if (posteriorTimeSlot-types.Timeslot(constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots))/types.Timeslot(constants.NumTimeslotsPerEpoch) == posteriorTimeSlot/types.Timeslot(constants.NumTimeslotsPerEpoch) {
			keySets = posteriorValidatorKeysetsActive
			entropy = posteriorEntropyAccumulator[2]
		} else {
			keySets = posteriorValidatorKeysetsPriorEpoch
			entropy = posteriorEntropyAccumulator[3]
		}
		coreIndices := permute(entropy, posteriorTimeSlot-types.Timeslot(constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots))
		validatorKeysets := keySets.KeyNullifier(posteriorDisputes)
		return GuarantorAssignments{
			CoreIndices:      coreIndices,
			ValidatorKeysets: validatorKeysets,
		}
	}
}

func permute(entropy [32]byte, timeslot types.Timeslot) [constants.NumValidators]types.CoreIndex {
	result := [constants.NumValidators]types.CoreIndex{}
	for validatorIndex := range constants.NumValidators {
		d := (constants.NumCores * validatorIndex) / constants.NumValidators
		result[validatorIndex] = types.CoreIndex(d)
	}

	shuffled := FisherYatesShuffleFromHash(result[:], entropy)

	timeslotsPerEpoch := types.Timeslot(constants.NumTimeslotsPerEpoch)
	rotationPeriod := types.Timeslot(constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots)
	numCores := types.Timeslot(constants.NumCores)

	shift := (timeslot % timeslotsPerEpoch) / rotationPeriod
	for i := range shuffled {
		shuffled[i] = types.CoreIndex((types.Timeslot(shuffled[i]) + shift) % numCores)
	}

	var shuffledArray [constants.NumValidators]types.CoreIndex
	copy(shuffledArray[:], shuffled)

	return shuffledArray
}

func fisherYatesShuffle[T any](s []T, nums []uint32) []T {
	if len(nums) < len(s) {
		panic("not enough numbers")
	}

	result := make([]T, 0, len(s))

	for i := range s {
		if len(s) == 0 {
			break
		}
		index := nums[i] % uint32(len(s))
		result = append(result, s[index])
		s[index] = s[len(s)-1]
		s = s[:len(s)-1]
	}

	return result
}

func sequenceFromHash(hash [32]byte, l int) []uint32 {
	result := make([]uint32, l)
	for i := range result {
		h := blake2b.Sum256(append(hash[:], serializer.EncodeLittleEndian(4, uint64(i/8))...))
		idx := (4 * i) % 32
		result[i] = uint32(serializer.DecodeLittleEndian(h[idx : idx+4]))
	}
	return result
}

func FisherYatesShuffleFromHash[T any](s []T, hash [32]byte) []T {
	return fisherYatesShuffle(s, sequenceFromHash(hash, len(s)))
}
