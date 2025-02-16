package extrinsics

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

// todo: validate Assurances 11.2.1
type Assurances []Assurance

type Assurance struct {
	ParentHash                    [32]byte // Must be equal to ParentHash field of header
	CoreAvailabilityContributions bitsequence.BitSequence
	ValidatorIndex                types.ValidatorIndex
	Signature                     types.Ed25519Signature
}

func (a Assurances) HasValidatorIndex(vIndex types.ValidatorIndex) bool {
	for _, assurance := range a {
		if assurance.ValidatorIndex == vIndex {
			return true
		}
	}
	return false
}

func (a Assurances) AvailabilityContributionsForCoreSupermajority(coreIndex types.CoreIndex) bool {
	sum := 0
	for _, assurance := range a {
		if assurance.CoreAvailabilityContributions.BitAt(int(coreIndex)) {
			sum += 1
		}
	}
	return sum > constants.TwoThirdsNumValidators
}
