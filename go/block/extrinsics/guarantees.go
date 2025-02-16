package extrinsics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

// todo: validate guarantees 11.4
type Guarantees []Guarantee

// 11.26
func (g Guarantees) ReporterValidatorKeysets(posteriorTimeSlot types.Timeslot, posteriorValidatorKeysetsActive types.ValidatorKeysets, posteriorValidatorKeysetsPriorEpoch types.ValidatorKeysets) types.ValidatorKeysetSlice {
	reportersKeysets := make([]types.ValidatorKeyset, 0)
	for _, guarantee := range g {
		var k types.ValidatorKeysets
		if int(posteriorTimeSlot)/constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots == int(guarantee.Timeslot)/constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots {
			//TODO: get G here instead, use second component
			k = posteriorValidatorKeysetsActive
		} else {
			//TODO: get G* here instead, use second component
			if (int(posteriorTimeSlot)-constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots)/constants.NumTimeslotsPerEpoch == int(posteriorTimeSlot)/constants.NumTimeslotsPerEpoch {
				k = posteriorValidatorKeysetsActive
			} else {
				k = posteriorValidatorKeysetsPriorEpoch
			}
		}
		for _, credentials := range guarantee.Credentials {
			reportersKeysets = append(reportersKeysets, k[credentials.ValidatorIndex])
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
