package extrinsics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

// todo: validate guarantees 11.4
type Guarantees []Guarantee

func (g Guarantees) ReporterValidatorIndices(validatorKeySets [constants.NumValidators]types.ValidatorKeyset) []types.ValidatorKeyset {
	fix me //11.26
	reportersKeysets := make([]types.ValidatorKeyset, 0)
	for _, guarantee := range g {
		for _, credentials := range guarantee.Credentials {
			reportersKeysets = append(reportersKeysets, validatorKeySets[credentials.ValidatorIndex])
		}
	}
	return reportersKeysets
}

type Guarantee struct {
	WorkReport  workreport.WorkReport
	Timeslot    types.Timeslot
	Credentials []Credential // only 2 or 3?
}

type Credential struct {
	ValidatorIndex types.ValidatorIndex
	Signature      types.Ed25519Signature
}
