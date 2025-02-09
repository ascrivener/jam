package extrinsics

import (
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

// todo: validate guarantees 11.4
type Guarantees []Guarantee

type Guarantee struct {
	WorkReport  workreport.WorkReport
	Timeslot    types.Timeslot
	Credentials []Credential // only 2 or 3?
}

type Credential struct {
	ValidatorIndex types.ValidatorIndex
	Signature      types.Ed25519Signature
}
