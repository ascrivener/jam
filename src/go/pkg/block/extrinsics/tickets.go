package extrinsics

import (
	"jam/pkg/types"
)

type Tickets []Ticket

type Ticket struct {
	EntryIndex    types.GenericNum               // r
	ValidityProof types.BandersnatchRingVRFProof // p
}
