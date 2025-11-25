package extrinsics

import (
	"jam/pkg/types"
)

type Tickets []Ticket

type Ticket struct {
	EntryIndex    uint8                          // r
	ValidityProof types.BandersnatchRingVRFProof // p
}
