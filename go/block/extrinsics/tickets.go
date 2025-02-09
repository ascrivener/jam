package extrinsics

import (
	"github.com/ascrivener/jam/types"
)

type Tickets []Ticket

type Ticket struct {
	EntryIndex    types.TicketEntryIndex
	ValidityProof types.BandersnatchRingVRFProof
}
