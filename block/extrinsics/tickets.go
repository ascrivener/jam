package extrinsics

import (
	"github.com/ascrivener/jam/types"
)

type Tickets []Ticket

type Ticket struct {
	TicketEntryIndex    types.TicketEntryIndex
	TicketValidityProof types.BandersnatchRingVRFProof
}
