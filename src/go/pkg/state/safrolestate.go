package state

import (
	"jam/pkg/sealingkeysequence"
	"jam/pkg/ticket"
	"jam/pkg/types"
)

type SafroleBasicState struct {
	ValidatorKeysetsPending    types.ValidatorKeysets                // 6.7 (yk)
	EpochTicketSubmissionsRoot types.BandersnatchRingRoot            // 6.4 (yz)
	SealingKeySequence         sealingkeysequence.SealingKeySequence // 6.5 (ys)
	TicketAccumulator          []ticket.Ticket                       // 6.5 (ya)
}
