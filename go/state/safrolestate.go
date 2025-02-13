package state

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

type SafroleBasicState struct {
	ValidatorKeysetsPending    [constants.NumValidators]types.ValidatorKeyset // 6.7 (yk)
	EpochTicketSubmissionsRoot types.BandersnatchRingRoot                     // 6.4 (yz)
	SealingKeySequence         SealingKeySequence                             // 6.5 (ys)
	TicketAccumulator          []SealKeyTicket                                // 6.5 (ya)
}

type SealingKeySequence struct {
	SealKeyTickets   *[constants.NumTimeslotsPerEpoch]SealKeyTicket
	BandersnatchKeys *[constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey
}

func NewSealKeyTicketSeries(tickets [constants.NumTimeslotsPerEpoch]SealKeyTicket) SealingKeySequence {
	return SealingKeySequence{
		SealKeyTickets:   &tickets,
		BandersnatchKeys: nil,
	}
}

func NewBandersnatchKeysSeries(keys [constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey) SealingKeySequence {
	return SealingKeySequence{
		SealKeyTickets:   nil,
		BandersnatchKeys: &keys,
	}
}

func (e SealingKeySequence) IsSealKeyTickets() bool {
	return e.SealKeyTickets != nil
}
