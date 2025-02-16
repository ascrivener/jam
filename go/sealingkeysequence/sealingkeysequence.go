package sealingkeysequence

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/ticket"
	"github.com/ascrivener/jam/types"
)

type SealingKeySequence struct {
	SealKeyTickets   *[constants.NumTimeslotsPerEpoch]ticket.Ticket
	BandersnatchKeys *[constants.NumTimeslotsPerEpoch]types.BandersnatchPublicKey
}

func NewSealKeyTicketSeries(tickets [constants.NumTimeslotsPerEpoch]ticket.Ticket) SealingKeySequence {
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
