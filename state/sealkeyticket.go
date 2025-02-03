package state

import "github.com/ascrivener/jam/types"

type SealKeyTicket struct {
	VerifiablyRandomIdentifier [32]byte
	EntryIndex                 types.TicketEntryIndex
}
