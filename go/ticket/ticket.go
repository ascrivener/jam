package ticket

import "github.com/ascrivener/jam/types"

type Ticket struct {
	VerifiablyRandomIdentifier [32]byte               // y
	EntryIndex                 types.TicketEntryIndex // r
}
