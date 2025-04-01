package header

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

type Header struct {
	ParentHash                   [32]byte
	PriorStateRoot               [32]byte
	ExtrinsicHash                [32]byte
	TimeSlot                     types.Timeslot
	EpochMarker                  *EpochMarker
	WinningTicketsMarker         *([constants.NumTimeslotsPerEpoch]Ticket)
	OffendersMarker              []types.Ed25519PublicKey
	BandersnatchBlockAuthorIndex types.ValidatorIndex
	VRFSignature                 types.BandersnatchVRFSignature
	BlockSeal                    types.BandersnatchVRFSignature
}

type EpochMarker struct {
	CurrentEpochRandomness [32]byte
	NextEpochRandomness    [32]byte
	ValidatorKeys          [constants.NumValidators]types.BandersnatchPublicKey
}

type Ticket struct {
	VerifiablyRandomIdentifier [32]byte
	EntryIndex                 types.TicketEntryIndex
}
