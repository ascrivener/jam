package header

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

type Header struct {
	ParentHash                   [32]byte                                  // p
	PriorStateRoot               [32]byte                                  // r
	ExtrinsicHash                [32]byte                                  // x
	TimeSlot                     types.Timeslot                            // t
	EpochMarker                  *EpochMarker                              // e
	WinningTicketsMarker         *([constants.NumTimeslotsPerEpoch]Ticket) // w
	OffendersMarker              []types.Ed25519PublicKey                  // o
	BandersnatchBlockAuthorIndex types.ValidatorIndex                      // i
	VRFSignature                 types.BandersnatchVRFSignature            // v
	BlockSeal                    types.BandersnatchVRFSignature            // s
}

func (h Header) SerializeUnsigned() []byte {
	serialized := serializer.Serialize(h)
	return serialized[:len(serialized)-len(h.BlockSeal)]
}

type EpochMarker struct {
	CurrentEpochRandomness [32]byte
	TicketsRandomness      [32]byte
	ValidatorKeys          [constants.NumValidators]struct {
		types.BandersnatchPublicKey
		types.Ed25519PublicKey
	}
}

type Ticket struct {
	VerifiablyRandomIdentifier [32]byte
	EntryIndex                 types.TicketEntryIndex
}
