package header

import (
	"jam/pkg/constants"
	"jam/pkg/serializer"
	"jam/pkg/ticket"
	"jam/pkg/types"

	"golang.org/x/crypto/blake2b"
)

// UnsignedHeader contains all header fields except the BlockSeal
type UnsignedHeader struct {
	ParentHash                   [32]byte                                         // p
	PriorStateRoot               [32]byte                                         // r
	ExtrinsicHash                [32]byte                                         // x
	TimeSlot                     types.Timeslot                                   // t
	EpochMarker                  *EpochMarker                                     // e
	WinningTicketsMarker         *([constants.NumTimeslotsPerEpoch]ticket.Ticket) // w
	BandersnatchBlockAuthorIndex types.ValidatorIndex                             // i
	VRFSignature                 types.BandersnatchVRFSignature                   // v
	OffendersMarker              []types.Ed25519PublicKey                         // o
}

type Header struct {
	UnsignedHeader
	BlockSeal types.BandersnatchVRFSignature // s
}

func (h Header) Hash() [32]byte {
	return blake2b.Sum256(serializer.Serialize(&h))
}

type EpochMarker struct {
	CurrentEpochRandomness [32]byte
	TicketsRandomness      [32]byte
	ValidatorKeys          [constants.NumValidators]struct {
		types.BandersnatchPublicKey
		types.Ed25519PublicKey
	}
}
