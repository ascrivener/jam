package header

import (
	"jam/pkg/constants"
	"jam/pkg/types"
)

// UnsignedHeader contains all header fields except the BlockSeal
type UnsignedHeader struct {
	ParentHash                   [32]byte                                  // p
	PriorStateRoot               [32]byte                                  // r
	ExtrinsicHash                [32]byte                                  // x
	TimeSlot                     types.Timeslot                            // t
	EpochMarker                  *EpochMarker                              // e
	WinningTicketsMarker         *([constants.NumTimeslotsPerEpoch]Ticket) // w
	OffendersMarker              []types.Ed25519PublicKey                  // o
	BandersnatchBlockAuthorIndex types.ValidatorIndex                      // i
	VRFSignature                 types.BandersnatchVRFSignature            // v
}

type Header struct {
	UnsignedHeader
	BlockSeal types.BandersnatchVRFSignature // s
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
	EntryIndex                 types.GenericNum
}
