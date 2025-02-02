package header

import (
	"errors"
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

type Header struct {
	ParentHash                   [32]byte
	PriorStateRoot               [32]byte
	ExtrinsicHash                [32]byte
	TimeSlotIndex                uint32
	EpochMarker                  *EpochMarker
	WinningTicketsMarker         *([constants.NumTimeslotsPerEpoch]Ticket)
	OffendersMarker              OffendersMarker
	BandersnatchBlockAuthorIndex types.ValidatorIndex
	VRFSignature                 types.BandersnatchSignature
	BlockSeal                    types.BandersnatchSignature
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

type OffendersMarker [](types.Ed25519PublicKey)

func NewOffendersMarker(elements ...types.Ed25519PublicKey) (OffendersMarker, error) {
	if len(elements) > constants.NumValidators {
		return nil, fmt.Errorf("exceeds maximum allowed length of %d", constants.NumValidators)
	}
	return elements, nil
}

func (arr *OffendersMarker) Append(element types.Ed25519PublicKey) error {
	if len(*arr) >= constants.NumValidators {
		return errors.New("cannot append, maximum length reached")
	}
	*arr = append(*arr, element)
	return nil
}
