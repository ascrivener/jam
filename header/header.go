package header

import (
	"errors"
	"fmt"

	"github.com/ascrivener/jam/constants"
)

type Header struct {
	ParentHash                   [32]byte
	PriorStateRoot               [32]byte
	ExtrinsicHash                [32]byte
	TimeSlotIndex                uint32
	EpochMarker                  *EpochMarker
	WinningTicketsMarker         *([constants.NumEpochTimeslots]Ticket)
	OffendersMarker              OffendersMarker
	BandersnatchBlockAuthorIndex constants.ValidatorIndex
	VRFSignature                 [32]byte
	BlockSeal                    [32]byte
}

type EpochMarker struct {
	CurrentEpochRandomness    [32]byte
	NextEpochRandomness       [32]byte
	BandersnatchValidatorKeys *[constants.NumValidators][32]byte
}

type Ticket struct {
	VerifiablyRandomIdentifier [32]byte
	EntryIndex                 constants.TicketEntryIndex
}

type OffendersMarker []([32]byte)

func NewOffendersMarker(elements ...[32]byte) (OffendersMarker, error) {
	if len(elements) > constants.NumValidators {
		return nil, fmt.Errorf("exceeds maximum allowed length of %d", constants.NumValidators)
	}
	return elements, nil
}

func (arr *OffendersMarker) Append(element [32]byte) error {
	if len(*arr) >= constants.NumValidators {
		return errors.New("cannot append, maximum length reached")
	}
	*arr = append(*arr, element)
	return nil
}
