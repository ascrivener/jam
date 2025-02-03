package types

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
)

type Ed25519PublicKey [32]byte

type BandersnatchPublicKey [32]byte

type BandersnatchSignature [64]byte

type BandersnatchRingVRFProof [784]byte

type BandersnatchRingRoot [144]byte

type Ed25519Signature [64]byte

type Timeslot uint32

type ValidatorIndex uint16

func NewValidatorIndex(value uint16) (ValidatorIndex, error) {
	if value >= constants.NumValidators {
		return 0, fmt.Errorf("invalid validator index value: must be less than %d", constants.NumValidators)
	}
	return ValidatorIndex(value), nil
}

type TicketEntryIndex uint8

func NewTicketEntryIndex(value uint8) (TicketEntryIndex, error) {
	if value >= constants.NumTicketEntries {
		return 0, fmt.Errorf("invalid ticket entry index value: must be less than %d", constants.NumTicketEntries)
	}
	return TicketEntryIndex(value), nil
}

type BlobLength uint32

type CoreIndex uint16

func NewCoreIndex(value uint16) (CoreIndex, error) {
	if value >= constants.NumCores {
		return 0, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return CoreIndex(value), nil
}

type ServiceIndex uint32

type GasValue int64

type ValidatorKeyset [336]byte

type Balance uint64
