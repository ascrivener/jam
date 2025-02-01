package constants

import "fmt"

const NumValidators = 1023

type ValidatorIndex uint16

func NewValidatorIndex(value uint16) (ValidatorIndex, error) {
	if value >= NumValidators {
		return 0, fmt.Errorf("invalid validator index value: must be less than %d", NumValidators)
	}
	return ValidatorIndex(value), nil
}

const NumTicketEntries = 2

type TicketEntryIndex uint8

func NewTicketEntryIndex(value uint8) (TicketEntryIndex, error) {
	if value >= NumTicketEntries {
		return 0, fmt.Errorf("invalid ticket entry index value: must be less than %d", NumTicketEntries)
	}
	return TicketEntryIndex(value), nil
}

const NumEpochTimeslots = 600
