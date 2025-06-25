package types

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
)

type Ed25519PublicKey [32]byte

type BandersnatchPublicKey [32]byte

type BandersnatchVRFSignature [96]byte

type BandersnatchRingVRFProof [784]byte

type BandersnatchRingRoot [144]byte

type Ed25519Signature [64]byte

type Timeslot uint32

func (t Timeslot) EpochIndex() int {
	return int(t) / int(constants.NumTimeslotsPerEpoch)
}

// m
func (t Timeslot) SlotPhaseIndex() int {
	return int(t) % int(constants.NumTimeslotsPerEpoch)
}

type ValidatorIndex uint16

func NewValidatorIndex(value uint16) (ValidatorIndex, error) {
	if value >= uint16(constants.NumValidators) {
		return 0, fmt.Errorf("invalid validator index value: must be less than %d", constants.NumValidators)
	}
	return ValidatorIndex(value), nil
}

type BlobLength uint32

type CoreIndex uint16

func NewCoreIndex(value uint16) (CoreIndex, error) {
	if value >= uint16(constants.NumCores) {
		return 0, fmt.Errorf("invalid core index value: must be less than %d", constants.NumCores)
	}
	return CoreIndex(value), nil
}

type ServiceIndex uint32

type GasValue uint64

type SignedGasValue int64

type ValidatorKeyset [336]byte

// b
func (v ValidatorKeyset) ToBandersnatchPublicKey() BandersnatchPublicKey {
	return BandersnatchPublicKey(v[:32])
}

// e
func (v ValidatorKeyset) ToEd25519PublicKey() Ed25519PublicKey {
	return Ed25519PublicKey(v[32:64])
}

type ValidatorKeysets [constants.NumValidators]ValidatorKeyset

func (v ValidatorKeysets) KeyNullifier(disputes Disputes) ValidatorKeysets {
	newValidatorKeysets := ValidatorKeysets{}
	for index, keyset := range v {
		if disputes.PunishEd25519Key(keyset.ToEd25519PublicKey()) {
			newValidatorKeysets[index] = [336]byte{}
		} else {
			newValidatorKeysets[index] = keyset
		}
	}
	return newValidatorKeysets
}

type ValidatorKeysetSlice []ValidatorKeyset

func (v ValidatorKeysetSlice) ContainsKeyset(keyset ValidatorKeyset) bool {
	for _, k := range v {
		if keyset == k {
			return true
		}
	}
	return false
}

type Balance uint64

type Disputes struct {
	WorkReportHashesGood  map[[32]byte]struct{}         // g
	WorkReportHashesBad   map[[32]byte]struct{}         // b
	WorkReportHashesWonky map[[32]byte]struct{}         // w
	ValidatorPunishes     map[Ed25519PublicKey]struct{} // o
}

func (d Disputes) PunishEd25519Key(key Ed25519PublicKey) bool {
	for posteriorValidatorPunish := range d.ValidatorPunishes {
		if key == posteriorValidatorPunish {
			return true
		}
	}
	return false
}

type ExecutionErrorType int

const (
	ExecutionErrorOutOfGas ExecutionErrorType = iota + 1
	ExecutionErrorPanic
	ExecutionErrorOversize
	ExecutionErrorBAD
	ExecutionErrorBIG
)

type ExecutionExitReason struct {
	ExecutionError *ExecutionErrorType
	Blob           *[]byte
}

func NewExecutionExitReasonError(reason ExecutionErrorType) ExecutionExitReason {
	return ExecutionExitReason{
		ExecutionError: &reason,
		Blob:           nil,
	}
}

func NewExecutionExitReasonBlob(blob []byte) ExecutionExitReason {
	return ExecutionExitReason{
		ExecutionError: nil,
		Blob:           &blob,
	}
}

func (er ExecutionExitReason) IsError() bool {
	return er.ExecutionError != nil
}

type PrivilegedServices struct {
	ManagerServiceIndex             ServiceIndex              // m
	AssignServiceIndex              ServiceIndex              // a
	DesignateServiceIndex           ServiceIndex              // v
	AlwaysAccumulateServicesWithGas map[ServiceIndex]GasValue // g
}

func (p PrivilegedServices) TotalAlwaysAccumulateGas() GasValue {
	sum := GasValue(0)
	for _, gasValue := range p.AlwaysAccumulateServicesWithGas {
		sum += gasValue
	}
	return sum
}

type Blob []byte

type GenericNum uint64

type GenericGasValue uint64

type Register uint64

const MaxRegister Register = (1 << 64) - 1
