package types

import (
	"fmt"

	"jam/pkg/constants"
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

func (t Timeslot) CoreAssignmentRotationIndex() uint32 {
	return uint32(t) / uint32(constants.ValidatorCoreAssignmentsRotationPeriodInTimeslots)
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
	ExecutionErrorBadExports
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
	ManagerServiceIndex             ServiceIndex                     // m
	AssignServiceIndices            [constants.NumCores]ServiceIndex // a
	DesignateServiceIndex           ServiceIndex                     // v
	RegistrarServiceIndex           ServiceIndex                     // r
	AlwaysAccumulateServicesWithGas map[ServiceIndex]GasValue        // z
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

type Register uint64

const MaxRegister Register = (1 << 64) - 1

type OperandTuple struct { // U
	WorkPackageHash       [32]byte            // p
	SegmentRoot           [32]byte            // e
	AuthorizerHash        [32]byte            // a
	WorkResultPayloadHash [32]byte            // y
	GasLimit              GenericNum          // g
	ExecutionExitReason   ExecutionExitReason // l
	WorkReportOutput      []byte              // t
}

type DeferredTransfer struct { // X
	SenderServiceIndex   ServiceIndex                     // s
	ReceiverServiceIndex ServiceIndex                     // d
	BalanceTransfer      Balance                          // a
	Memo                 [constants.TransferMemoSize]byte // m
	GasLimit             GasValue                         // g
}

// DeepCopy creates a deep copy of DeferredTransfer
func (t DeferredTransfer) DeepCopy() DeferredTransfer {
	// Create a new instance with all fields copied
	return DeferredTransfer{
		SenderServiceIndex:   t.SenderServiceIndex,
		ReceiverServiceIndex: t.ReceiverServiceIndex,
		BalanceTransfer:      t.BalanceTransfer,
		Memo:                 t.Memo,
		GasLimit:             t.GasLimit,
	}
}

type AccumulationInput struct { // I
	OperandTuple     *OperandTuple
	DeferredTransfer *DeferredTransfer
}

func NewAccumulationInputFromOperandTuple(operand OperandTuple) AccumulationInput {
	return AccumulationInput{
		OperandTuple: &operand,
	}
}

func NewAccumulationInputFromDeferredTransfer(transfer DeferredTransfer) AccumulationInput {
	return AccumulationInput{
		DeferredTransfer: &transfer,
	}
}

func (u AccumulationInput) IsOperandTuple() bool {
	return u.OperandTuple != nil
}

func (u AccumulationInput) IsDeferredTransfer() bool {
	return u.DeferredTransfer != nil
}

func (u AccumulationInput) GetOperandTuple() *OperandTuple {
	if u.IsOperandTuple() {
		return u.OperandTuple
	}
	return nil
}

func (u AccumulationInput) GetDeferredTransfer() *DeferredTransfer {
	if u.IsDeferredTransfer() {
		return u.DeferredTransfer
	}
	return nil
}
