package extrinsics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

// todo: validate disputes
type Disputes struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	WorkReportHash [32]byte
	EpochIndex     uint64 // TODO: must be epoch index of the prior state or 1 less
	Judgements     [constants.NumValidatorSafetyThreshold]Judgement
}

type Judgement struct {
	Valid          bool
	ValidatorIndex types.ValidatorIndex
	Signature      types.Ed25519Signature
}

type Culprit struct {
	InvalidWorkReportHash [32]byte
	ValidatorKey          types.Ed25519PublicKey
	Signature             types.Ed25519Signature
}

type Fault struct {
	WorkReportHash    [32]byte
	IncorrectValidity bool
	ValidatorKey      types.Ed25519PublicKey
	Signature         types.Ed25519Signature
}
