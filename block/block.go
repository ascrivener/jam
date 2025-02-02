package block

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/header"
	"github.com/ascrivener/jam/types"
)

type Block struct {
	Header     header.Header
	Extrinsics Extrinsics
}

type Extrinsics struct {
	Tickets      int
	Preimages    int
	Reports      int
	Availability int
	Disputes     Disputes
}

// todo: validate disputes
type Disputes struct {
	Verdicts []Verdict
	Culprits []Culprit
	Faults   []Fault
}

type Verdict struct {
	ReportHash [32]byte
	EpochIndex uint64 // TODO: must be epoch index of the prior state or 1 less
	Judgements [constants.NumValidatorSafetyThreshold]Judgement
}

type Judgement struct {
	Valid          bool
	ValidatorIndex types.ValidatorIndex
	Signature      types.Ed25519Signature
}

type Culprit struct {
	IncorrectWorkReport [32]byte
	ValidatorKey        types.Ed25519PublicKey
	Signature           types.Ed25519Signature
}

type Fault struct {
	WorkReport        [32]byte
	IncorrectValidity bool
	ValidatorKey      types.Ed25519PublicKey
	Signature         types.Ed25519Signature
}
