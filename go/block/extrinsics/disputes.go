package extrinsics

import (
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
)

// todo: validate disputes
type Disputes struct {
	Verdicts []Verdict // v
	Culprits []Culprit // c
	Faults   []Fault   // f
}

func (d Disputes) ToSumOfValidJudgementsMap() map[[32]byte]int {
	m := make(map[[32]byte]int)
	for _, verdict := range d.Verdicts {
		m[verdict.WorkReportHash] = verdict.SumOfValidJudgements()
	}
	return m
}

type Verdict struct {
	WorkReportHash [32]byte                                         // r
	EpochIndex     uint32                                           // a
	Judgements     [constants.NumValidatorSafetyThreshold]Judgement // j
}

func (v Verdict) SumOfValidJudgements() int {
	sum := 0
	for _, judgement := range v.Judgements {
		if judgement.Valid {
			sum++
		}
	}
	return sum
}

type Judgement struct {
	Valid          bool                   // v
	ValidatorIndex types.ValidatorIndex   // i
	Signature      types.Ed25519Signature // s
}

type Culprit struct {
	InvalidWorkReportHash [32]byte               // r
	ValidatorKey          types.Ed25519PublicKey // k
	Signature             types.Ed25519Signature // s
}

type Fault struct {
	WorkReportHash  [32]byte               // r
	CorrectValidity bool                   // v
	ValidatorKey    types.Ed25519PublicKey // k
	Signature       types.Ed25519Signature // s
}
