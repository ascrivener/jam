package extrinsics

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/types"
)

// todo: validate Assurances 11.2.1
type Assurances []Assurance

type Assurance struct {
	ParentHash                    [32]byte // Must be equal to ParentHash field of header
	CoreAvailabilityContributions bitsequence.BitSequence
	ValidatorIndex                types.ValidatorIndex
	Signature                     types.Ed25519Signature
}
