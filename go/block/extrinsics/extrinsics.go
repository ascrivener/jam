package extrinsics

import (
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
	"golang.org/x/crypto/blake2b"
)

type Extrinsics struct {
	Tickets    Tickets    // T // 6.29
	Preimages  Preimages  // P
	Guarantees Guarantees // G 11.4
	Assurances Assurances // A
	Disputes   Disputes   // D
}

func (e *Extrinsics) MerkleCommitment() [32]byte {
	hashedExtrinsics := make([]byte, 0)
	hashedTickets := blake2b.Sum256(serializer.Serialize(e.Tickets))
	hashedExtrinsics = append(hashedExtrinsics, hashedTickets[:]...)
	hashedPreimages := blake2b.Sum256(serializer.Serialize(e.Preimages))
	hashedExtrinsics = append(hashedExtrinsics, hashedPreimages[:]...)
	type GuaranteeWithHashedWorkReport struct {
		HashedWorkReport [32]byte
		Timeslot         types.Timeslot
		Credentials      []Credential
	}

	guaranteesWithHashedWorkReport := make([]GuaranteeWithHashedWorkReport, 0)
	for _, guarantee := range e.Guarantees {
		hashedWorkReport := blake2b.Sum256(serializer.Serialize(guarantee.WorkReport))
		guaranteesWithHashedWorkReport = append(
			guaranteesWithHashedWorkReport,
			GuaranteeWithHashedWorkReport{
				HashedWorkReport: hashedWorkReport,
				Timeslot:         guarantee.Timeslot,
				Credentials:      guarantee.Credentials,
			},
		)
	}

	hashedGuarantees := blake2b.Sum256(serializer.Serialize(guaranteesWithHashedWorkReport))
	hashedExtrinsics = append(hashedExtrinsics, hashedGuarantees[:]...)
	hashedAssurances := blake2b.Sum256(serializer.Serialize(e.Assurances))
	hashedExtrinsics = append(hashedExtrinsics, hashedAssurances[:]...)
	hashedDisputes := blake2b.Sum256(serializer.Serialize(e.Disputes))
	hashedExtrinsics = append(hashedExtrinsics, hashedDisputes[:]...)

	return blake2b.Sum256(hashedExtrinsics)
}
