package asntypes

// Public key types
type BandersnatchPublic string
type Ed25519Public string
type BlsPublic string

// Signature types
type BandersnatchVrfSignature string
type BandersnatchRingVrfSignature string
type Ed25519Signature string

// Commitment types
type BandersnatchRingCommitment string

// ValidatorMetadata - using ByteSequence since it's a variable-length blob
type ValidatorMetadata string

// ValidatorData - struct containing validator public keys and metadata
type ValidatorData struct {
	Bandersnatch BandersnatchPublic `json:"bandersnatch" asn1:"tag:0"`
	Ed25519      Ed25519Public      `json:"ed25519" asn1:"tag:1"`
	Bls          BlsPublic          `json:"bls" asn1:"tag:2"`
	Metadata     ValidatorMetadata  `json:"metadata" asn1:"tag:3"`
}

// ValidatorsData - sequence of validator data
type ValidatorsData []ValidatorData
