package asntypes

// AvailabilityAssignments represents assignments for availability
type AvailabilityAssignments []*AssignmentEntry

type AssignmentEntry struct {
	WorkReport WorkReport `json:"report" asn1:"tag:0"`
	Timeout    TimeSlot   `json:"timeout" asn1:"tag:1"`
}

// AssurancesInput represents the input for assurances test vectors
type AssurancesInput struct {
	Assurances AssurancesExtrinsic `json:"assurances" asn1:"tag:0"`
	Slot       TimeSlot            `json:"slot" asn1:"tag:1"`
	Parent     HeaderHash          `json:"parent" asn1:"tag:2"`
}

// AssurancesExtrinsic represents a sequence of AvailAssurance
type AssurancesExtrinsic []AvailAssurance

// AvailAssurance represents an individual availability assurance
type AvailAssurance struct {
	Anchor         OpaqueHash       `json:"anchor" asn1:"tag:0"`
	Bitfield       ByteSequence     `json:"bitfield" asn1:"tag:1"`
	ValidatorIndex U32              `json:"validator_index" asn1:"tag:2"`
	Signature      Ed25519Signature `json:"signature" asn1:"tag:3"`
}

// AssurancesErrorCode represents error codes for assurances
type AssurancesErrorCode int

const (
	BadAttestationParent      AssurancesErrorCode = 0
	BadValidatorIndex         AssurancesErrorCode = 1
	CoreNotEngaged            AssurancesErrorCode = 2
	BadSignature              AssurancesErrorCode = 3
	NotSortedOrUniqueAssurers AssurancesErrorCode = 4
)

// AssurancesOutputData represents the successful output data
type AssurancesOutputData struct {
	Reported []WorkReport `json:"reported" asn1:"tag:0"`
}

// AssurancesOutput represents the output for assurances
type AssurancesOutput struct {
	OK  *AssurancesOutputData `json:"ok,omitempty" asn1:"tag:0,optional"`
	Err string                `json:"err,omitempty" asn1:"tag:1,optional"`
}

type AssurancesState struct {
	AvailAssignments AvailabilityAssignments `json:"avail_assignments" asn1:"tag:0"`
	CurrValidators   ValidatorsData          `json:"curr_validators" asn1:"tag:1"`
}

// AssurancesTestCase represents a complete test case for assurances
type AssurancesTestCase struct {
	Input     AssurancesInput  `json:"input" asn1:"tag:0"`
	PreState  AssurancesState  `json:"pre_state" asn1:"tag:1"`
	Output    AssurancesOutput `json:"output" asn1:"tag:2"`
	PostState AssurancesState  `json:"post_state" asn1:"tag:3"`
}
