package asntypes

// State represents the state of the JAM system used in test vectors
type State struct {
	Slot        U32                `json:"slot" asn1:"tag:0"`
	Entropy     Entropy            `json:"entropy" asn1:"tag:1"`
	ReadyQueue  ReadyQueue         `json:"ready_queue" asn1:"tag:2"`
	Accumulated AccumulatedQueue   `json:"accumulated" asn1:"tag:3"`
	Privileges  Privileges         `json:"privileges" asn1:"tag:4"`
	Accounts    []AccountsMapEntry `json:"accounts" asn1:"tag:5"`
}

// Privileges represents privilege settings in the state
type Privileges struct {
	Bless     U32   `json:"bless" asn1:"tag:0"`
	Assign    U32   `json:"assign" asn1:"tag:1"`
	Designate U32   `json:"designate" asn1:"tag:2"`
	AlwaysAcc []U32 `json:"always_acc" asn1:"tag:3"`
}

// AccountsMapEntry represents an entry in the accounts map
type AccountsMapEntry struct {
	ID   U32     `json:"id" asn1:"tag:0"`
	Data Account `json:"data" asn1:"tag:1"`
}

// Account represents an account in the state
type Account struct {
	Service   ServiceInfo         `json:"service" asn1:"tag:0"`
	Preimages []PreimagesMapEntry `json:"preimages" asn1:"tag:1"`
}

// PreimagesMapEntry represents an entry in the preimages map
type PreimagesMapEntry struct {
	Hash ByteArray32  `json:"hash" asn1:"tag:0"`
	Blob ByteSequence `json:"blob" asn1:"tag:1"`
}

// TestCase represents a complete test case
type TestCase struct {
	Input     Input  `json:"input" asn1:"tag:0"`
	PreState  State  `json:"pre_state" asn1:"tag:1"`
	Output    Output `json:"output" asn1:"tag:2"`
	PostState State  `json:"post_state" asn1:"tag:3"`
}

// Input represents the input to a test case
type Input struct {
	Slot    U32          `json:"slot" asn1:"tag:0"`
	Reports []WorkReport `json:"reports" asn1:"tag:1"`
}

// Output represents the output of a test case
type Output struct {
	OK  *ByteArray32 `json:"ok,omitempty" asn1:"tag:0,optional"`
	Err *struct{}    `json:"err,omitempty" asn1:"tag:1,optional"`
}
