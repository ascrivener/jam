package asntypes

import (
	"encoding/json"
)

// ImportSpec represents an import specification
type ImportSpec struct {
	TreeRoot OpaqueHash `json:"tree_root" asn1:"tag:0"`
	Index    U16        `json:"index" asn1:"tag:1"`
}

// ExtrinsicSpec represents an extrinsic specification
type ExtrinsicSpec struct {
	Hash OpaqueHash `json:"hash" asn1:"tag:0"`
	Len  U32        `json:"len" asn1:"tag:1"`
}

// RefineContext represents the context for refinement
type RefineContext struct {
	Anchor           HeaderHash   `json:"anchor" asn1:"tag:0"`
	StateRoot        StateRoot    `json:"state_root" asn1:"tag:1"`
	BeefyRoot        BeefyRoot    `json:"beefy_root" asn1:"tag:2"`
	LookupAnchor     HeaderHash   `json:"lookup_anchor" asn1:"tag:3"`
	LookupAnchorSlot TimeSlot     `json:"lookup_anchor_slot" asn1:"tag:4"`
	Prerequisites    []OpaqueHash `json:"prerequisites" asn1:"tag:5"`
}

// Authorizer represents an authorizer entity
type Authorizer struct {
	CodeHash OpaqueHash   `json:"code_hash" asn1:"tag:0"`
	Params   ByteSequence `json:"params" asn1:"tag:1"`
}

// WorkExecResultOk represents a successful work execution result
type WorkExecResultOk struct {
	Data ByteSequence `json:"data"`
}

// WorkExecResult represents the result of work execution with different cases
type WorkExecResult struct {
	// Only one of these will be populated
	OK           *ByteSequence `json:"ok,omitempty"`
	OutOfGas     *struct{}     `json:"out_of_gas,omitempty"`
	Panic        *struct{}     `json:"panic,omitempty"`
	BadExports   *struct{}     `json:"bad_exports,omitempty"`
	BadCode      *struct{}     `json:"bad_code,omitempty"`
	CodeOversize *struct{}     `json:"code_oversize,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for WorkExecResult
func (w *WorkExecResult) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a map to determine which field is set
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Check each possible field
	if raw, ok := rawMap["ok"]; ok {
		var byteSeq ByteSequence
		if err := json.Unmarshal(raw, &byteSeq); err != nil {
			return err
		}
		w.OK = &byteSeq
		return nil
	}

	if _, ok := rawMap["out_of_gas"]; ok {
		w.OutOfGas = &struct{}{}
		return nil
	}

	if _, ok := rawMap["panic"]; ok {
		w.Panic = &struct{}{}
		return nil
	}

	if _, ok := rawMap["bad_exports"]; ok {
		w.BadExports = &struct{}{}
		return nil
	}

	if _, ok := rawMap["bad_code"]; ok {
		w.BadCode = &struct{}{}
		return nil
	}

	if _, ok := rawMap["code_oversize"]; ok {
		w.CodeOversize = &struct{}{}
		return nil
	}

	// No recognized field found
	return nil
}

// RefineLoad represents the load statistics for refinement
type RefineLoad struct {
	GasUsed        U64 `json:"gas_used" asn1:"tag:0"`
	Imports        U16 `json:"imports" asn1:"tag:1"`
	ExtrinsicCount U16 `json:"extrinsic_count" asn1:"tag:2"`
	ExtrinsicSize  U32 `json:"extrinsic_size" asn1:"tag:3"`
	Exports        U16 `json:"exports" asn1:"tag:4"`
}

// WorkResult represents the result of work execution
type WorkResult struct {
	ServiceId     ServiceId      `json:"service_id" asn1:"tag:0"`
	CodeHash      OpaqueHash     `json:"code_hash" asn1:"tag:1"`
	PayloadHash   OpaqueHash     `json:"payload_hash" asn1:"tag:2"`
	AccumulateGas Gas            `json:"accumulate_gas" asn1:"tag:3"`
	Result        WorkExecResult `json:"result" asn1:"tag:4"`
	RefineLoad    RefineLoad     `json:"refine_load" asn1:"tag:5"`
}

// WorkPackageSpec represents a specification of a work package
type WorkPackageSpec struct {
	Hash         WorkPackageHash `json:"hash" asn1:"tag:0"`
	Length       U32             `json:"length" asn1:"tag:1"`
	ErasureRoot  ErasureRoot     `json:"erasure_root" asn1:"tag:2"`
	ExportsRoot  ExportsRoot     `json:"exports_root" asn1:"tag:3"`
	ExportsCount U16             `json:"exports_count" asn1:"tag:4"`
}

// SegmentRootLookupItem represents a lookup item for segment roots
type SegmentRootLookupItem struct {
	WorkPackageHash WorkPackageHash `json:"work_package_hash" asn1:"tag:0"`
	SegmentTreeRoot OpaqueHash      `json:"segment_tree_root" asn1:"tag:1"`
}

// SegmentRootLookup represents a collection of segment root lookup items
type SegmentRootLookup []SegmentRootLookupItem

// WorkReport represents a work report
type WorkReport struct {
	PackageSpec       WorkPackageSpec   `json:"package_spec" asn1:"tag:0"`
	Context           RefineContext     `json:"context" asn1:"tag:1"`
	CoreIndex         CoreIndex         `json:"core_index" asn1:"tag:2"`
	AuthorizerHash    AuthorizerHash    `json:"authorizer_hash" asn1:"tag:3"`
	AuthOutput        ByteSequence      `json:"auth_output" asn1:"tag:4"`
	SegmentRootLookup SegmentRootLookup `json:"segment_root_lookup" asn1:"tag:5"`
	Results           []WorkResult      `json:"results" asn1:"tag:6"`
	AuthGasUsed       U64               `json:"auth_gas_used" asn1:"tag:7"`
}

// WorkItem represents a work item
type WorkItem struct {
	Service            ServiceId       `json:"service" asn1:"tag:0"`
	CodeHash           OpaqueHash      `json:"code_hash" asn1:"tag:1"`
	Payload            ByteSequence    `json:"payload" asn1:"tag:2"`
	RefineGasLimit     Gas             `json:"refine_gas_limit" asn1:"tag:3"`
	AccumulateGasLimit Gas             `json:"accumulate_gas_limit" asn1:"tag:4"`
	ImportSegments     []ImportSpec    `json:"import_segments" asn1:"tag:5"`
	Extrinsic          []ExtrinsicSpec `json:"extrinsic" asn1:"tag:6"`
	ExportCount        U16             `json:"export_count" asn1:"tag:7"`
}

// WorkPackage represents a complete work package
type WorkPackage struct {
	Authorization ByteSequence  `json:"authorization" asn1:"tag:0"`
	AuthCodeHost  ServiceId     `json:"auth_code_host" asn1:"tag:1"`
	Authorizer    Authorizer    `json:"authorizer" asn1:"tag:2"`
	Context       RefineContext `json:"context" asn1:"tag:3"`
	Items         []WorkItem    `json:"items" asn1:"tag:4"`
}
