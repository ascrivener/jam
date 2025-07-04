package fuzzinterface

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workreport"
)

// Protocol message types as defined in the fuzzing spec

type Version struct {
	Major uint8
	Minor uint8
	Patch uint8
}

type PeerInfo struct {
	Name       string
	AppVersion Version
	JamVersion Version
}

type SetState struct {
	Header BlockHeader
	State  State
}

type GetState [32]byte // HeaderHash

type StateRoot [32]byte

// JSON structure types for test vectors

// ValidatorEntry represents validator information for an epoch
type ValidatorEntry struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
}

// EpochMark contains epoch information in a block header
type EpochMark struct {
	Entropy        string           `json:"entropy"`
	TicketsEntropy string           `json:"tickets_entropy"`
	Validators     []ValidatorEntry `json:"validators"`
}

func convertEpochMark(epochMarkJSON *EpochMark) (*header.EpochMarker, error) {
	if epochMarkJSON == nil {
		return nil, nil
	}

	validatorKeys := [constants.NumValidators]struct {
		types.BandersnatchPublicKey
		types.Ed25519PublicKey
	}{}

	for i, v := range epochMarkJSON.Validators {
		bandersnatchPublicKey, err := hexToHash(v.Bandersnatch)
		if err != nil {
			return nil, err
		}
		ed25519PublicKey, err := hexToHash(v.Ed25519)
		if err != nil {
			return nil, err
		}
		validatorKeys[i] = struct {
			types.BandersnatchPublicKey
			types.Ed25519PublicKey
		}{
			types.BandersnatchPublicKey(bandersnatchPublicKey),
			types.Ed25519PublicKey(ed25519PublicKey),
		}
	}

	entropy, err := hexToHash(epochMarkJSON.Entropy)
	if err != nil {
		return nil, err
	}
	ticketsEntropy, err := hexToHash(epochMarkJSON.TicketsEntropy)
	if err != nil {
		return nil, err
	}
	return &header.EpochMarker{
		CurrentEpochRandomness: entropy,
		TicketsRandomness:      ticketsEntropy,
		ValidatorKeys:          validatorKeys,
	}, nil
}

// TicketMark contains ticket information
type TicketMark struct {
	ID      string `json:"id"`
	Attempt uint64 `json:"attempt"`
}

func convertTicketsMark(ticketsMarkJSON *[]TicketMark) (*[constants.NumTimeslotsPerEpoch]header.Ticket, error) {
	tickets := [constants.NumTimeslotsPerEpoch]header.Ticket{}

	if ticketsMarkJSON == nil {
		return nil, nil
	}

	for i, t := range *ticketsMarkJSON {
		hash, err := hexToHash(t.ID)
		if err != nil {
			return nil, err
		}
		tickets[i] = header.Ticket{
			EntryIndex:                 types.GenericNum(t.Attempt),
			VerifiablyRandomIdentifier: hash,
		}
	}

	return &tickets, nil
}

// OffenderMark represents an offender in the blockchain
type OffenderMark struct {
}

// BlockHeader represents the header of a block
type BlockHeader struct {
	Parent          string         `json:"parent"`
	ParentStateRoot string         `json:"parent_state_root"`
	ExtrinsicHash   string         `json:"extrinsic_hash"`
	Slot            int            `json:"slot"`
	AuthorIndex     int            `json:"author_index"`
	EntropySource   string         `json:"entropy_source"`
	Seal            string         `json:"seal"`
	EpochMark       *EpochMark     `json:"epoch_mark"`
	OffendersMark   []OffenderMark `json:"offenders_mark"`
	TicketsMark     *[]TicketMark  `json:"tickets_mark"`
}

func (h *BlockHeader) toInternal() (header.Header, error) {

	ticketsMark, err := convertTicketsMark(h.TicketsMark)
	if err != nil {
		return header.Header{}, err
	}

	if len(h.OffendersMark) > 0 {
		panic("Offenders marker not implemented")
	}

	parentHash, err := hexToHash(h.Parent)
	if err != nil {
		return header.Header{}, err
	}

	priorStateRoot, err := hexToHash(h.ParentStateRoot)
	if err != nil {
		return header.Header{}, err
	}

	extrinsicHash, err := hexToHash(h.ExtrinsicHash)
	if err != nil {
		return header.Header{}, err
	}

	vrfSignature, err := hexToBytes(h.EntropySource)
	if err != nil {
		return header.Header{}, err
	}
	if len(vrfSignature) != 96 {
		return header.Header{}, fmt.Errorf("invalid length for VRF signature: %d", len(vrfSignature))
	}

	blockSeal, err := hexToBytes(h.Seal)
	if err != nil {
		return header.Header{}, err
	}
	if len(blockSeal) != 96 {
		return header.Header{}, fmt.Errorf("invalid length for block seal: %d", len(blockSeal))
	}

	epochMark, err := convertEpochMark(h.EpochMark)
	if err != nil {
		return header.Header{}, err
	}

	return header.Header{
		UnsignedHeader: header.UnsignedHeader{
			ParentHash:                   parentHash,
			PriorStateRoot:               priorStateRoot,
			ExtrinsicHash:                extrinsicHash,
			TimeSlot:                     types.Timeslot(h.Slot),
			BandersnatchBlockAuthorIndex: types.ValidatorIndex(h.AuthorIndex),
			VRFSignature:                 types.BandersnatchVRFSignature(vrfSignature),
			EpochMarker:                  epochMark,
			WinningTicketsMarker:         ticketsMark,
			OffendersMarker:              []types.Ed25519PublicKey{},
		},
		BlockSeal: types.BandersnatchVRFSignature(blockSeal),
	}, nil

}

// Disputes represents dispute information in a block
type Disputes struct {
	Verdicts []interface{} `json:"verdicts"`
	Culprits []interface{} `json:"culprits"`
	Faults   []interface{} `json:"faults"`
}

func convertDisputes(disputesJSON Disputes) (extrinsics.Disputes, error) {
	if len(disputesJSON.Verdicts) > 0 || len(disputesJSON.Culprits) > 0 || len(disputesJSON.Faults) > 0 {
		return extrinsics.Disputes{}, fmt.Errorf("disputes not supported")
	}
	return extrinsics.Disputes{
		Verdicts: []extrinsics.Verdict{},
		Culprits: []extrinsics.Culprit{},
		Faults:   []extrinsics.Fault{},
	}, nil
}

// GuaranteeSignatureJSON represents a signature for a guarantee
type GuaranteeSignatureJSON struct {
	ValidatorIndex int    `json:"validator_index"`
	Signature      string `json:"signature"`
}

// GuaranteeJSON represents a guarantee in a block
type Guarantee struct {
	Report     WorkReport               `json:"report"`
	Slot       uint64                   `json:"slot"`
	Signatures []GuaranteeSignatureJSON `json:"signatures"`
}

// convertGuarantees converts JSON guarantees to extrinsics.Guarantees
func convertGuarantees(guaranteesJSON []Guarantee) (extrinsics.Guarantees, error) {
	guarantees := extrinsics.Guarantees{}

	for _, g := range guaranteesJSON {
		// Convert the work report
		implReport, err := g.Report.toInternal()
		if err != nil {
			return extrinsics.Guarantees{}, err
		}

		// Convert signatures
		signatures := make([]extrinsics.Credential, 0, len(g.Signatures))
		for _, sig := range g.Signatures {
			// Convert the signature string to byte array
			sigBytes, err := hexToBytes(sig.Signature)
			if err != nil {
				return extrinsics.Guarantees{}, err
			}
			if len(sigBytes) != 64 {
				return extrinsics.Guarantees{}, fmt.Errorf("invalid length for signature: %d", len(sigBytes))
			}

			// Create the Ed25519Signature (which is [64]byte)
			var ed25519Sig types.Ed25519Signature
			copy(ed25519Sig[:], sigBytes)

			// Create and append the guarantee signature
			signatures = append(signatures, extrinsics.Credential{
				ValidatorIndex: types.ValidatorIndex(sig.ValidatorIndex),
				Signature:      ed25519Sig,
			})
		}

		// Create and append the guarantee
		guarantee := extrinsics.Guarantee{
			WorkReport:  implReport,
			Timeslot:    types.Timeslot(g.Slot),
			Credentials: signatures,
		}

		guarantees = append(guarantees, guarantee)
	}

	return guarantees, nil
}

type WorkReport struct {
	PackageSpec       WorkPackageSpec   `json:"package_spec"`
	Context           RefineContext     `json:"context"`
	CoreIndex         uint64            `json:"core_index"`
	AuthorizerHash    string            `json:"authorizer_hash"`
	AuthOutput        string            `json:"auth_output"`
	SegmentRootLookup SegmentRootLookup `json:"segment_root_lookup"`
	Results           []WorkDigest      `json:"results"`
	AuthGasUsed       uint64            `json:"auth_gas_used"`
}

// convertJSONReportToImplReport converts a workreport from the JSON to the implementation's WorkReport type
func (w *WorkReport) toInternal() (workreport.WorkReport, error) {
	var report workreport.WorkReport

	// Set CoreIndex
	report.CoreIndex = types.GenericNum(w.CoreIndex)

	// Convert results
	for _, result := range w.Results {
		codeHash, err := hexToHash(result.CodeHash)
		if err != nil {
			return workreport.WorkReport{}, err
		}
		payloadHash, err := hexToHash(result.PayloadHash)
		if err != nil {
			return workreport.WorkReport{}, err
		}

		workDigest := workreport.WorkDigest{
			ServiceIndex:                 types.ServiceIndex(result.ServiceId),
			ServiceCodeHash:              codeHash,
			PayloadHash:                  payloadHash,
			AccumulateGasLimit:           types.GasValue(result.AccumulateGas),
			WorkResult:                   types.ExecutionExitReason{},
			ActualRefinementGasUsed:      types.GenericGasValue(result.RefineLoad.GasUsed),
			NumSegmentsImportedFrom:      types.GenericNum(result.RefineLoad.Imports),
			NumExtrinsicsUsed:            types.GenericNum(result.RefineLoad.ExtrinsicCount),
			SizeInOctetsOfExtrinsicsUsed: types.GenericNum(result.RefineLoad.ExtrinsicSize),
			NumSegmentsExportedInto:      types.GenericNum(result.RefineLoad.Exports),
		}

		if result.Result.OK != nil {
			okBytes, err := hexToBytes(*result.Result.OK)
			if err != nil {
				return workreport.WorkReport{}, err
			}
			// If OK is present, convert hex string to binary
			workDigest.WorkResult = types.NewExecutionExitReasonBlob(okBytes)
		}

		report.WorkDigests = append(report.WorkDigests, workDigest)
	}

	// Set package spec
	packageSpecHash, err := hexToHash(w.PackageSpec.Hash)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	erasureRoot, err := hexToHash(w.PackageSpec.ErasureRoot)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	exportsRoot, err := hexToHash(w.PackageSpec.ExportsRoot)
	if err != nil {
		return workreport.WorkReport{}, err
	}

	report.WorkPackageSpecification = workreport.AvailabilitySpecification{
		WorkPackageHash:  packageSpecHash,                        // h
		WorkBundleLength: types.BlobLength(w.PackageSpec.Length), // l
		ErasureRoot:      erasureRoot,                            // u
		SegmentRoot:      exportsRoot,                            // e - ExportsRoot maps to SegmentRoot
		SegmentCount:     uint16(w.PackageSpec.ExportsCount),     // n - ExportsCount maps to SegmentCount
	}

	// Set refinement context
	anchorHash, err := hexToHash(w.Context.Anchor)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	stateRoot, err := hexToHash(w.Context.StateRoot)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	beefyRoot, err := hexToHash(w.Context.BeefyRoot)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	lookupAnchor, err := hexToHash(w.Context.LookupAnchor)
	if err != nil {
		return workreport.WorkReport{}, err
	}

	// Convert prerequisites to map of [32]byte
	prereqMap := make(map[[32]byte]struct{})
	for _, prereq := range w.Context.Prerequisites {
		hash, err := hexToHash(prereq)
		if err != nil {
			return workreport.WorkReport{}, err
		}
		prereqMap[hash] = struct{}{}
	}

	report.RefinementContext = workreport.RefinementContext{
		AnchorHeaderHash:              anchorHash,                                 // a
		PosteriorStateRoot:            stateRoot,                                  // s
		PosteriorBEEFYRoot:            beefyRoot,                                  // b
		LookupAnchorHeaderHash:        lookupAnchor,                               // l
		Timeslot:                      types.Timeslot(w.Context.LookupAnchorSlot), // t
		PrerequisiteWorkPackageHashes: prereqMap,                                  // p
	}

	// Set AuthorizerHash (a)
	authorizerHash, err := hexToHash(w.AuthorizerHash)
	if err != nil {
		return workreport.WorkReport{}, err
	}
	report.AuthorizerHash = authorizerHash

	// Set Output (o) - properly decode the hex string ByteSequence to bytes
	if w.AuthOutput != "" {
		output, err := hexToBytes(w.AuthOutput)
		if err != nil {
			return workreport.WorkReport{}, err
		}
		report.Output = output
	} else {
		report.Output = []byte{}
	}

	// Set SegmentRootLookup (l)
	report.SegmentRootLookup = make(map[[32]byte][32]byte)
	for _, item := range w.SegmentRootLookup {
		key, err := hexToHash(item.WorkPackageHash)
		if err != nil {
			return workreport.WorkReport{}, err
		}
		val, err := hexToHash(item.SegmentTreeRoot)
		if err != nil {
			return workreport.WorkReport{}, err
		}
		report.SegmentRootLookup[key] = val
	}

	// Set IsAuthorizedGasConsumption from AuthGasUsed
	report.IsAuthorizedGasConsumption = types.GenericGasValue(w.AuthGasUsed)

	return report, nil
}

// WorkPackageSpec represents a specification of a work package
type WorkPackageSpec struct {
	Hash         string `json:"hash"`
	Length       uint64 `json:"length"`
	ErasureRoot  string `json:"erasure_root"`
	ExportsRoot  string `json:"exports_root"`
	ExportsCount uint64 `json:"exports_count"`
}

// RefineContext represents a context for refinement
type RefineContext struct {
	Anchor           string   `json:"anchor"`
	StateRoot        string   `json:"state_root"`
	BeefyRoot        string   `json:"beefy_root"`
	LookupAnchor     string   `json:"lookup_anchor"`
	LookupAnchorSlot uint64   `json:"lookup_anchor_slot"`
	Prerequisites    []string `json:"prerequisites"`
}

// SegmentRootLookupItem represents a lookup item for segment roots
type SegmentRootLookupItem struct {
	WorkPackageHash string `json:"work_package_hash"`
	SegmentTreeRoot string `json:"segment_tree_root"`
}

// SegmentRootLookup represents a collection of segment root lookup items
type SegmentRootLookup []SegmentRootLookupItem

// WorkDigest represents the result of work execution
type WorkDigest struct {
	ServiceId     uint64         `json:"service_id"`
	CodeHash      string         `json:"code_hash"`
	PayloadHash   string         `json:"payload_hash"`
	AccumulateGas uint64         `json:"accumulate_gas"`
	Result        WorkExecResult `json:"result"`
	RefineLoad    RefineLoad     `json:"refine_load"`
}

// WorkExecResult represents the result of work execution (OK or error)
type WorkExecResult struct {
	OK *string `json:"ok,omitempty"`
}

// RefineLoad represents the load statistics for refinement
type RefineLoad struct {
	GasUsed        uint64 `json:"gas_used"`
	Imports        uint64 `json:"imports"`
	ExtrinsicCount uint64 `json:"extrinsic_count"`
	ExtrinsicSize  uint64 `json:"extrinsic_size"`
	Exports        uint64 `json:"exports"`
}

// Assurance represents assurance data in an extrinsic
type Assurance struct {
	Anchor         string `json:"anchor"`
	Bitfield       string `json:"bitfield"`
	ValidatorIndex uint64 `json:"validator_index"`
	Signature      string `json:"signature"`
}

func convertAssurances(assurancesJSON []Assurance) (extrinsics.Assurances, error) {
	assurances := extrinsics.Assurances{}

	for _, a := range assurancesJSON {
		// Convert anchor (parent hash) from hex string to [32]byte
		parentHash, err := hexToHash(a.Anchor)
		if err != nil {
			return nil, err
		}

		bytes, err := hexToBytes(a.Bitfield)
		if err != nil {
			return nil, err
		}

		// Convert bitfield string to BitSequence
		bitfield, err := bitsequence.CoreBitMaskFromBytesLSB(bytes)
		if err != nil {
			return nil, err
		}

		signature, err := hexToBytes(a.Signature)
		if err != nil {
			return nil, err
		}
		if len(signature) != 64 {
			return nil, fmt.Errorf("signature wrong length: expected 64, got %d", len(signature))
		}

		// Create and append the assurance
		assurance := extrinsics.Assurance{
			ParentHash:                    parentHash,
			CoreAvailabilityContributions: *bitfield,
			ValidatorIndex:                types.ValidatorIndex(a.ValidatorIndex),
			Signature:                     types.Ed25519Signature(signature),
		}

		assurances = append(assurances, assurance)
	}

	return assurances, nil
}

// Ticket represents a ticket in an extrinsic
type Ticket struct {
	Attempt   uint64 `json:"attempt"`
	Signature string `json:"signature"`
}

func convertTickets(ticketsJSON []Ticket) (extrinsics.Tickets, error) {
	tickets := extrinsics.Tickets{}

	for _, t := range ticketsJSON {
		bytes, err := hexToBytes(t.Signature)
		if err != nil {
			return nil, err
		}

		if len(bytes) != 784 {
			return nil, fmt.Errorf("invalid signature length: expected 784, got %d", len(bytes))
		}

		tickets = append(tickets, extrinsics.Ticket{
			EntryIndex:    types.GenericNum(t.Attempt),
			ValidityProof: types.BandersnatchRingVRFProof(bytes),
		})
	}

	return tickets, nil
}

// Preimage represents a preimage in an extrinsic
type Preimage struct {
	ServiceIndex uint64 `json:"requester"`
	Data         string `json:"blob"`
}

func convertPreimages(preimagesJSON []Preimage) (extrinsics.Preimages, error) {
	preimages := extrinsics.Preimages{}

	for _, p := range preimagesJSON {
		data, err := hexToBytes(p.Data)
		if err != nil {
			return nil, err
		}
		preimages = append(preimages, extrinsics.Preimage{
			ServiceIndex: types.ServiceIndex(p.ServiceIndex),
			Data:         data,
		})
	}

	return preimages, nil
}

// Extrinsic represents the extrinsic part of a block
type Extrinsic struct {
	Tickets    []Ticket    `json:"tickets"`
	Preimages  []Preimage  `json:"preimages"`
	Guarantees []Guarantee `json:"guarantees"`
	Assurances []Assurance `json:"assurances"`
	Disputes   Disputes    `json:"disputes"`
}

// Block represents a complete block with header and extrinsic
type Block struct {
	Header    BlockHeader `json:"header"`
	Extrinsic Extrinsic   `json:"extrinsic"`
}

// BlockFromJSON parses a JSON block representation directly into a block.Block
func (b *Block) ToInternal() (block.Block, error) {

	blockHeader, err := b.Header.toInternal()
	if err != nil {
		return block.Block{}, err
	}

	tickets, err := convertTickets(b.Extrinsic.Tickets)
	if err != nil {
		return block.Block{}, err
	}
	guarantees, err := convertGuarantees(b.Extrinsic.Guarantees)
	if err != nil {
		return block.Block{}, err
	}
	assurances, err := convertAssurances(b.Extrinsic.Assurances)
	if err != nil {
		return block.Block{}, err
	}
	disputes, err := convertDisputes(b.Extrinsic.Disputes)
	if err != nil {
		return block.Block{}, err
	}
	preimages, err := convertPreimages(b.Extrinsic.Preimages)
	if err != nil {
		return block.Block{}, err
	}
	// Convert extrinsic part (simplified for now)
	extrinsics := extrinsics.Extrinsics{
		Guarantees: guarantees,
		Assurances: assurances,
		Disputes:   disputes,
		Tickets:    tickets,
		Preimages:  preimages,
	}

	// Build the full block
	return block.Block{
		Header:     blockHeader,
		Extrinsics: extrinsics,
	}, nil
}

type StateKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (kv StateKV) toInternal() (merklizer.StateKV, error) {
	key, err := hexToBytes(kv.Key)
	if err != nil {
		return merklizer.StateKV{}, err
	}
	if len(key) != 31 {
		return merklizer.StateKV{}, fmt.Errorf("invalid key length: expected 31, got %d", len(key))
	}
	value, err := hexToBytes(kv.Value)
	if err != nil {
		return merklizer.StateKV{}, err
	}
	return merklizer.StateKV{
		OriginalKey: [31]byte(key),
		Value:       value,
	}, nil
}

// KeyVals represents a list of key-value pairs
type State []StateKV

func (s State) ToInternal() (merklizer.State, error) {
	state := merklizer.State{}
	for _, kv := range s {
		stateKV, err := kv.toInternal()
		if err != nil {
			return nil, err
		}
		state = append(state, stateKV)
	}
	return state, nil
}

func StateFromInternal(state merklizer.State) State {
	s := State{}
	for _, kv := range state {
		s = append(s, StateKV{
			Key:   hex.EncodeToString(kv.OriginalKey[:]),
			Value: hex.EncodeToString(kv.Value),
		})
	}
	return s
}

// StateKeyValues represents the key-value pairs in a state
type StateKeyValues struct {
	StateRoot string `json:"state_root"`
	KeyVals   State  `json:"keyvals"`
}

// Message represents the protocol message envelope
type Message struct {
	PeerInfo    *PeerInfo  `json:"peer_info,omitempty"`
	ImportBlock *Block     `json:"import_block,omitempty"`
	SetState    *SetState  `json:"set_state,omitempty"`
	GetState    *GetState  `json:"get_state,omitempty"`
	State       *State     `json:"state,omitempty"`
	StateRoot   *StateRoot `json:"state_root,omitempty"`
}

// MessageType identifies the type of a message for encoding/decoding
type MessageType byte

const (
	MessageTypePeerInfo    MessageType = 0
	MessageTypeImportBlock MessageType = 1
	MessageTypeSetState    MessageType = 2
	MessageTypeGetState    MessageType = 3
	MessageTypeState       MessageType = 4
	MessageTypeStateRoot   MessageType = 5
)

// EncodeMessage encodes a Message according to the JAM codec format
// prefixed with a 32-bit little-endian length
func EncodeMessage(msg Message) ([]byte, error) {
	// Encode the message based on its type
	var encodedMessage []byte
	var err error
	var msgType MessageType

	switch {
	case msg.PeerInfo != nil:
		encodedMessage, err = encodePeerInfo(*msg.PeerInfo)
		msgType = MessageTypePeerInfo
	case msg.ImportBlock != nil:
		encodedMessage, err = encodeImportBlock(*msg.ImportBlock)
		msgType = MessageTypeImportBlock
	case msg.SetState != nil:
		encodedMessage, err = encodeSetState(*msg.SetState)
		msgType = MessageTypeSetState
	case msg.GetState != nil:
		encodedMessage, err = encodeGetState(*msg.GetState)
		msgType = MessageTypeGetState
	case msg.State != nil:
		encodedMessage, err = encodeState(*msg.State)
		msgType = MessageTypeState
	case msg.StateRoot != nil:
		encodedMessage, err = encodeStateRoot(*msg.StateRoot)
		msgType = MessageTypeStateRoot
	default:
		return nil, fmt.Errorf("unknown message type")
	}

	if err != nil {
		return nil, err
	}

	// Prefix with message type
	result := append([]byte{byte(msgType)}, encodedMessage...)

	// Calculate length and prefix it
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(len(result)))
	return append(lengthBytes, result...), nil
}

// DecodeMessage decodes a message from bytes
func DecodeMessage(data []byte) (Message, error) {
	// First 4 bytes are the length prefix
	if len(data) < 5 { // At least 4 bytes for length + 1 for message type
		return Message{}, fmt.Errorf("message too short")
	}

	// Skip the length prefix
	data = data[4:]

	// Get the message type
	msgType := MessageType(data[0])

	// Skip the type byte
	data = data[1:]

	var msg Message
	var err error

	switch msgType {
	case MessageTypePeerInfo:
		var peerInfo PeerInfo
		peerInfo, err = decodePeerInfo(data)
		msg.PeerInfo = &peerInfo
	case MessageTypeImportBlock:
		var importBlock Block
		importBlock, err = decodeImportBlock(data)
		msg.ImportBlock = &importBlock
	case MessageTypeSetState:
		var setState SetState
		setState, err = decodeSetState(data)
		msg.SetState = &setState
	case MessageTypeGetState:
		var getState GetState
		getState, err = decodeGetState(data)
		msg.GetState = &getState
	case MessageTypeState:
		var state State
		state, err = decodeState(data)
		msg.State = &state
	case MessageTypeStateRoot:
		var stateRoot StateRoot
		stateRoot, err = decodeStateRoot(data)
		msg.StateRoot = &stateRoot
	default:
		return Message{}, fmt.Errorf("unknown message type: %d", msgType)
	}

	return msg, err
}

// Individual message type encoders and decoders
// Note: These are placeholder implementations that need to be completed
// based on the JAM codec specification

func encodePeerInfo(info PeerInfo) ([]byte, error) {
	// TODO: Implement based on JAM codec spec
	// Placeholder implementation
	var buf bytes.Buffer

	// Encode name
	buf.WriteByte(byte(len(info.Name)))
	buf.WriteString(info.Name)

	// Encode versions
	buf.WriteByte(info.AppVersion.Major)
	buf.WriteByte(info.AppVersion.Minor)
	buf.WriteByte(info.AppVersion.Patch)

	buf.WriteByte(info.JamVersion.Major)
	buf.WriteByte(info.JamVersion.Minor)
	buf.WriteByte(info.JamVersion.Patch)

	return buf.Bytes(), nil
}

func decodePeerInfo(data []byte) (PeerInfo, error) {
	// TODO: Implement based on JAM codec spec
	// Placeholder implementation
	if len(data) < 7 { // Minimum size for name length, name (at least empty), and versions
		return PeerInfo{}, fmt.Errorf("peer info data too short")
	}

	// Read name
	nameLen := int(data[0])
	if 1+nameLen+6 > len(data) {
		return PeerInfo{}, fmt.Errorf("peer info data too short for name")
	}
	name := string(data[1 : 1+nameLen])

	// Read versions
	appVersion := Version{
		Major: data[1+nameLen],
		Minor: data[1+nameLen+1],
		Patch: data[1+nameLen+2],
	}

	jamVersion := Version{
		Major: data[1+nameLen+3],
		Minor: data[1+nameLen+4],
		Patch: data[1+nameLen+5],
	}

	return PeerInfo{
		Name:       name,
		AppVersion: appVersion,
		JamVersion: jamVersion,
	}, nil
}

// Placeholder implementations for other message types
// These need to be implemented according to the JAM codec specification

func encodeImportBlock(block Block) ([]byte, error) {
	// Marshal the block to JSON
	data, err := json.Marshal(block)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal block: %w", err)
	}
	return data, nil
}

func decodeImportBlock(data []byte) (Block, error) {
	// If the data is encoded as JSON (which seems most likely based on your example)
	var block Block
	err := json.Unmarshal(data, &block)
	if err != nil {
		return Block{}, fmt.Errorf("failed to unmarshal block: %w", err)
	}
	return block, nil
}

func encodeSetState(setState SetState) ([]byte, error) {
	// Marshal the setState to JSON
	data, err := json.Marshal(setState)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal set state: %w", err)
	}
	return data, nil
}

func decodeSetState(data []byte) (SetState, error) {
	// Unmarshal from JSON into SetState struct
	var setState SetState
	err := json.Unmarshal(data, &setState)
	if err != nil {
		return SetState{}, fmt.Errorf("failed to unmarshal set state: %w", err)
	}
	return setState, nil
}

func encodeGetState(getState GetState) ([]byte, error) {
	return getState[:], nil
}

func decodeGetState(data []byte) (GetState, error) {
	if len(data) != 32 {
		return GetState{}, fmt.Errorf("invalid length for header hash: %d", len(data))
	}

	var hash GetState
	copy(hash[:], data[:32])
	return hash, nil
}

func encodeState(state State) ([]byte, error) {
	// Marshal the state to JSON
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state: %w", err)
	}
	return data, nil
}

func decodeState(data []byte) (State, error) {
	// Unmarshal JSON into State
	var state State
	err := json.Unmarshal(data, &state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	return state, nil
}

func encodeStateRoot(stateRoot StateRoot) ([]byte, error) {
	return stateRoot[:], nil
}

func decodeStateRoot(data []byte) (StateRoot, error) {
	if len(data) != 32 {
		return StateRoot{}, fmt.Errorf("invalid length for state root: %d", len(data))
	}

	var root StateRoot
	copy(root[:], data[:32])
	return root, nil
}

// Helper functions for hash conversion
func hexToHash(hexStr string) ([32]byte, error) {
	var result [32]byte

	// Remove 0x prefix if present
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}

	// Check length
	if len(hexStr) != 64 {
		return result, fmt.Errorf("invalid hash length: %d", len(hexStr))
	}

	// Convert from hex
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, err
	}

	// Copy to result
	copy(result[:], bytes)
	return result, nil
}

// hexToBytes converts a hex string (with or without 0x prefix) to a byte slice
func hexToBytes(hexStr string) ([]byte, error) {
	// Remove 0x prefix if it exists
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	// Add leading zero if odd length
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
