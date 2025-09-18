package fuzzinterface

import (
	"encoding/binary"
	"fmt"

	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

// Protocol message types as defined in the fuzzing spec

type Version struct {
	Major uint8
	Minor uint8
	Patch uint8
}

const FEATURE_ANCESTRY = 1 << 0
const FEATURE_FORK = 1 << 1

type PeerInfo struct {
	FuzzVersion uint8
	Features    uint32
	JamVersion  Version
	AppVersion  Version
	Name        []byte
}

type ImportBlock block.Block

type Initialize struct {
	Header   header.Header
	State    merklizer.State
	Ancestry []AncestryItem
}

type AncestryItem struct {
	Slot       types.Timeslot
	HeaderHash [32]byte
}

type GetState [32]byte // HeaderHash

type StateRoot [32]byte

type RequestMessage struct {
	PeerInfo    *PeerInfo    `json:"peer_info,omitempty"`
	ImportBlock *ImportBlock `json:"import_block,omitempty"`
	Initialize  *Initialize  `json:"initialize,omitempty"`
	GetState    *GetState    `json:"get_state,omitempty"`
}

type ResponseMessage struct {
	PeerInfo  *PeerInfo        `json:"peer_info,omitempty"`
	State     *merklizer.State `json:"state,omitempty"`
	StateRoot *StateRoot       `json:"state_root,omitempty"`
	Error     *[]byte          `json:"error,omitempty"`
}

// RequestMessageType identifies the type of a request message
type RequestMessageType byte

const (
	// Request message types
	RequestMessageTypePeerInfo    RequestMessageType = 0
	RequestMessageTypeInitialize  RequestMessageType = 1
	RequestMessageTypeImportBlock RequestMessageType = 3
	RequestMessageTypeGetState    RequestMessageType = 4
)

// ResponseMessageType identifies the type of a response message
type ResponseMessageType byte

const (
	// Response message types
	ResponseMessageTypePeerInfo  ResponseMessageType = 0
	ResponseMessageTypeStateRoot ResponseMessageType = 2
	ResponseMessageTypeState     ResponseMessageType = 5
	ResponseMessageTypeError     ResponseMessageType = 255
)

// EncodeMessage encodes a Message according to the JAM codec format
// prefixed with a 32-bit little-endian length
func EncodeMessage(msg ResponseMessage) ([]byte, error) {
	// Encode the message based on its type
	var encodedMessage []byte
	var msgType ResponseMessageType

	switch {
	case msg.PeerInfo != nil:
		encodedMessage = serializer.Serialize(*msg.PeerInfo)
		msgType = ResponseMessageTypePeerInfo
	case msg.State != nil:
		encodedMessage = serializer.Serialize(*msg.State)
		msgType = ResponseMessageTypeState
	case msg.StateRoot != nil:
		encodedMessage = serializer.Serialize(*msg.StateRoot)
		msgType = ResponseMessageTypeStateRoot
	case msg.Error != nil:
		encodedMessage = serializer.Serialize(*msg.Error)
		msgType = ResponseMessageTypeError
	default:
		return nil, fmt.Errorf("unknown message type")
	}

	// Prefix with message type
	result := append([]byte{byte(msgType)}, encodedMessage...)

	// Calculate length and prefix it
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(len(result)))
	return append(lengthBytes, result...), nil
}
