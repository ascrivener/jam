package fuzzinterface

import (
	"encoding/binary"
	"fmt"

	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
)

// Protocol message types as defined in the fuzzing spec

type Version struct {
	Major uint8
	Minor uint8
	Patch uint8
}

type PeerInfo struct {
	Name       []byte
	AppVersion Version
	JamVersion Version
}

type ImportBlock block.Block

type SetState struct {
	Header        header.Header
	StateWithRoot struct {
		StateRoot [32]byte
		State     merklizer.State
	}
}

type GetState [32]byte // HeaderHash

type StateRoot [32]byte

type RequestMessage struct {
	PeerInfo    *PeerInfo    `json:"peer_info,omitempty"`
	ImportBlock *ImportBlock `json:"import_block,omitempty"`
	SetState    *SetState    `json:"set_state,omitempty"`
	GetState    *GetState    `json:"get_state,omitempty"`
}

type ResponseMessage struct {
	PeerInfo  *PeerInfo        `json:"peer_info,omitempty"`
	State     *merklizer.State `json:"state,omitempty"`
	StateRoot *StateRoot       `json:"state_root,omitempty"`
}

// RequestMessageType identifies the type of a request message
type RequestMessageType byte

const (
	// Request message types
	RequestMessageTypePeerInfo    RequestMessageType = 0
	RequestMessageTypeImportBlock RequestMessageType = 1
	RequestMessageTypeSetState    RequestMessageType = 2
	RequestMessageTypeGetState    RequestMessageType = 3
)

// ResponseMessageType identifies the type of a response message
type ResponseMessageType byte

const (
	// Response message types
	ResponseMessageTypePeerInfo  ResponseMessageType = 0
	ResponseMessageTypeState     ResponseMessageType = 4
	ResponseMessageTypeStateRoot ResponseMessageType = 5
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

// DecodeMessage decodes a message from bytes
func DecodeMessage(data []byte) (RequestMessage, error) {
	// Check minimum message length
	if len(data) < 1 { // At least 1 byte for message type
		return RequestMessage{}, fmt.Errorf("message too short")
	}

	// Get the message type
	msgType := RequestMessageType(data[0])

	// Skip the type byte
	data = data[1:]

	var msg RequestMessage
	var err error

	switch msgType {
	case RequestMessageTypePeerInfo:
		var peerInfo PeerInfo
		err = serializer.Deserialize(data, &peerInfo)
		if err != nil {
			return RequestMessage{}, err
		}
		msg.PeerInfo = &peerInfo
	case RequestMessageTypeImportBlock:
		var importBlock ImportBlock
		err := serializer.Deserialize(data, &importBlock)
		if err != nil {
			return RequestMessage{}, err
		}
		msg.ImportBlock = &importBlock
	case RequestMessageTypeSetState:
		var setState SetState
		err = serializer.Deserialize(data, &setState)
		if err != nil {
			return RequestMessage{}, err
		}
		msg.SetState = &setState
	case RequestMessageTypeGetState:
		var getState GetState
		err = serializer.Deserialize(data, &getState)
		if err != nil {
			return RequestMessage{}, err
		}
		msg.GetState = &getState
	default:
		return RequestMessage{}, fmt.Errorf("unknown message type: %d", msgType)
	}

	return msg, err
}
