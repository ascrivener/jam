package net

import (
	"crypto/tls"
	"io"

	"github.com/quic-go/quic-go"
)

// StreamKind represents the kind of a JAMNP-S stream
type StreamKind byte

const (
	// UP streams (0-127)
	StreamKindUP0BlockAnnouncement StreamKind = 0

	// CE streams (128-255)
	StreamKindCE128BlockRequest          StreamKind = 128
	StreamKindCE129StateRequest          StreamKind = 129
	StreamKindCE131TicketDistribution    StreamKind = 131
	StreamKindCE141AssuranceDistribution StreamKind = 141
)

// Direction represents the direction of a block request
type Direction byte

const (
	// DirectionDescendants requests blocks in the descendant (forward) direction
	DirectionDescendants Direction = 0
	// DirectionAncestors requests blocks in the ancestor (backward) direction
	DirectionAncestors Direction = 1
)

// BlockReference represents a reference to a block
type BlockReference struct {
	Hash []byte
	Slot uint32
}

// BlockAnnouncement represents a block announcement message
type BlockAnnouncement struct {
	Headers      [][]byte
	FinalizedRef BlockReference
}

// BlockRequest represents a block request message
type BlockRequest struct {
	Hash      [32]byte
	Direction Direction
	MaxBlocks uint32
}

// StateRequestOptions represents options for a state request
type StateRequestOptions struct {
	StateRoot   []byte // 32 bytes
	StartKey    []byte // 31 bytes
	EndKey      []byte // 31 bytes
	MaximumSize uint32
}

// KeyValuePair represents a key/value pair in a state response
type KeyValuePair struct {
	Key   []byte
	Value []byte
}

// StateResponse represents a response to a state request
type StateResponse struct {
	BoundaryNodes []byte
	KeyValuePairs []KeyValuePair
}

// StreamHandler is a function that handles a stream
type StreamHandler func(Stream) error

// Connection represents a JAMNP-S connection
type Connection interface {
	// OpenStream opens a new stream with the specified kind
	OpenStream(kind StreamKind) (Stream, error)

	// RemoteKey returns the remote peer's public key
	RemoteKey() []byte

	// InitializedByRemote returns true if this connection was initialized by the remote peer
	InitializedByRemote() bool

	// ValidatorIdx returns the index of the validator this connection is to
	ValidatorIdx() int

	// LocalKey returns the local peer's public key
	LocalKey() []byte

	// TLSConnectionState returns the TLS connection state
	TLSConnectionState() tls.ConnectionState

	// QuicConnection returns the underlying QUIC connection
	QuicConnection() *quic.Conn

	// Close closes the connection
	Close() error
}

// Stream represents a JAMNP-S stream
type Stream interface {
	io.Reader
	io.Writer

	// Close closes the stream
	Close() error

	// CloseWrite closes the write-direction of the stream
	CloseWrite() error

	// Reset resets the stream
	Reset() error

	// Kind returns the stream kind
	Kind() StreamKind
}
