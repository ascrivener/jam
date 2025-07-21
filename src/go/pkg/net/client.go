package net

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ClientOptions contains options for creating a new client
type ClientOptions struct {
	// PublicKey is the client's Ed25519 public key
	PublicKey ed25519.PublicKey

	// PrivateKey is the client's Ed25519 private key
	PrivateKey ed25519.PrivateKey

	// ProtocolVersion is the protocol version string (e.g., "jam-1.0")
	ProtocolVersion string

	// ChainHash is the chain hash string
	ChainHash string

	// IsBuilder indicates whether this client is a builder
	IsBuilder bool

	// DialTimeout is the timeout for dialing a connection
	DialTimeout time.Duration

	// Insecure disables peer certificate verification
	Insecure bool
}

// Client is a JAMNP-S protocol client
type Client struct {
	opts       ClientOptions
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	conns      map[string]Connection
	connsMu    sync.Mutex
}

// NewClient creates a new JAMNP-S client
func NewClient(opts ClientOptions) (*Client, error) {
	// Validate options
	if len(opts.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	if opts.ProtocolVersion == "" {
		opts.ProtocolVersion = "jam-1.0"
	}
	if opts.ChainHash == "" {
		opts.ChainHash = "polkadot"
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}

	// Create TLS config
	tlsConfig, err := generateTLSConfig(opts.PublicKey, opts.PrivateKey, opts.ProtocolVersion, opts.ChainHash, opts.IsBuilder, opts.Insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS config: %w", err)
	}

	// Create QUIC config
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: opts.DialTimeout,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}

	return &Client{
		opts:       opts,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		conns:      make(map[string]Connection),
	}, nil
}

// Connect connects to a JAMNP-S server
func (c *Client) Connect(ctx context.Context, address string) (Connection, error) {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	// Check if we already have a connection
	if conn, ok := c.conns[address]; ok {
		return conn, nil
	}

	// Set a timeout context if not already set
	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, c.opts.DialTimeout)
		defer cancel()
	}

	// Resolve address
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	// If host is empty, use localhost
	if host == "" {
		host = "localhost"
	}

	// Format address with port
	formattedAddr := net.JoinHostPort(host, port)

	// Establish QUIC connection
	udpAddr, err := net.ResolveUDPAddr("udp", formattedAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// Connect to the server
	quicConn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	// Create JAMNP-S connection
	conn, err := NewConnection(quicConn, c.opts.PublicKey)
	if err != nil {
		quicConn.CloseWithError(0, "connection setup failed")
		return nil, fmt.Errorf("failed to create JAMNP-S connection: %w", err)
	}

	// Store connection
	c.conns[address] = conn

	return conn, nil
}

// Close closes all connections
func (c *Client) Close() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	for _, conn := range c.conns {
		conn.Close()
	}

	c.conns = make(map[string]Connection)
}

// OpenBlockAnnouncementStream opens a UP 0 block announcement stream
func (c *Client) OpenBlockAnnouncementStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindUP0BlockAnnouncements)
}

// OpenAssuranceDistributionStream opens a CE 141 assurance distribution stream
func (c *Client) OpenAssuranceDistributionStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE141AssuranceDistribution)
}

// OpenStateRequestStream opens a CE 129 state request stream
func (c *Client) OpenStateRequestStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE129StateRequest)
}

// OpenBlockRequestStream opens a CE 2 block request stream
func (c *Client) OpenBlockRequestStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE2BlockRequest)
}

// RequestBlocks requests blocks from a node
func (c *Client) RequestBlocks(ctx context.Context, conn Connection, hash [32]byte, direction Direction, maxBlocks uint32) ([][]byte, error) {
	// Open a block request stream
	stream, err := c.OpenBlockRequestStream(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to open block request stream: %w", err)
	}
	defer stream.Close()

	// Encode request
	req := &BlockRequest{
		Hash:      hash,
		Direction: direction,
		MaxBlocks: maxBlocks,
	}
	data := EncodeBlockRequest(req)

	// Write message
	err = WriteMessage(stream, data)
	if err != nil {
		return nil, fmt.Errorf("failed to write block request: %w", err)
	}

	// Read response
	var blocks [][]byte

	for {
		// Read message
		msg, err := ReadMessage(stream)
		if err != nil {
			// If we've received at least one block and got EOF, that's normal
			if errors.Is(err, io.EOF) && len(blocks) > 0 {
				break
			}
			return blocks, fmt.Errorf("failed to read block response: %w", err)
		}

		// Add block to result
		blockCopy := make([]byte, len(msg))
		copy(blockCopy, msg)
		blocks = append(blocks, blockCopy)

		// Break if we've received all requested blocks
		if uint32(len(blocks)) >= maxBlocks {
			break
		}
	}

	return blocks, nil
}

// RequestState requests state from a node
func (c *Client) RequestState(ctx context.Context, conn Connection, options *StateRequestOptions) (*StateResponse, error) {
	// Open a state request stream
	stream, err := c.OpenStateRequestStream(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("failed to open state request stream: %w", err)
	}
	defer stream.Close()

	// Encode request
	data := EncodeStateRequest(options)

	// Write message
	err = WriteMessage(stream, data)
	if err != nil {
		return nil, fmt.Errorf("failed to write state request: %w", err)
	}

	// Read response - first message is boundary nodes
	boundaryNodes, err := ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read boundary nodes: %w", err)
	}

	// Read response - second message is key/value pairs
	kvPairs, err := ReadMessage(stream)
	if err != nil {
		// We at least got boundary nodes, so return a partial response
		if errors.Is(err, io.EOF) {
			return &StateResponse{
				BoundaryNodes: boundaryNodes,
				KeyValuePairs: []KeyValuePair{},
			}, nil
		}
		return nil, fmt.Errorf("failed to read key/value pairs: %w", err)
	}

	// Parse response
	response, err := ParseStateResponse(boundaryNodes, kvPairs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse state response: %w", err)
	}

	return response, nil
}

// RequestWorkReport requests a work report from a node
func (c *Client) RequestWorkReport(ctx context.Context, conn Connection, hash [32]byte) ([]byte, error) {
	// Open a work report request stream (CE 3)
	stream, err := conn.OpenStream(StreamKindCE3WorkReportRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to open work report request stream: %w", err)
	}
	defer stream.Close()

	// Encode request
	data := EncodeWorkReportRequest(hash)

	// Write message
	err = WriteMessage(stream, data)
	if err != nil {
		return nil, fmt.Errorf("failed to write work report request: %w", err)
	}

	// Read response
	report, err := ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read work report response: %w", err)
	}

	return report, nil
}

// HandleBlockAnnouncements registers a handler for block announcements
func (c *Client) HandleBlockAnnouncements(conn Connection, handler func(*BlockAnnouncement) error) error {
	streamHandler := func(stream Stream) error {
		for {
			// Read message
			msg, err := ReadMessage(stream)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}

			// Parse announcement
			announcement, err := ParseBlockAnnouncement(msg)
			if err != nil {
				return err
			}

			// Call handler
			if err := handler(announcement); err != nil {
				return err
			}
		}
	}

	conn.RegisterHandler(StreamKindUP0BlockAnnouncements, streamHandler)
	return nil
}

// HandleAssuranceDistributions registers a handler for assurance distributions
func (c *Client) HandleAssuranceDistributions(conn Connection, handler func([]byte) error) error {
	streamHandler := func(stream Stream) error {
		for {
			// Read message
			msg, err := ReadMessage(stream)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}

			// Call handler
			if err := handler(msg); err != nil {
				return err
			}
		}
	}

	conn.RegisterHandler(StreamKindCE141AssuranceDistribution, streamHandler)
	return nil
}
