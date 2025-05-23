package net

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go"
)

// StreamKind represents the type of JAMNP-S stream
type StreamKind byte

const (
	// UP (Unique Persistent) stream kinds
	BlockAnnouncementStream StreamKind = 0

	// CE (Common Ephemeral) stream kinds start at 128
	WorkPackageSubmissionStream StreamKind = 133
	RequestWorkReportStream     StreamKind = 136
)

// Client represents a JAMNP-S client
type Client struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	tlsConfig  *tls.Config
	sessions   map[string]quic.Connection
	mutex      sync.Mutex
}

// Config contains configuration options for the JAMNP-S client
type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	ChainHash  string // First 8 nibbles of the chain's genesis header hash
	Version    string // Protocol version, typically "0"
	IsBuilder  bool   // Whether this client should identify as a work-package builder
	Insecure   bool   // Skip certificate verification (for testing only)
}

// NewClient creates a new JAMNP-S client
func NewClient(config Config) (*Client, error) {
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(config.PublicKey))
	}
	if len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(config.PrivateKey))
	}

	// Generate TLS certificate
	tlsConfig, err := generateTLSConfig(
		config.PublicKey,
		config.PrivateKey,
		config.Version,
		config.ChainHash,
		config.IsBuilder,
		config.Insecure,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS config: %w", err)
	}

	return &Client{
		publicKey:  config.PublicKey,
		privateKey: config.PrivateKey,
		tlsConfig:  tlsConfig,
		sessions:   make(map[string]quic.Connection),
	}, nil
}

// Connect establishes a QUIC connection to a JAMNP-S peer
func (c *Client) Connect(ctx context.Context, address string) (quic.Connection, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if we already have a session for this address
	if session, ok := c.sessions[address]; ok && session.Context().Err() == nil {
		return session, nil
	}

	// Connect to the peer
	session, err := quic.DialAddr(ctx, address, c.tlsConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}

	c.sessions[address] = session
	return session, nil
}

// OpenStream opens a new stream of the specified kind
func (c *Client) OpenStream(ctx context.Context, session quic.Connection, kind StreamKind) (quic.Stream, error) {
	// Open a new stream
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Write the stream kind as the first byte
	_, err = stream.Write([]byte{byte(kind)})
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write stream kind: %w", err)
	}

	return stream, nil
}

// Close closes all active sessions
func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var lastErr error
	for addr, session := range c.sessions {
		err := session.CloseWithError(0, "client closed")
		if err != nil {
			lastErr = err
		}
		delete(c.sessions, addr)
	}

	return lastErr
}
