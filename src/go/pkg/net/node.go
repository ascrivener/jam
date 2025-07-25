package net

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// NodeOptions configures a JAMNP-S Node
type NodeOptions struct {
	PrivateKey  ed25519.PrivateKey // Ed25519 private key
	ChainID     string             // Chain ID
	ListenAddr  string             // Address to listen on (default: ":40000")
	DialTimeout time.Duration      // Timeout for outbound connections (default: 10s)
	IsBuilder   bool
}

// Node is a unified JAMNP-S node that can both initiate and accept connections
type Node struct {
	opts        NodeOptions
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	listener    *quic.Listener
	listenAddr  string
	connections map[string]Connection        // Map of address -> connection
	peerKeys    map[string]ed25519.PublicKey // Map of peer key -> connection
	acceptCond  *sync.Cond                   // Condition variable for AcceptFrom
	acceptMtx   sync.Mutex                   // Mutex for acceptCond
	incomingCh  chan incomingConn            // Channel for incoming connections
	closeCh     chan struct{}                // Channel for close signal
	closed      bool                         // Whether the node is closed
	closeMtx    sync.Mutex                   // Mutex for closed
}

// incomingConn represents an incoming connection with its public key
type incomingConn struct {
	conn      Connection
	publicKey ed25519.PublicKey
}

// OIDs for certificate extensions
var (
	// OID for KeyUsage extension
	oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
	// OID for ExtKeyUsage extension
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// AlternativeNameEncoding is the encoding used for the alternative name
const AlternativeNameEncoding = "abcdefghijklmnopqrstuvwxyz234567"

// NewNode creates a new JAMNP-S node
func NewNode(opts NodeOptions) (*Node, error) {
	// Set default values
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":40000"
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}

	// Generate TLS certificate
	cert, err := generateCertificate(opts.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	// Set ALPN protocol identifier according to JAMNP-S spec
	// Format: jamnp-s/V/H or jamnp-s/V/H/builder
	alpnProto := fmt.Sprintf("jamnp-s/0/%s", opts.ChainID)
	if opts.IsBuilder {
		alpnProto += "/builder"
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Require TLS 1.3
		// Custom verification to validate peer certificate
		VerifyPeerCertificate: verifyPeerCertificate,
		// Set ALPN protocol identifier according to JAMNP-S spec
		NextProtos: []string{alpnProto},
		// Disable standard certificate verification to avoid key size errors
		InsecureSkipVerify: true,
		// Explicitly enable client certificate
		ClientAuth: tls.RequireAnyClientCert,
		// Always send the client certificate
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	// Configure QUIC
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		EnableDatagrams:      false,
		Tracer: func(ctx context.Context, p logging.Perspective, connID logging.ConnectionID) *logging.ConnectionTracer {
			fmt.Printf("QUIC connection trace started: %v, %v\n", p, connID)
			return &logging.ConnectionTracer{
				StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
					fmt.Printf("QUIC connection started: %v -> %v\n", local, remote)
				},
				ClosedConnection: func(err error) {
					fmt.Printf("QUIC connection closed: %v\n", err)
				},
				SentTransportParameters: func(parameters *logging.TransportParameters) {
					fmt.Printf("QUIC sent transport parameters\n")
				},
				ReceivedTransportParameters: func(parameters *logging.TransportParameters) {
					fmt.Printf("QUIC received transport parameters\n")
				},
				ChoseALPN: func(protocol string) {
					fmt.Printf("QUIC chose ALPN protocol: %s\n", protocol)
				},
				Debug: func(name, msg string) {
					fmt.Printf("QUIC debug [%s]: %s\n", name, msg)
				},
			}
		},
	}

	node := &Node{
		opts:        opts,
		tlsConfig:   tlsConfig,
		quicConfig:  quicConfig,
		listenAddr:  opts.ListenAddr,
		connections: make(map[string]Connection),
		peerKeys:    make(map[string]ed25519.PublicKey),
		incomingCh:  make(chan incomingConn),
		closeCh:     make(chan struct{}),
	}

	// Initialize condition variable
	node.acceptCond = sync.NewCond(&node.acceptMtx)

	return node, nil
}

// GenerateAlternativeName generates the alternative name for a certificate
// using the algorithm specified in the JAMNP-S protocol
func GenerateAlternativeName(pubKey ed25519.PublicKey) (string, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key size: %d", len(pubKey))
	}

	// Create a big.Int from the public key (little-endian)
	n := new(big.Int)
	// Reverse the bytes for little-endian interpretation
	revBytes := make([]byte, len(pubKey))
	for i, b := range pubKey {
		revBytes[len(pubKey)-1-i] = b
	}
	n.SetBytes(revBytes)

	// Generate the alternative name using the B function from spec
	result := "e" // Start with 'e' as per spec

	// Constants for the loop
	thirtytwo := big.NewInt(32)
	mod := new(big.Int)

	for i := 0; i < 52; i++ {
		// Get the remainder when divided by 32
		mod = mod.Mod(n, thirtytwo)
		idx := int(mod.Int64())
		result += string(AlternativeNameEncoding[idx])

		// Divide by 32 for the next iteration
		n.Div(n, thirtytwo)
	}

	return result, nil
}

// verifyPeerCertificate verifies that the peer's certificate follows the JAMNP-S spec
func verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificate provided by peer")
	}

	// Parse the peer's certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	// Check that the certificate uses Ed25519
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("peer certificate does not use Ed25519 key")
	}

	// Check that the certificate has exactly one DNS SANs
	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("peer certificate must have exactly one DNS name, has %d",
			len(cert.DNSNames))
	}

	// Generate the expected alternative name
	expectedName, err := GenerateAlternativeName(publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate expected name: %w", err)
	}

	// Verify the alternative name
	if cert.DNSNames[0] != expectedName {
		return fmt.Errorf("peer certificate DNS name does not match expected name: %s vs %s",
			cert.DNSNames[0], expectedName)
	}

	return nil
}

// Start starts the node's listener to accept incoming connections
func (n *Node) Start(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	listener, err := quic.Listen(conn, n.tlsConfig, n.quicConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	n.listener = listener

	// Start accepting connections in a goroutine
	go n.acceptLoop(ctx)

	return nil
}

// acceptLoop accepts incoming connections
func (n *Node) acceptLoop(ctx context.Context) {
	for {
		// Check if the context is done or the node is closed
		select {
		case <-ctx.Done():
			return
		case <-n.closeCh:
			return
		default:
		}

		// Accept a new connection
		quicConn, err := n.listener.Accept(ctx)
		if err != nil {
			// Check if the error is due to listener closing
			if n.isClosed() {
				return
			}

			// Log the error and continue
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		// Handle the connection in a goroutine
		go n.handleIncomingConnection(quicConn)
	}
}

// handleIncomingConnection processes an incoming QUIC connection
func (n *Node) handleIncomingConnection(quicConn quic.Connection) {
	// Extract the peer's public key from the TLS certificate
	tlsState := quicConn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		quicConn.CloseWithError(0, "no client certificate")
		return
	}

	cert := tlsState.PeerCertificates[0]
	remoteKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		quicConn.CloseWithError(0, "invalid certificate key type")
		return
	}

	// Create a JAMNP-S connection
	conn, err := NewConnection(quicConn, n.opts.PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		quicConn.CloseWithError(0, "failed to create connection")
		return
	}

	// Send the connection to the incoming channel
	select {
	case n.incomingCh <- incomingConn{conn: conn, publicKey: remoteKey}:
		// Connection will be handled by AcceptFrom or another method
	case <-n.closeCh:
		conn.Close()
		return
	}

	// Store the public key for this connection
	peerKeyStr := fmt.Sprintf("%x", remoteKey)

	n.acceptMtx.Lock()
	n.peerKeys[peerKeyStr] = remoteKey
	n.acceptMtx.Unlock()

	// Signal that a new connection has been accepted
	n.acceptCond.Broadcast()
}

// AcceptFrom waits for a connection from a specific validator by public key
func (n *Node) AcceptFrom(ctx context.Context, publicKey ed25519.PublicKey) (Connection, error) {

	// Check if we already have a connection from this peer
	n.acceptMtx.Lock()
	defer n.acceptMtx.Unlock()

	// Set up a goroutine to check the incoming channel
	connCh := make(chan Connection, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			select {
			case incoming := <-n.incomingCh:
				// Check if this is the peer we're waiting for
				if bytes.Equal(incoming.publicKey, publicKey) {
					connCh <- incoming.conn
					return
				}

				// Not the peer we're looking for, close and continue
				incoming.conn.Close()

			case <-ctx.Done():
				errCh <- ctx.Err()
				return

			case <-n.closeCh:
				errCh <- fmt.Errorf("node closed")
				return
			}
		}
	}()

	// Wait for either a connection or an error
	select {
	case conn := <-connCh:
		return conn, nil

	case err := <-errCh:
		return nil, err

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Connect establishes an outbound connection to the given address
func (n *Node) Connect(ctx context.Context, address string) (Connection, error) {
	// Check if we already have a connection to this address
	n.acceptMtx.Lock()
	if conn, ok := n.connections[address]; ok {
		n.acceptMtx.Unlock()
		return conn, nil
	}
	n.acceptMtx.Unlock()

	// Create a context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, n.opts.DialTimeout)
	defer cancel()

	// Resolve the address
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// Dial the UDP address
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}

	// Establish QUIC connection
	quicConn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, n.tlsConfig, n.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	// Create JAMNP-S connection
	conn, err := NewConnection(quicConn, n.opts.PrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		quicConn.CloseWithError(0, "failed to create connection")
		return nil, fmt.Errorf("failed to create JAMNP-S connection: %w", err)
	}

	// Extract peer's public key
	tlsState := quicConn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		conn.Close()
		return nil, fmt.Errorf("no server certificate")
	}

	cert := tlsState.PeerCertificates[0]
	remoteKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("invalid certificate key type")
	}

	// Store the connection
	n.acceptMtx.Lock()
	n.connections[address] = conn
	n.peerKeys[fmt.Sprintf("%x", remoteKey)] = remoteKey
	n.acceptMtx.Unlock()

	return conn, nil
}

// Addr returns the listening address
func (n *Node) Addr() net.Addr {
	if n.listener == nil {
		return nil
	}
	return n.listener.Addr()
}

// Close closes the node and all its connections
func (n *Node) Close() error {
	n.closeMtx.Lock()
	defer n.closeMtx.Unlock()

	if n.closed {
		return nil
	}

	n.closed = true
	close(n.closeCh)

	// Close the listener
	var err error
	if n.listener != nil {
		err = n.listener.Close()
	}

	// Close all connections
	n.acceptMtx.Lock()
	for _, conn := range n.connections {
		conn.Close()
	}
	n.connections = make(map[string]Connection)
	n.peerKeys = make(map[string]ed25519.PublicKey)
	n.acceptMtx.Unlock()

	return err
}

// isClosed checks if the node is closed
func (n *Node) isClosed() bool {
	n.closeMtx.Lock()
	defer n.closeMtx.Unlock()
	return n.closed
}

// generateCertificate creates a self-signed certificate for the JAMNP-S client
func generateCertificate(privateKey ed25519.PrivateKey) (tls.Certificate, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	// Generate alternative name from public key
	altName, err := GenerateAlternativeName(publicKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate alternative name: %w", err)
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create a minimal certificate template without any KeyUsage or BasicConstraints
	// This ensures Go doesn't automatically add critical extensions
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "JAM Client Ed25519 Cert", // Match the OpenSSL -subj
		},
		DNSNames:  []string{altName},
		NotBefore: time.Now().Add(-time.Hour),  // Valid from 1 hour ago
		NotAfter:  time.Now().AddDate(1, 0, 0), // Valid for 1 year
		// KeyUsage and BasicConstraints intentionally left empty
	}

	// Create non-critical extensions for compatibility

	// 1. BasicConstraints with CA:TRUE
	// DER encoding for BasicConstraints with CA:TRUE
	basicConstraintsBytes := []byte{0x30, 0x03, 0x01, 0x01, 0xff} // SEQUENCE { BOOLEAN TRUE }

	// 2. KeyUsage with digitalSignature and keyCertSign
	// BIT STRING where bits are counted from the right (LSB) to left (MSB)
	// digitalSignature is bit 0 (value 1<<0 = 1)
	// keyCertSign is bit 5 (value 1<<5 = 32)
	// Combined value is 1+32 = 33 (00100001 in binary)
	// With 0 unused bits, the encoding is:
	keyUsageBytes := []byte{0x03, 0x02, 0x00, 0x21} // BIT STRING, 2 bytes, 0 unused bits, value 00100001

	// Add our custom extensions
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // BasicConstraints OID
			Critical: false,                               // Must be non-critical to avoid TLS handshake errors
			Value:    basicConstraintsBytes,
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // KeyUsage OID
			Critical: false,                               // Must be non-critical to avoid TLS handshake errors
			Value:    keyUsageBytes,
		},
	}

	// Create the certificate with our manually added non-critical extensions
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create a tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}

	return tlsCert, nil
}

// OpenBlockAnnouncementStream opens a UP 0 block announcement stream
func (n *Node) OpenBlockAnnouncementStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindUP0BlockAnnouncement)
}

// OpenAssuranceDistributionStream opens a CE 141 assurance distribution stream
func (n *Node) OpenAssuranceDistributionStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE141AssuranceDistribution)
}

// OpenStateRequestStream opens a CE 129 state request stream
func (n *Node) OpenStateRequestStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE129StateRequest)
}

// OpenBlockRequestStream opens a CE 2 block request stream
func (n *Node) OpenBlockRequestStream(ctx context.Context, conn Connection) (Stream, error) {
	return conn.OpenStream(StreamKindCE2BlockRequest)
}

// RequestBlocks requests blocks from a node
func (n *Node) RequestBlocks(ctx context.Context, conn Connection, hash [32]byte, direction Direction, maxBlocks uint32) ([][]byte, error) {
	// Open a block request stream
	stream, err := conn.OpenStream(StreamKindCE2BlockRequest)
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
func (n *Node) RequestState(ctx context.Context, conn Connection, options *StateRequestOptions) (*StateResponse, error) {
	// Open a state request stream
	stream, err := conn.OpenStream(StreamKindCE129StateRequest)
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
func (n *Node) RequestWorkReport(ctx context.Context, conn Connection, hash [32]byte) ([]byte, error) {
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
func (n *Node) HandleBlockAnnouncements(conn Connection, handler func(*BlockAnnouncement) error) error {
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

	conn.RegisterHandler(StreamKindUP0BlockAnnouncement, streamHandler)
	return nil
}

// HandleAssuranceDistributions registers a handler for assurance distributions
func (n *Node) HandleAssuranceDistributions(conn Connection, handler func([]byte) error) error {
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
