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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"jam/pkg/state"
	"jam/pkg/types"
	"log"
	"math"
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
	DialTimeout time.Duration      // Timeout for outbound connections (default: 30s)
	IsBuilder   bool
}

// ValidatorInfo contains validator information including keyset and index
type ValidatorInfo struct {
	Keyset types.ValidatorKeyset
	Index  int
}

// Node is a unified JAMNP-S node that can both initiate and accept connections
type Node struct {
	opts        NodeOptions
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	listener    *quic.Listener
	listenAddr  string
	connections sync.Map // Map of address -> connection
	myValidator ValidatorInfo
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

var (
	globalNode *Node
	nodeMutex  sync.RWMutex
	nodeOnce   sync.Once
)

// InitializeGlobalNode initializes the global singleton Node instance
func InitializeGlobalNode(opts NodeOptions) error {
	var initErr error
	nodeOnce.Do(func() {
		node, err := NewNode(opts)
		if err != nil {
			initErr = err
			return
		}

		nodeMutex.Lock()
		globalNode = node
		nodeMutex.Unlock()
	})
	return initErr
}

// GetGlobalNode returns the global singleton Node instance
func GetGlobalNode() *Node {
	nodeMutex.RLock()
	defer nodeMutex.RUnlock()
	return globalNode
}

// IsGlobalNodeInitialized checks if the global node has been initialized
func IsGlobalNodeInitialized() bool {
	nodeMutex.RLock()
	defer nodeMutex.RUnlock()
	return globalNode != nil
}

// NewNode creates a new JAMNP-S node
func NewNode(opts NodeOptions) (*Node, error) {

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
		connections: sync.Map{},
	}

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

// Start starts the node. Initiate connections and UP 0 stream
func (n *Node) Start(ctx context.Context) error {
	state, err := state.GetState()
	if err != nil {
		return fmt.Errorf("failed to get state: %w", err)
	}

	// Partition validators into two sets: those where I am the preferred initiator and those where I am not
	myKey := n.opts.PrivateKey.Public().(ed25519.PublicKey)
	var iAmInitiator []ValidatorInfo
	var theyAreInitiator []ValidatorInfo

	amValidator := false
	for idx, validatorKeyset := range state.ValidatorKeysetsActive {
		publicKey := validatorKeyset.ToEd25519PublicKey()
		if bytes.Equal(publicKey[:], myKey) {
			log.Printf("Skipping connection to self (validator %d)", idx)
			n.myValidator = ValidatorInfo{Keyset: validatorKeyset, Index: idx}
			amValidator = true
			continue
		}

		otherKey := publicKey[:]

		// Check if we are the preferred initiator using the formula
		myKeyLast := myKey[31] > 127
		otherKeyLast := otherKey[31] > 127
		myKeyLessThan := bytes.Compare(myKey, otherKey) < 0

		// XOR operation for the three boolean conditions
		amPreferredInitiator := (myKeyLast != otherKeyLast) != myKeyLessThan

		if amPreferredInitiator {
			iAmInitiator = append(iAmInitiator, ValidatorInfo{Keyset: validatorKeyset, Index: idx})
		} else {
			theyAreInitiator = append(theyAreInitiator, ValidatorInfo{Keyset: validatorKeyset, Index: idx})
		}
	}
	if !amValidator {
		log.Fatalf("Failed to find self validator")
	}

	log.Printf("Partitioned validators: I am initiator for %d validators, waiting for %d validators to connect to me",
		len(iAmInitiator), len(theyAreInitiator))

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

	// Use a WaitGroup to wait for both accepting and initiating connections to complete
	var wg sync.WaitGroup

	// Start accepting connections in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.acceptConnections(ctx, theyAreInitiator, len(state.ValidatorKeysetsActive))
	}()

	// Start outbound connections to validators where I am the initiator
	for _, v := range iAmInitiator {
		wg.Add(1)
		go func(validator ValidatorInfo) {
			defer wg.Done()
			n.initiateConnection(ctx, validator, len(state.ValidatorKeysetsActive))
		}(v)
	}

	// Wait for all connections (both incoming and outgoing) to be established
	wg.Wait()

	log.Printf("Network node started, listening at %s", n.listenAddr)
	return nil
}

// createAndStoreConnection creates a JAMNP-S connection from a QUIC connection and stores it
func (n *Node) createAndStoreConnection(ctx context.Context, quicConn quic.Connection, validatorInfo ValidatorInfo, initializedByRemote bool, totalValidators int) error {
	// Create JAMNP-S connection (this will register handlers, start accepting streams, and open required streams)
	conn, err := NewConnection(ctx, quicConn, n.opts.PrivateKey.Public().(ed25519.PublicKey), validatorInfo, initializedByRemote, n.myValidator.Index, totalValidators)
	if err != nil {
		quicConn.CloseWithError(0, "failed to create connection")
		return fmt.Errorf("failed to create JAMNP-S connection: %w", err)
	}

	// Store the connection in the map
	n.connections.Store(hex.EncodeToString(conn.RemoteKey()), conn)

	return nil
}

// acceptConnections accepts incoming connections
func (n *Node) acceptConnections(ctx context.Context, theyAreInitiator []ValidatorInfo, totalValidators int) {
	// Create a map for faster lookup of expected validators by public key
	expectedValidators := make(map[string]ValidatorInfo)
	for _, validator := range theyAreInitiator {
		publicKey := validator.Keyset.ToEd25519PublicKey()
		expectedValidators[hex.EncodeToString(publicKey[:])] = validator
	}

	log.Printf("Accepting connections from %d expected validators", len(expectedValidators))

	// Channel to signal when a connection is successfully established
	connectionEstablished := make(chan string, len(expectedValidators))
	connectedValidators := make(map[string]bool)

	// Channel to deliver new QUIC connections
	newConnections := make(chan quic.Connection, 1)

	// Goroutine to accept connections and forward them to the channel
	go func() {
		for {
			quicConn, err := n.listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled
				}
				fmt.Printf("Error accepting connection: %v\n", err)
				continue
			}

			select {
			case newConnections <- quicConn:
				// Successfully forwarded
			case <-ctx.Done():
				quicConn.CloseWithError(0, "shutting down")
				return
			}
		}
	}()

	for {
		// Use blocking select to handle either connection signals or new connections
		select {
		case validatorKey := <-connectionEstablished:
			connectedValidators[validatorKey] = true
			log.Printf("Connected validator %s (%d/%d validators connected)",
				validatorKey, len(connectedValidators), len(expectedValidators))

			if len(connectedValidators) == len(expectedValidators) {
				log.Printf("All %d expected validators have connected. Stopping acceptance of new connections.", len(expectedValidators))
				return
			}

		case quicConn := <-newConnections:
			// Handle the connection in a goroutine
			go func(conn quic.Connection) {
				// Extract the peer's public key from the TLS certificate
				tlsState := conn.ConnectionState().TLS
				if len(tlsState.PeerCertificates) == 0 {
					conn.CloseWithError(0, "no client certificate")
					return
				}

				cert := tlsState.PeerCertificates[0]
				remoteKey, ok := cert.PublicKey.(ed25519.PublicKey)
				if !ok {
					conn.CloseWithError(0, "invalid certificate key type")
					return
				}

				// Check if this validator is in the expected list
				remoteKeyStr := fmt.Sprintf("%x", remoteKey)
				validatorInfo, isExpected := expectedValidators[remoteKeyStr]

				if !isExpected {
					conn.CloseWithError(0, "validator not in expected initiator list")
					fmt.Printf("Rejected connection from unexpected validator with key: %s\n", remoteKeyStr)
					return
				}

				// Check if this validator has already connected by checking if it's already in connections
				if _, exists := n.connections.Load(remoteKeyStr); exists {
					conn.CloseWithError(0, "validator already connected")
					fmt.Printf("Rejected duplicate connection from validator with key: %s\n", remoteKeyStr)
					return
				}

				err := n.createAndStoreConnection(ctx, conn, validatorInfo, true, totalValidators)
				if err != nil {
					fmt.Printf("Failed to create connection for validator %s: %v\n", remoteKeyStr, err)
					return
				}

				// Signal that this connection has been successfully established
				select {
				case connectionEstablished <- remoteKeyStr:
					// Successfully signaled
				default:
					// Channel might be full or closed, but connection is still established
					log.Printf("Warning: Could not signal connection establishment for %s", remoteKeyStr)
				}
			}(quicConn)

		case <-ctx.Done():
			return
		}
	}
}

// initiateConnection establishes an outbound connection to a validator where this node is the initiator
func (n *Node) initiateConnection(ctx context.Context, validator ValidatorInfo, totalValidators int) {
	// Establish connection with retry logic
	for attempts := 0; attempts < 3; attempts++ {
		err := n.Connect(ctx, validator, totalValidators)
		if err == nil {
			log.Printf("Successfully connected to validator %d", validator.Index)
			return
		}

		log.Printf("Connection attempt %d to validator %d failed: %v",
			attempts+1, validator.Index, err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
			continue
		}
	}

	log.Printf("Failed to connect to validator %d after 3 attempts", validator.Index)
}

// Connect establishes an outbound connection to the given address
func (n *Node) Connect(ctx context.Context, validatorInfo ValidatorInfo, totalValidators int) error {
	// Extract the last 128 bytes which contain network information
	networkInfo := validatorInfo.Keyset[len(validatorInfo.Keyset)-128:]

	// Extract IPv6 address (first 16 bytes of network info)
	ipv6Addr := networkInfo[:16]
	ipv6Str := net.IP(ipv6Addr).String()

	// Extract port (next 2 bytes in little endian)
	port := binary.LittleEndian.Uint16(networkInfo[16:18])

	// Construct target address
	target := fmt.Sprintf("[%s]:%d", ipv6Str, port)

	log.Printf("Connecting to validator %d at %s", validatorInfo.Index, target)

	// Create a context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, n.opts.DialTimeout)
	defer cancel()

	// Use the built-in QUIC DialAddrEarly which handles connection establishment properly
	conn, err := quic.DialAddrEarly(dialCtx, target, n.tlsConfig, n.quicConfig)
	if err != nil {
		return fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	if err = n.createAndStoreConnection(ctx, conn, validatorInfo, false, totalValidators); err != nil {
		return fmt.Errorf("failed to create and store connection: %w", err)
	}

	return nil
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

	// Close the listener
	var err error
	if n.listener != nil {
		err = n.listener.Close()
	}

	// Close all connections
	n.connections.Range(func(key, value interface{}) bool {
		conn := value.(Connection)
		conn.Close()
		return true
	})

	return err
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

// isGridNeighbor checks if two validators are neighbors in the grid structure
func isGridNeighbor(myIndex, theirIndex, totalValidators int) bool {
	if totalValidators <= 1 {
		return false
	}

	W := int(math.Sqrt(float64(totalValidators))) // floor(sqrt(V))

	myRow := myIndex / W
	myCol := myIndex % W
	theirRow := theirIndex / W
	theirCol := theirIndex % W

	// Same row or same column
	return myRow == theirRow || myCol == theirCol
}
