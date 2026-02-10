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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"jam/pkg/block/extrinsics"
	"jam/pkg/block/header"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"log"
	"math"
	"math/big"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// NodeOptions configures a JAMNP-S Node
type NodeOptions struct {
	PrivateKey  []byte        // Ed25519 private key (64 bytes)
	ChainID     string        // Chain ID
	ListenAddr  string        // Address to listen on (default: ":40000")
	DialTimeout time.Duration // Timeout for outbound connections (default: 30s)
	IsBuilder   bool
}

// ValidatorInfo contains validator information including keyset and index
type ValidatorInfo struct {
	Keyset types.ValidatorKeyset
	Index  int
}

// Node is a unified JAMNP-S node that can both initiate and accept connections
type Node struct {
	opts            NodeOptions
	tlsConfig       *tls.Config
	quicConfig      *quic.Config
	listener        *quic.Listener
	listenAddr      string
	connections     sync.Map // Map of address -> connection
	myValidator     ValidatorInfo
	protocolHandler *ProtocolHandler // Handler for CE protocols with mempool
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
func GenerateAlternativeName(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
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
	// Go's x509 package returns ed25519.PublicKey for Ed25519 certificates
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

// Start starts the node using chain state for peer discovery (production mode)
// Deprecated: Use StartWithProvider for more flexibility
func (n *Node) Start(ctx context.Context) error {
	provider, err := NewChainStatePeerProvider(n.opts.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create chain state peer provider: %w", err)
	}
	return n.StartWithProvider(ctx, provider)
}

// StartWithProvider starts the node using the provided PeerProvider for peer discovery
func (n *Node) StartWithProvider(ctx context.Context, provider PeerProvider) error {
	// Get our own validator info
	myInfo, err := provider.GetMyInfo()
	if err != nil {
		return fmt.Errorf("failed to get own validator info: %w", err)
	}
	n.myValidator = *myInfo

	// Get all peers
	peers, err := provider.GetPeers()
	if err != nil {
		return fmt.Errorf("failed to get peers: %w", err)
	}

	totalValidators := provider.GetTotalValidators()

	// Partition peers into two sets: those where I am the preferred initiator and those where I am not
	myKey := n.opts.PrivateKey[32:] // Extract public key from private key
	var iAmInitiator []PeerInfo
	var theyAreInitiator []PeerInfo

	for _, peer := range peers {
		otherKey := peer.Ed25519[:]

		// Check if we are the preferred initiator using the formula from JAMNP-S spec
		// P(a, b) = a when (a[31] > 127) XOR (b[31] > 127) XOR (a < b)
		myKeyLast := myKey[31] > 127
		otherKeyLast := otherKey[31] > 127
		myKeyLessThan := bytes.Compare(myKey, otherKey) < 0

		// XOR operation for the three boolean conditions
		amPreferredInitiator := (myKeyLast != otherKeyLast) != myKeyLessThan

		if amPreferredInitiator {
			iAmInitiator = append(iAmInitiator, peer)
		} else {
			theyAreInitiator = append(theyAreInitiator, peer)
		}
	}

	log.Printf("[Node %d] Partitioned %d peers: I initiate to %d, waiting for %d to connect",
		n.myValidator.Index, len(peers), len(iAmInitiator), len(theyAreInitiator))

	// Start listening
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
	log.Printf("[Node %d] Listening on %s", n.myValidator.Index, n.listenAddr)

	// Use a WaitGroup to wait for both accepting and initiating connections to complete
	var wg sync.WaitGroup

	// Start accepting connections in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		n.acceptConnectionsFromPeers(ctx, theyAreInitiator, totalValidators)
	}()

	// Start outbound connections to peers where I am the initiator
	for _, peer := range iAmInitiator {
		wg.Add(1)
		go func(p PeerInfo) {
			defer wg.Done()
			n.initiateConnectionToPeer(ctx, p, totalValidators)
		}(peer)
	}

	// Wait for all connections (both incoming and outgoing) to be established
	wg.Wait()

	log.Printf("[Node %d] All %d peers connected", n.myValidator.Index, len(peers))
	return nil
}

// acceptConnectionsFromPeers accepts incoming connections from expected peers
func (n *Node) acceptConnectionsFromPeers(ctx context.Context, expectedPeers []PeerInfo, totalValidators int) {
	if len(expectedPeers) == 0 {
		log.Printf("[Node %d] No incoming connections expected", n.myValidator.Index)
		return
	}

	// Create a map for faster lookup of expected peers by public key
	expectedByKey := make(map[string]PeerInfo)
	for _, peer := range expectedPeers {
		expectedByKey[hex.EncodeToString(peer.Ed25519[:])] = peer
	}

	log.Printf("[Node %d] Waiting for %d incoming connections", n.myValidator.Index, len(expectedPeers))

	// Channel to signal when a connection is successfully established
	connectionEstablished := make(chan string, len(expectedPeers))
	connectedPeers := make(map[string]bool)

	// Channel to deliver new QUIC connections
	newConnections := make(chan *quic.Conn, 1)

	// Goroutine to accept connections and forward them to the channel
	go func() {
		for {
			quicConn, err := n.listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled
				}
				log.Printf("[Node %d] Error accepting connection: %v", n.myValidator.Index, err)
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
		select {
		case peerKey := <-connectionEstablished:
			connectedPeers[peerKey] = true
			log.Printf("[Node %d] Accepted connection from peer (%d/%d connected)",
				n.myValidator.Index, len(connectedPeers), len(expectedPeers))

			if len(connectedPeers) == len(expectedPeers) {
				log.Printf("[Node %d] All expected incoming connections established", n.myValidator.Index)
				return
			}

		case quicConn := <-newConnections:
			go func(conn *quic.Conn) {
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

				remoteKeyStr := hex.EncodeToString(remoteKey)
				peerInfo, isExpected := expectedByKey[remoteKeyStr]

				if !isExpected {
					conn.CloseWithError(0, "peer not in expected list")
					log.Printf("[Node %d] Rejected unexpected connection from %s", n.myValidator.Index, remoteKeyStr[:16])
					return
				}

				// Check if already connected
				if _, exists := n.connections.Load(remoteKeyStr); exists {
					conn.CloseWithError(0, "already connected")
					return
				}

				// Create ValidatorInfo from PeerInfo
				validatorInfo := peerInfoToValidatorInfo(peerInfo)

				err := n.createAndStoreConnection(ctx, conn, validatorInfo, true, totalValidators)
				if err != nil {
					log.Printf("[Node %d] Failed to create connection for peer %d: %v",
						n.myValidator.Index, peerInfo.Index, err)
					return
				}

				select {
				case connectionEstablished <- remoteKeyStr:
				default:
					log.Printf("[Node %d] Warning: Could not signal connection from peer %d",
						n.myValidator.Index, peerInfo.Index)
				}
			}(quicConn)

		case <-ctx.Done():
			return
		}
	}
}

// initiateConnectionToPeer establishes an outbound connection to a peer
func (n *Node) initiateConnectionToPeer(ctx context.Context, peer PeerInfo, totalValidators int) {
	for attempts := 0; attempts < 3; attempts++ {
		err := n.connectToPeer(ctx, peer, totalValidators)
		if err == nil {
			log.Printf("[Node %d] Connected to peer %d", n.myValidator.Index, peer.Index)
			return
		}

		log.Printf("[Node %d] Connection attempt %d to peer %d failed: %v",
			n.myValidator.Index, attempts+1, peer.Index, err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
			continue
		}
	}

	log.Printf("[Node %d] Failed to connect to peer %d after 3 attempts", n.myValidator.Index, peer.Index)
}

// connectToPeer establishes a connection to a specific peer
func (n *Node) connectToPeer(ctx context.Context, peer PeerInfo, totalValidators int) error {
	target := peer.Address

	log.Printf("[Node %d] Connecting to peer %d at %s", n.myValidator.Index, peer.Index, target)

	dialCtx, cancel := context.WithTimeout(ctx, n.opts.DialTimeout)
	defer cancel()

	conn, err := quic.DialAddrEarly(dialCtx, target, n.tlsConfig, n.quicConfig)
	if err != nil {
		return fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	validatorInfo := peerInfoToValidatorInfo(peer)

	if err = n.createAndStoreConnection(ctx, conn, validatorInfo, false, totalValidators); err != nil {
		return fmt.Errorf("failed to create and store connection: %w", err)
	}

	return nil
}

// peerInfoToValidatorInfo converts PeerInfo to ValidatorInfo
func peerInfoToValidatorInfo(peer PeerInfo) ValidatorInfo {
	var keyset types.ValidatorKeyset
	if peer.Keyset != nil {
		keyset = *peer.Keyset
	} else {
		// For config-based peers, create minimal keyset with Ed25519 key
		copy(keyset[32:64], peer.Ed25519[:])
	}
	return ValidatorInfo{
		Keyset: keyset,
		Index:  peer.Index,
	}
}

// createAndStoreConnection creates a JAMNP-S connection from a QUIC connection and stores it
func (n *Node) createAndStoreConnection(ctx context.Context, quicConn *quic.Conn, validatorInfo ValidatorInfo, initializedByRemote bool, totalValidators int) error {
	// Create JAMNP-S connection (this will register handlers, start accepting streams, and open required streams)
	// Extract public key from private key (last 32 bytes)
	publicKey := n.opts.PrivateKey[32:]
	conn, err := NewConnection(ctx, quicConn, publicKey, validatorInfo, initializedByRemote, n.myValidator.Index, totalValidators)
	if err != nil {
		quicConn.CloseWithError(0, "failed to create connection")
		return fmt.Errorf("failed to create JAMNP-S connection: %w", err)
	}

	// Register CE protocol handlers if we have a protocol handler
	if n.protocolHandler != nil {
		if jconn, ok := conn.(*jamnpsConnection); ok {
			n.protocolHandler.RegisterHandlers(jconn)
		}
	}

	// Store the connection in the map
	n.connections.Store(hex.EncodeToString(conn.RemoteKey()), conn)

	return nil
}

// SetProtocolHandler sets the protocol handler for CE streams
func (n *Node) SetProtocolHandler(ph *ProtocolHandler) {
	n.protocolHandler = ph
}

// GetProtocolHandler returns the protocol handler
func (n *Node) GetProtocolHandler() *ProtocolHandler {
	return n.protocolHandler
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
func generateCertificate(privateKeyBytes []byte) (tls.Certificate, error) {
	// Convert []byte to ed25519.PrivateKey (implements crypto.Signer)
	privateKey := ed25519.PrivateKey(privateKeyBytes)
	// Extract public key from private key (last 32 bytes)
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
	// Note: publicKey must be ed25519.PublicKey, privateKey must be ed25519.PrivateKey (implements crypto.Signer)
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create a tls.Certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey, // ed25519.PrivateKey implements crypto.Signer
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

// getGridNeighborConnections returns all connections to grid neighbors
func (n *Node) getGridNeighborConnections() []*jamnpsConnection {
	var neighbors []*jamnpsConnection
	n.connections.Range(func(key, value interface{}) bool {
		jconn, ok := value.(*jamnpsConnection)
		if ok && jconn.isNeighbor {
			neighbors = append(neighbors, jconn)
		}
		return true
	})
	return neighbors
}

// ForEachGridNeighbor runs a function for each grid neighbor connection
func (n *Node) ForEachGridNeighbor(fn func(*jamnpsConnection)) {
	for _, conn := range n.getGridNeighborConnections() {
		fn(conn)
	}
}

// BroadcastCE broadcasts data to all grid neighbors via a CE stream
// Opens a new stream for each neighbor, sends data, and closes
func (n *Node) BroadcastCE(streamKind StreamKind, data []byte, label string) {
	n.ForEachGridNeighbor(func(conn *jamnpsConnection) {
		go func(c *jamnpsConnection) {
			stream, err := c.OpenStream(streamKind)
			if err != nil {
				log.Printf("[%s] Failed to open stream to validator %d: %v", label, c.ValidatorIdx(), err)
				return
			}
			defer stream.Close()

			if err := WriteMessage(stream, data); err != nil {
				log.Printf("[%s] Failed to send to validator %d: %v", label, c.ValidatorIdx(), err)
				return
			}

			stream.CloseWrite()
			log.Printf("[%s] Sent to validator %d", label, c.ValidatorIdx())
		}(conn)
	})
}

// BroadcastTicket sends a ticket to all grid neighbors via CE 132
func (n *Node) BroadcastTicket(epochIndex uint32, ticket extrinsics.Ticket) {
	n.BroadcastCE(StreamKindCE132TicketDistribution, EncodeTicket(epochIndex, ticket), "CE 132")
}

// BroadcastAssurance sends an assurance to all grid neighbors via CE 141
func (n *Node) BroadcastAssurance(assurance extrinsics.Assurance) {
	n.BroadcastCE(StreamKindCE141AssuranceDistribution, EncodeAssurance(assurance), "CE 141")
}

// BroadcastGuarantee sends a guaranteed work-report to all grid neighbors via CE 135
func (n *Node) BroadcastGuarantee(guarantee extrinsics.Guarantee) {
	n.BroadcastCE(StreamKindCE135WorkReportDistribution, serializer.Serialize(guarantee), "CE 135")
}

// BroadcastJudgment sends a judgment to all grid neighbors via CE 145
func (n *Node) BroadcastJudgment(epochIndex uint32, validatorIndex types.ValidatorIndex, validity bool, workReportHash [32]byte, signature types.Ed25519Signature) {
	n.BroadcastCE(StreamKindCE145JudgmentPublication, EncodeJudgment(epochIndex, validatorIndex, validity, workReportHash, signature), "CE 145")
}

// BroadcastUP broadcasts data to all grid neighbors via an existing UP stream
func (n *Node) BroadcastUP(streamKind StreamKind, data []byte, label string) error {
	var broadcastErrors []error

	n.ForEachGridNeighbor(func(conn *jamnpsConnection) {
		conn.upStreamsMu.Lock()
		stream, exists := conn.upStreams[streamKind]
		conn.upStreamsMu.Unlock()

		if !exists || stream == nil {
			log.Printf("[%s] No stream to validator %d", label, conn.ValidatorIdx())
			return
		}

		if err := WriteMessage(stream, data); err != nil {
			log.Printf("[%s] Failed to send to validator %d: %v", label, conn.ValidatorIdx(), err)
			broadcastErrors = append(broadcastErrors, err)
		} else {
			log.Printf("[%s] Sent to validator %d", label, conn.ValidatorIdx())
		}
	})

	if len(broadcastErrors) > 0 {
		return fmt.Errorf("failed to broadcast to %d peers", len(broadcastErrors))
	}
	return nil
}

// BroadcastBlockAnnouncement sends a block announcement to all grid neighbors via UP 0
func (n *Node) BroadcastBlockAnnouncement(hdr header.Header, finalHash [32]byte, finalSlot types.Timeslot) error {
	announcement := Announcement{
		Header: hdr,
		Final: Final{
			HeaderHash:    finalHash,
			FinalizedSlot: finalSlot,
		},
	}
	return n.BroadcastUP(StreamKindUP0BlockAnnouncement, serializer.Serialize(announcement), "UP 0")
}
