package net

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/serializer"
	"jam/pkg/state"
	"jam/pkg/staterepository"
	"jam/pkg/types"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrStreamClosed is returned when a stream is closed
	ErrStreamClosed = errors.New("stream closed")

	// ErrConnectionClosed is returned when a connection is closed
	ErrConnectionClosed = errors.New("connection closed")

	// ErrInvalidStreamKind is returned when an invalid stream kind is specified
	ErrInvalidStreamKind = errors.New("invalid stream kind")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("operation timed out")
)

// jamnpsConnection implements the Connection interface
type jamnpsConnection struct {
	conn                quic.Connection
	localKey            ed25519.PublicKey
	validatorInfo       ValidatorInfo
	initializedByRemote bool
	isNeighbor          bool
	upStreams           map[StreamKind]quic.Stream
	upStreamsMu         sync.Mutex
	handlers            map[StreamKind]StreamHandler
	handlersMu          sync.RWMutex
	streams             map[quic.StreamID]Stream
	streamMu            sync.Mutex
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	acceptErrCh         chan error
}

// jamnpsStream implements the Stream interface
type jamnpsStream struct {
	stream    quic.Stream
	kind      StreamKind
	readMu    sync.Mutex
	writeMu   sync.Mutex
	writeBuf  *bytes.Buffer
	readBuf   *bytes.Buffer
	messageIn chan []byte
}

// NewConnection creates a new Connection from a QUIC connection
func NewConnection(ctx context.Context, conn quic.Connection, localKey ed25519.PublicKey, validatorInfo ValidatorInfo, initializedByRemote bool, myValidatorIndex int, totalValidators int) (Connection, error) {
	// Create connection context
	connCtx, cancel := context.WithCancel(ctx)

	connection := &jamnpsConnection{
		conn:                conn,
		localKey:            localKey,
		validatorInfo:       validatorInfo,
		initializedByRemote: initializedByRemote,
		upStreams:           make(map[StreamKind]quic.Stream),
		handlers:            make(map[StreamKind]StreamHandler),
		ctx:                 connCtx,
		cancel:              cancel,
		acceptErrCh:         make(chan error, 1),
		streams:             make(map[quic.StreamID]Stream),
	}

	// register all handlers
	connection.registerHandlers()

	// Start stream acceptor
	connection.wg.Add(1)
	go connection.acceptStreams()

	// open required streams
	connection.openRequiredBlockAnnouncementStreams(ctx, myValidatorIndex, totalValidators)

	return connection, nil
}

// acceptStreams handles incoming streams
func (c *jamnpsConnection) acceptStreams() {
	defer c.wg.Done()

	for {
		// Accept new stream
		stream, err := c.conn.AcceptStream(c.ctx)
		if err != nil {
			// Check if context was canceled or connection closed
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}

			select {
			case c.acceptErrCh <- err:
				// Error sent
			default:
				// Channel full, continue
			}

			// If this is a connection-level error, stop accepting
			if !errors.Is(err, io.EOF) {
				c.acceptErrCh <- err
				return
			}

			// Brief pause to avoid tight loops on transient errors
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Read stream kind byte
		kindBuf := make([]byte, 1)
		_, err = io.ReadFull(stream, kindBuf)
		if err != nil {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			continue
		}

		kind := StreamKind(kindBuf[0])

		// Handle UP streams specially
		if kind < 128 {
			c.handleUPStream(kind, stream)
		} else {
			c.handleStreamWithHandler(stream, kind, false)
		}
	}
}

// handleStreamWithHandler dispatches a stream to its registered handler
func (c *jamnpsConnection) handleStreamWithHandler(stream quic.Stream, kind StreamKind, isUPStream bool) {
	c.handlersMu.RLock()
	handler, ok := c.handlers[kind]
	c.handlersMu.RUnlock()

	if ok {
		// Handle stream in a goroutine
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			jstream := &jamnpsStream{
				stream: stream,
				kind:   kind,
			}

			err := handler(jstream)
			if err != nil {
				log.Printf("Stream handler error for kind %d from validator %d: %v",
					kind, c.ValidatorIdx(), err)

				// Close the stream on error to prevent resource leaks
				jstream.Close()

				// For UP streams, remove from the stored streams map
				if isUPStream {
					c.upStreamsMu.Lock()
					if storedStream, exists := c.upStreams[kind]; exists && storedStream.StreamID() == stream.StreamID() {
						delete(c.upStreams, kind)
						log.Printf("Removed failed UP stream %d from validator %d", kind, c.ValidatorIdx())
					}
					c.upStreamsMu.Unlock()
				}
			}

			if !isUPStream {
				// For CE streams, close automatically on handler return
				jstream.Close()
			}
			// For UP streams, we don't close automatically as they are long-lived
		}()
	} else {
		// No handler, reset the stream
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}
}

// handleUPStream processes a UP (Unique Persistent) stream
func (c *jamnpsConnection) handleUPStream(kind StreamKind, stream quic.Stream) {
	c.upStreamsMu.Lock()
	defer c.upStreamsMu.Unlock()

	// If we already have a stream for this kind, check if we should replace it
	if existing, ok := c.upStreams[kind]; ok {
		if stream.StreamID() > existing.StreamID() {
			// New stream has higher ID, replace the old one
			existing.CancelRead(0)
			existing.CancelWrite(0)
			delete(c.upStreams, kind)
		} else {
			// Existing stream has higher or equal ID, reject the new one
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return
		}
	}

	// Store the new stream
	c.upStreams[kind] = stream

	// Handle the stream with registered handler if available
	c.handleStreamWithHandler(stream, kind, true)
}

// OpenStream opens a new stream of the specified kind
func (c *jamnpsConnection) OpenStream(kind StreamKind) (Stream, error) {
	// Open a new QUIC stream
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Write the stream kind byte
	_, err = stream.Write([]byte{byte(kind)})
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, fmt.Errorf("failed to write stream kind: %w", err)
	}

	// If this is a UP stream, store it
	if kind < 128 {
		c.upStreamsMu.Lock()
		if existing, ok := c.upStreams[kind]; ok {
			// Close existing stream
			existing.CancelRead(0)
			existing.CancelWrite(0)
		}
		c.upStreams[kind] = stream
		c.upStreamsMu.Unlock()
	}

	return &jamnpsStream{
		stream: stream,
		kind:   kind,
	}, nil
}

// RegisterHandler registers a handler for a specific stream kind
func (c *jamnpsConnection) registerHandler(kind StreamKind, handler StreamHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers[kind] = handler
}

// RegisterHandlers registers handlers for all active connections
func (c *jamnpsConnection) registerHandlers() {
	// Register handler for incoming block announcements (UP 0)
	c.registerHandler(StreamKindUP0BlockAnnouncement, func(stream Stream) error {
		return c.handleBlockAnnouncementStream(stream)
	})

	// Register handler for incoming assurance distributions (CE 141)
	err := c.HandleAssuranceDistributions(func(data []byte) error {
		log.Printf("Received assurance distribution from validator %d: %d bytes",
			c.ValidatorIdx(), len(data))
		// TODO: Process the assurance distribution
		return nil
	})
	if err != nil {
		log.Printf("Warning: Failed to register assurance distribution handler for validator %d: %v",
			c.ValidatorIdx(), err)
	}
}

type Announcement struct {
	Header header.Header
	Final  Final
}

type Final struct {
	HeaderHash    [32]byte
	FinalizedSlot types.Timeslot
}

// HandleAssuranceDistributions registers a handler for assurance distributions
func (c *jamnpsConnection) HandleAssuranceDistributions(handler func([]byte) error) error {
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

	c.registerHandler(StreamKindCE141AssuranceDistribution, streamHandler)
	return nil
}

// openRequiredBlockAnnouncementStreams opens UP 0 streams to all grid neighbors where we are the initiator
func (c *jamnpsConnection) openRequiredBlockAnnouncementStreams(ctx context.Context, myValidatorIndex int, totalValidators int) {
	if c.initializedByRemote {
		log.Printf("Skipping UP 0 stream - not required for validator %d (initialized by remote)", c.validatorInfo.Index)
		return
	}
	if !isGridNeighbor(myValidatorIndex, c.validatorInfo.Index, totalValidators) {
		log.Printf("Skipping UP 0 stream - not required for validator %d (not a grid neighbor)", c.validatorInfo.Index)
		return
	}
	panic("unused rn")
	// err := c.openBlockAnnouncementStream(ctx)
	// if err != nil {
	// 	log.Printf("Warning: Failed to open UP 0 stream for validator %s: %v", c.RemoteKey(), err)
	// } else {
	// 	log.Printf("Successfully opened UP 0 stream for validator %s", c.RemoteKey())
	// }
}

// openBlockAnnouncementStream opens a UP 0 stream to a specific validator and performs handshake
func (c *jamnpsConnection) openBlockAnnouncementStream() error {
	// Open the UP 0 stream as the initiator
	stream, err := c.OpenStream(StreamKindUP0BlockAnnouncement)
	if err != nil {
		return fmt.Errorf("failed to open block announcement stream: %w", err)
	}

	// Use the unified parallel handshake and announcement handling
	if err := c.handleBlockAnnouncementStream(stream); err != nil {
		return fmt.Errorf("failed to handle block announcement stream: %w", err)
	}

	log.Printf("Completed block announcement stream handling")
	return nil
}

// Handshake data structures according to JAMNP-S specification
// Final = Header Hash ++ Slot
// Leaf = Header Hash ++ Slot
// Handshake = Final ++ len++[Leaf]

type HandshakeFinal struct {
	HeaderHash [32]byte
	Slot       types.Timeslot
}

type HandshakeLeaf struct {
	HeaderHash [32]byte
	Slot       types.Timeslot
}

type Handshake struct {
	Final  HandshakeFinal
	Leaves []HandshakeLeaf
}

// createHandshake creates a handshake message with current finalized block info and known leaves
func createHandshake() (Handshake, error) {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return Handshake{}, errors.New("global repository not initialized")
	}
	state, err := state.GetState()
	if err != nil {
		return Handshake{}, fmt.Errorf("failed to get state: %w", err)
	}
	// TODO: Get actual finalized block info from state
	// For now, use placeholder values
	latestFinalizedBlock := state.RecentActivity.RecentBlocks[len(state.RecentActivity.RecentBlocks)-1]

	latestFinalizedBlockInfo, err := block.Get(latestFinalizedBlock.HeaderHash)
	if err != nil {
		return Handshake{}, fmt.Errorf("failed to get latest finalized block info: %w", err)
	}
	finalHash := blake2b.Sum256(serializer.Serialize(latestFinalizedBlockInfo.Block.Header))
	finalSlot := latestFinalizedBlockInfo.Block.Header.TimeSlot

	// TODO: Get actual leaves (descendants of finalized block with no known children)
	// For now, use empty leaves array
	leaves := []HandshakeLeaf{
		{
			HeaderHash: finalHash,
			Slot:       finalSlot,
		},
	}

	return Handshake{
		Final: HandshakeFinal{
			HeaderHash: finalHash,
			Slot:       finalSlot,
		},
		Leaves: leaves,
	}, nil
}

// handleBlockAnnouncementStream handles both handshake and announcements in parallel
func (c *jamnpsConnection) handleBlockAnnouncementStream(stream Stream) error {
	errChan := make(chan error, 2)

	// Goroutine 1: Sender (handshake + outbound announcements)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("sender panic: %v", r)
			}
		}()

		// Send our handshake immediately
		handshake, err := createHandshake()
		if err != nil {
			errChan <- fmt.Errorf("failed to create handshake: %w", err)
			return
		}
		handshakeData := serializer.Serialize(handshake)
		if err := WriteMessage(stream, handshakeData); err != nil {
			errChan <- fmt.Errorf("failed to send handshake: %w", err)
			return
		}

		log.Printf("Sent handshake to validator %d", c.ValidatorIdx())

		// Keep the sender goroutine alive to maintain the bidirectional stream
		// Even if we don't have announcements to send, we need to keep this side open
		// for announcement := range c.outboundAnnouncements {
		//     WriteMessage(stream, announcement)
		// }

		// Block indefinitely to keep the stream alive
		// In a full implementation, this would listen for outbound announcements
		select {} // Block forever
	}()

	// Goroutine 2: Receiver (handshake + inbound announcements)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("receiver panic: %v", r)
			}
		}()

		// Receive peer's handshake first
		handshakeMsg, err := ReadMessage(stream)
		if err != nil {
			errChan <- fmt.Errorf("failed to read peer handshake: %w", err)
			return
		}

		log.Printf("Received handshake from validator %d: %d bytes", c.ValidatorIdx(), len(handshakeMsg))

		// Parse the handshake message
		peerHandshake := Handshake{}
		err = serializer.Deserialize(handshakeMsg, &peerHandshake)
		if err != nil {
			errChan <- fmt.Errorf("failed to parse peer handshake: %w", err)
			return
		}

		// Process the parsed handshake
		if err := c.processHandshake(peerHandshake); err != nil {
			errChan <- fmt.Errorf("failed to process peer handshake: %w", err)
			return
		}

		// Now enter the announcement loop
		for {
			// Read message
			msg, err := ReadMessage(stream)
			if err != nil {
				if errors.Is(err, io.EOF) {
					errChan <- nil
					return
				}
				errChan <- err
				return
			}

			announcement := &Announcement{}
			err = serializer.Deserialize(msg, announcement)
			if err != nil {
				errChan <- err
				return
			}

			// Call handler
			if err := c.processBlockAnnouncement(announcement); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// Wait for either goroutine to complete (or error)
	return <-errChan
}

// processHandshake processes a received handshake message
func (c *jamnpsConnection) processHandshake(handshake Handshake) error {
	log.Printf("Processing handshake from validator %d:", c.ValidatorIdx())
	log.Printf("  Final block: hash=%x, slot=%d", handshake.Final.HeaderHash, handshake.Final.Slot)
	log.Printf("  Leaves: %d entries", len(handshake.Leaves))

	for i, leaf := range handshake.Leaves {
		log.Printf("    Leaf %d: hash=%x, slot=%d", i, leaf.HeaderHash, leaf.Slot)
	}

	// TODO: Implement actual handshake processing logic:
	// 1. Validate the finalized block info against our local state
	// 2. Store/update peer's known leaves for announcement filtering
	// 3. Compare with our own state to determine sync needs
	// 4. Determine what announcements to send based on peer's knowledge

	return nil
}

// RequestBlocks requests blocks from a node
func (c *jamnpsConnection) RequestBlocks(ctx context.Context, hash [32]byte, direction Direction, maxBlocks uint32) ([][]byte, error) {
	log.Printf("=== Starting block request ===")
	log.Printf("Requesting from validator %d: hash=%x, direction=%d, maxBlocks=%d", c.ValidatorIdx(), hash, direction, maxBlocks)

	// Open a block request stream
	stream, err := c.OpenStream(StreamKindCE128BlockRequest)
	if err != nil {
		log.Printf("Failed to open stream: %v", err)
		return nil, fmt.Errorf("failed to open block request stream: %w", err)
	}

	log.Printf("Successfully opened CE 128 stream")

	// Encode request
	req := BlockRequest{
		Hash:      hash,
		Direction: direction,
		MaxBlocks: maxBlocks,
	}
	data := serializer.Serialize(req)

	log.Printf("hash: %x", req.Hash)

	log.Printf("Encoded request data (%d bytes): %x", len(data), data)
	log.Printf("Request breakdown: hash=%x, direction=%d, maxBlocks=%d", req.Hash, req.Direction, req.MaxBlocks)

	// Write raw data (no message framing for JAMNP-S)
	err = WriteMessage(stream, data)
	if err != nil {
		log.Printf("Failed to write to stream: %v", err)
		return nil, fmt.Errorf("failed to write block request: %w", err)
	}

	stream.CloseWrite()

	response, err := ReadMessage(stream)
	if err != nil {
		log.Printf("Failed to read from stream: %v", err)
		return nil, fmt.Errorf("failed to read block response: %w", err)
	}

	stream.Close()

	fmt.Println(response)
	return nil, nil
}

// Close closes the connection
func (c *jamnpsConnection) Close() error {
	c.cancel()

	// Close all UP streams
	c.upStreamsMu.Lock()
	for _, stream := range c.upStreams {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}
	c.upStreams = make(map[StreamKind]quic.Stream)
	c.upStreamsMu.Unlock()

	// Close the connection
	err := c.conn.CloseWithError(0, "normal close")

	// Wait for all goroutines to finish
	c.wg.Wait()

	return err
}

// RemoteKey returns the remote peer's public key
func (c *jamnpsConnection) RemoteKey() ed25519.PublicKey {
	publicKey := c.validatorInfo.Keyset.ToEd25519PublicKey()
	return publicKey[:]
}

// InitializedByRemote returns true if this connection was initialized by the remote peer
func (c *jamnpsConnection) InitializedByRemote() bool {
	return c.initializedByRemote
}

// ValidatorIdx returns the index of the validator this connection is to
func (c *jamnpsConnection) ValidatorIdx() int {
	return c.validatorInfo.Index
}

// LocalKey returns the local peer's public key
func (c *jamnpsConnection) LocalKey() ed25519.PublicKey {
	return c.localKey
}

// TLSConnectionState returns the TLS connection state
func (c *jamnpsConnection) TLSConnectionState() tls.ConnectionState {
	return c.conn.ConnectionState().TLS
}

// QuicConnection returns the underlying QUIC connection
func (c *jamnpsConnection) QuicConnection() quic.Connection {
	return c.conn
}

// Read reads data from the stream
func (s *jamnpsStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// If we have data in the buffer, return it
	if s.readBuf != nil && s.readBuf.Len() > 0 {
		return s.readBuf.Read(p)
	}

	// Otherwise, read from the underlying stream
	return s.stream.Read(p)
}

// Write writes data to the stream
func (s *jamnpsStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// If we have a write buffer, write to it
	if s.writeBuf != nil {
		return s.writeBuf.Write(p)
	}

	// Otherwise, write directly to the stream
	return s.stream.Write(p)
}

// Close closes the stream
func (s *jamnpsStream) Close() error {
	return s.stream.Close()
}

// CloseWrite closes the write-direction of the stream
func (s *jamnpsStream) CloseWrite() error {
	return s.stream.Close()
}

// Reset resets the stream
func (s *jamnpsStream) Reset() error {
	s.stream.CancelRead(0)
	s.stream.CancelWrite(0)
	return nil
}

// Kind returns the stream kind
func (s *jamnpsStream) Kind() StreamKind {
	return s.kind
}

func (c *jamnpsConnection) processBlockAnnouncement(announcement *Announcement) error {

	// Calculate the hash of the announced block (not the finalized block)
	announcedBlockData := serializer.Serialize(announcement.Header)
	announcedBlockHash := blake2b.Sum256(announcedBlockData)

	log.Printf("Announced block hash: %x", announcedBlockHash)
	log.Printf("Finalized block hash: %x", announcement.Final.HeaderHash)

	// Request the actual announced block in a separate goroutine to avoid blocking the stream
	go func() {
		blocks, err := c.RequestBlocks(c.ctx, announcedBlockHash, DirectionAncestors, 1)
		if err != nil {
			log.Printf("Failed to request announced block from validator %d: %v", c.ValidatorIdx(), err)
			// Don't propagate the error - just log it to keep the announcement stream alive
			return
		}

		if len(blocks) > 0 {
			log.Printf("Successfully received %d blocks from validator %d", len(blocks), c.ValidatorIdx())
		}
	}()

	// Always return nil to keep the announcement stream alive
	return nil
}
