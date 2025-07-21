package net

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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
	conn        quic.Connection
	localKey    ed25519.PublicKey
	remoteKey   ed25519.PublicKey
	upStreams   map[StreamKind]quic.Stream
	upStreamsMu sync.Mutex
	handlers    map[StreamKind]StreamHandler
	handlersMu  sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	acceptErrCh chan error
}

// jamnpsStream implements the Stream interface
type jamnpsStream struct {
	stream quic.Stream
	kind   StreamKind
}

// NewConnection creates a new Connection from a QUIC connection
func NewConnection(conn quic.Connection, localKey ed25519.PublicKey) (Connection, error) {
	// Extract the remote public key from the connection's peer certificate
	tlsState := conn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer did not provide a certificate")
	}

	cert := tlsState.PeerCertificates[0]
	remoteKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer certificate does not use Ed25519")
	}

	// Create connection context
	ctx, cancel := context.WithCancel(context.Background())

	connection := &jamnpsConnection{
		conn:        conn,
		localKey:    localKey,
		remoteKey:   remoteKey,
		upStreams:   make(map[StreamKind]quic.Stream),
		handlers:    make(map[StreamKind]StreamHandler),
		ctx:         ctx,
		cancel:      cancel,
		acceptErrCh: make(chan error, 1),
	}

	// Start stream acceptor
	connection.wg.Add(1)
	go connection.acceptStreams()

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
			continue
		}

		// Handle CE stream with registered handler if available
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
					// Log error if needed
				}

				// Make sure stream is closed
				jstream.Close()
			}()
		} else {
			// No handler, reset the stream
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
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
				// Log error if needed
			}

			// For UP streams, we don't close automatically on handler return
			// as they are long-lived
		}()
	}
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

// AcceptStream accepts an incoming stream
func (c *jamnpsConnection) AcceptStream() (StreamKind, Stream, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case err := <-c.acceptErrCh:
		return 0, nil, err
	case <-time.After(500 * time.Millisecond):
		// No errors, continue with normal operation
	}

	// Accept new stream
	stream, err := c.conn.AcceptStream(c.ctx)
	if err != nil {
		return 0, nil, err
	}

	// Read stream kind byte
	kindBuf := make([]byte, 1)
	_, err = io.ReadFull(stream, kindBuf)
	if err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return 0, nil, err
	}

	kind := StreamKind(kindBuf[0])

	// Return the stream
	return kind, &jamnpsStream{
		stream: stream,
		kind:   kind,
	}, nil
}

// RegisterHandler registers a handler for a specific stream kind
func (c *jamnpsConnection) RegisterHandler(kind StreamKind, handler StreamHandler) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers[kind] = handler
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
	return c.remoteKey
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
	return s.stream.Read(p)
}

// Write writes data to the stream
func (s *jamnpsStream) Write(p []byte) (int, error) {
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
