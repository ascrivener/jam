package net

import (
	"context"
	"fmt"
	"io"

	"encoding/binary"

	"github.com/quic-go/quic-go"
)

// BlockAnnouncementHandler represents a handler for block announcement messages
type BlockAnnouncementHandler interface {
	// HandleBlockAnnouncement is called when a new block is announced
	HandleBlockAnnouncement(header []byte) error
}

// WorkReportInfo contains information about a work report
type WorkReportInfo struct {
	Hash       [32]byte
	WorkReport []byte
}

// BlockHandler manages the block announcement UP 0 protocol
type BlockHandler struct {
	client  *Client
	session quic.Connection
	stream  quic.Stream
	handler BlockAnnouncementHandler
	// Track the latest finalized block we know about
	finalizedHash [32]byte
	finalizedSlot uint32
}

// NewBlockHandler creates a new handler for the block announcement protocol
func NewBlockHandler(client *Client, session quic.Connection, handler BlockAnnouncementHandler) (*BlockHandler, error) {
	// Open the UP 0 stream
	stream, err := client.OpenStream(context.Background(), session, BlockAnnouncementStream)
	if err != nil {
		return nil, fmt.Errorf("failed to open block announcement stream: %w", err)
	}

	return &BlockHandler{
		client:  client,
		session: session,
		stream:  stream,
		handler: handler,
		// Initialize with zeros - we'll use this as a placeholder if we don't know the latest finalized block
		finalizedHash: [32]byte{},
		finalizedSlot: 0,
	}, nil
}

// SetFinalizedBlock updates the handler with information about the latest finalized block
func (h *BlockHandler) SetFinalizedBlock(hash [32]byte, slot uint32) {
	h.finalizedHash = hash
	h.finalizedSlot = slot
}

// Start begins handling block announcements
func (h *BlockHandler) Start(ctx context.Context) error {
	// Prepare handshake message according to the JAMNP-S specification:
	// Handshake = Final ++ len++[Leaf]
	// Final = Header Hash ++ Slot
	// We send the latest finalized block hash + slot, and an empty list of leaves for now
	initialMsg := Message{}

	// Add finalized block hash (32 bytes)
	for _, b := range h.finalizedHash {
		initialMsg = append(initialMsg, b)
	}

	// Add finalized block slot (uint32)
	slotBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(slotBytes, h.finalizedSlot)
	initialMsg = append(initialMsg, slotBytes...)

	// Add empty leaf list (length 0)
	initialMsg.EncodeUint32(0)

	fmt.Printf("Sending handshake message: %d bytes, finalized hash: %x, slot: %d\n",
		len(initialMsg), h.finalizedHash, h.finalizedSlot)

	// Send the handshake message
	err := SendMessage(h.stream, initialMsg)
	if err != nil {
		return fmt.Errorf("failed to send initial handshake: %w", err)
	}

	fmt.Println("Handshake message sent successfully")

	// Start reading messages
	go h.readLoop(ctx)

	return nil
}

// readLoop continuously reads and processes messages from the stream
func (h *BlockHandler) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Read the next message
			msg, err := ReadMessage(h.stream)
			if err != nil {
				if err == io.EOF {
					// Stream closed normally
					fmt.Println("Stream closed normally (EOF)")
					return
				}
				// Log error and return
				fmt.Printf("Error reading message: %v\n", err)
				return
			}

			fmt.Printf("Received message of %d bytes\n", len(msg))

			// Process the message
			err = h.processMessage(msg)
			if err != nil {
				// Log error but continue reading
				fmt.Printf("Error processing message: %v\n", err)
				continue
			}
		}
	}
}

// processMessage handles an incoming block announcement message
func (h *BlockHandler) processMessage(msg Message) error {
	offset := 0

	// According to the protocol spec, we should first parse the finalized block info
	// Final = Header Hash ++ Slot
	if len(msg) < 32+4 {
		return fmt.Errorf("message too short to contain finalized block info")
	}

	// Extract finalized block hash (32 bytes)
	finalizedHash := [32]byte{}
	copy(finalizedHash[:], msg[offset:offset+32])
	offset += 32

	// Extract finalized block slot (uint32)
	finalizedSlot := binary.LittleEndian.Uint32(msg[offset : offset+4])
	offset += 4

	fmt.Printf("Received finalized block info: hash %x, slot %d\n", finalizedHash, finalizedSlot)

	// Update our knowledge of the latest finalized block
	h.SetFinalizedBlock(finalizedHash, finalizedSlot)

	// Now read the number of leaves (as in the original code)
	numLeaves, err := DecodeUint32(msg, &offset)
	if err != nil {
		return fmt.Errorf("failed to decode leaf count: %w", err)
	}

	fmt.Printf("Number of leaves in message: %d\n", numLeaves)

	// Process each leaf
	for i := uint32(0); i < numLeaves; i++ {
		// In the block announcement protocol, each leaf is:
		// Leaf = Header Hash ++ Slot

		// Check if we have enough bytes for the header hash and slot
		if offset+32+4 > len(msg) {
			return fmt.Errorf("message truncated: not enough bytes for leaf %d", i)
		}

		// Extract header hash (32 bytes)
		headerHash := [32]byte{}
		copy(headerHash[:], msg[offset:offset+32])
		offset += 32

		// Extract header slot (uint32)
		headerSlot := binary.LittleEndian.Uint32(msg[offset : offset+4])
		offset += 4

		fmt.Printf("Leaf %d: header hash %x, slot %d\n", i, headerHash, headerSlot)

		// Create a simple header with the hash and slot
		// For the BlockHandler, we'll use a binary format that includes both
		header := make([]byte, 36)
		copy(header[:32], headerHash[:])
		binary.LittleEndian.PutUint32(header[32:], headerSlot)

		// Handle the new block header
		if h.handler != nil {
			err = h.handler.HandleBlockAnnouncement(header)
			if err != nil {
				// Log error but continue processing other leaves
				fmt.Printf("Error handling block announcement: %v\n", err)
				continue
			}
		}
	}

	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SendNewLeaf announces a new block header to the peer
func (h *BlockHandler) SendNewLeaf(header []byte) error {
	msg := Message{}

	// 1 leaf to announce
	msg.EncodeUint32(1)

	// Encode the header with its length
	msg.EncodeByteSliceWithLength(header)

	return SendMessage(h.stream, msg)
}

// Close closes the block announcement handler
func (h *BlockHandler) Close() error {
	return h.stream.Close()
}

// RequestWorkReport requests a work report by its hash using CE 136
func RequestWorkReport(ctx context.Context, client *Client, session quic.Connection, hash [32]byte) ([]byte, error) {
	// Open a new CE 136 stream
	stream, err := client.OpenStream(ctx, session, RequestWorkReportStream)
	if err != nil {
		return nil, fmt.Errorf("failed to open request work report stream: %w", err)
	}
	defer stream.Close()

	// Send the request message with the hash
	requestMsg := Message{}
	requestMsg.EncodeHash(hash)

	err = SendMessage(stream, requestMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to send work report request: %w", err)
	}

	// Read the response
	response, err := ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read work report response: %w", err)
	}

	// First byte is status code
	if len(response) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	statusCode := response[0]
	if statusCode != 0 {
		return nil, fmt.Errorf("failed to get work report: status code %d", statusCode)
	}

	// Return the work report (rest of the message after status code)
	if len(response) <= 1 {
		return nil, fmt.Errorf("missing work report in response")
	}

	return response[1:], nil
}

// SubmitWorkPackage submits a work package using CE 133
func SubmitWorkPackage(ctx context.Context, client *Client, session quic.Connection, workPackage []byte) error {
	// Open a new CE 133 stream
	stream, err := client.OpenStream(ctx, session, WorkPackageSubmissionStream)
	if err != nil {
		return fmt.Errorf("failed to open work package submission stream: %w", err)
	}
	defer stream.Close()

	// Send the work package
	err = SendMessage(stream, workPackage)
	if err != nil {
		return fmt.Errorf("failed to send work package: %w", err)
	}

	// Read the response
	response, err := ReadMessage(stream)
	if err != nil {
		return fmt.Errorf("failed to read work package submission response: %w", err)
	}

	// First byte is status code
	if len(response) == 0 {
		return fmt.Errorf("empty response")
	}

	statusCode := response[0]
	if statusCode != 0 {
		errorMsg := "unknown error"
		if len(response) > 1 {
			errorMsg = string(response[1:])
		}
		return fmt.Errorf("failed to submit work package: status code %d, error: %s", statusCode, errorMsg)
	}

	return nil
}
