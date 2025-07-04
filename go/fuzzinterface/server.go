package fuzzinterface

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/ascrivener/jam/block"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/statetransition"
)

// Server represents a fuzzer interface server
type Server struct {
	repo         staterepository.PebbleStateRepository
	peerInfo     PeerInfo
	stateMapLock sync.RWMutex
}

// NewServer creates a new fuzzer interface server
func NewServer(repo staterepository.PebbleStateRepository) *Server {
	return &Server{
		repo: repo,
		peerInfo: PeerInfo{
			Name: []byte("jam-node"),
			AppVersion: Version{
				Major: 0,
				Minor: 1,
				Patch: 0,
			},
			JamVersion: Version{
				Major: 0,
				Minor: 6,
				Patch: 6,
			},
		},
	}
}

// Start starts the fuzzer interface server
func (s *Server) Start(socketPath string) error {
	// Remove socket if it already exists
	if err := os.RemoveAll(socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Listen on Unix domain socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}
	log.Printf("Fuzzer interface listening on %s", socketPath)

	go func() {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}

			log.Printf("New fuzzer connection accepted")
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a single fuzzer connection
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Wait for first message (PeerInfo)
	msg, err := s.receiveMessage(conn)
	if err != nil {
		log.Printf("Error receiving initial PeerInfo: %v", err)
		return
	}

	// Verify it's a PeerInfo message
	if msg.PeerInfo == nil {
		log.Printf("First message is not PeerInfo, closing connection")
		return
	}

	log.Printf("Handshake received from fuzzer: %s (App v%d.%d.%d, JAM v%d.%d.%d)",
		string(msg.PeerInfo.Name),
		msg.PeerInfo.AppVersion.Major, msg.PeerInfo.AppVersion.Minor, msg.PeerInfo.AppVersion.Patch,
		msg.PeerInfo.JamVersion.Major, msg.PeerInfo.JamVersion.Minor, msg.PeerInfo.JamVersion.Patch)

	// Send our PeerInfo
	resp := ResponseMessage{PeerInfo: &s.peerInfo}
	if err := s.sendMessage(conn, resp); err != nil {
		log.Printf("Error sending PeerInfo: %v", err)
		return
	}

	// Main communication loop
	for {
		msg, err := s.receiveMessage(conn)
		if err != nil {
			if err == io.EOF {
				log.Println("Fuzzer disconnected")
				return
			}
			log.Printf("Error receiving message: %v", err)
			return
		}

		resp, err := s.handleMessage(msg)
		if err != nil {
			log.Printf("Error handling message: %v", err)
			return
		}

		if err := s.sendMessage(conn, resp); err != nil {
			log.Printf("Error sending response: %v", err)
			return
		}
	}
}

// receiveMessage reads a message from the connection
func (s *Server) receiveMessage(conn net.Conn) (RequestMessage, error) {
	// Read message length (4 bytes, little-endian)
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return RequestMessage{}, err
	}
	messageLength := binary.LittleEndian.Uint32(lengthBytes)

	// Read message data
	messageData := make([]byte, messageLength)
	if _, err := io.ReadFull(conn, messageData); err != nil {
		return RequestMessage{}, err
	}

	return DecodeMessage(messageData)
}

// sendMessage sends a message to the connection
func (s *Server) sendMessage(conn net.Conn, msg ResponseMessage) error {
	data, err := EncodeMessage(msg)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

// handleMessage processes an incoming message and returns the appropriate response
func (s *Server) handleMessage(msg RequestMessage) (ResponseMessage, error) {
	switch {
	case msg.PeerInfo != nil:
		return ResponseMessage{PeerInfo: &s.peerInfo}, nil

	case msg.SetState != nil:
		return s.handleSetState(*msg.SetState)

	case msg.ImportBlock != nil:
		return s.handleImportBlock(*msg.ImportBlock)

	case msg.GetState != nil:
		return s.handleGetState(*msg.GetState)

	default:
		return ResponseMessage{}, fmt.Errorf("unsupported message type")
	}
}

// handleSetState handles a SetState request
func (s *Server) handleSetState(setState SetState) (ResponseMessage, error) {

	// Begin a transaction
	if err := s.repo.BeginTransaction(); err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Use a separate txErr variable to track transaction errors
	var txSuccess bool
	defer func() {
		if !txSuccess {
			// Rollback if not marked successful
			s.repo.RollbackTransaction()
		}
	}()

	if err := setState.StateWithRoot.State.OverwriteCurrentState(s.repo); err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to overwrite current state: %w", err)
	}

	blockWithInfo := block.BlockWithInfo{
		Block: block.Block{
			Header: setState.Header,
		},
		Info: block.BlockInfo{
			PosteriorStateRoot: setState.StateWithRoot.StateRoot,
		},
	}

	if err := blockWithInfo.Set(s.repo); err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to store block: %w", err)
	}

	// Commit the transaction
	if err := s.repo.CommitTransaction(); err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txSuccess = true

	// Compute state root
	stateRoot := merklizer.MerklizeState(merklizer.GetState(s.repo))

	log.Printf("State set successfully, state root: %x", stateRoot)
	return ResponseMessage{StateRoot: (*StateRoot)(&stateRoot)}, nil
}

// handleImportBlock handles an ImportBlock request
func (s *Server) handleImportBlock(importBlock ImportBlock) (ResponseMessage, error) {

	err := statetransition.STF(s.repo, block.Block(importBlock))
	stateRoot := merklizer.MerklizeState(merklizer.GetState(s.repo))
	if err != nil {
		log.Printf("Failed to process block: %v", err)
	} else {
		log.Printf("Block processed successfully for timeslot %d, state root: %x", importBlock.Header.TimeSlot, stateRoot)
	}
	return ResponseMessage{StateRoot: (*StateRoot)(&stateRoot)}, nil
}

// handleGetState handles a GetState request
func (s *Server) handleGetState(getState GetState) (ResponseMessage, error) {
	state := merklizer.GetState(s.repo)

	log.Printf("Returning state for header hash %x with %d key-value pairs", getState, len(state))
	return ResponseMessage{State: &state}, nil
}
