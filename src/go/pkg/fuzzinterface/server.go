package fuzzinterface

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"jam/pkg/block"
	"jam/pkg/errors"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/statetransition"
)

// Server represents a fuzzer interface server
type Server struct {
	peerInfo     PeerInfo
	stateMapLock sync.RWMutex
}

// NewServer creates a new fuzzer interface server
func NewServer() *Server {
	return &Server{
		peerInfo: PeerInfo{
			FuzzVersion: 1,
			Features:    FEATURE_FORK,
			AppVersion: Version{
				Major: 0,
				Minor: 1,
				Patch: 0,
			},
			JamVersion: Version{
				Major: 0,
				Minor: 7,
				Patch: 0,
			},
			Name: []byte("jamzilla"),
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

	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept connection: %w", err)
	}
	defer conn.Close()

	log.Printf("New fuzzer connection accepted")
	if err := s.handleConnection(conn); err != nil {
		return err
	}

	return nil
}

// handleConnection handles a single fuzzer connection
func (s *Server) handleConnection(conn net.Conn) error {
	defer conn.Close()

	// Wait for first message (PeerInfo)
	msgData, err := s.receiveMessageData(conn)
	if err != nil {
		log.Printf("Error receiving initial PeerInfo: %v", err)
		return err
	}

	// Get the message type
	msgType := RequestMessageType(msgData[0])

	if msgType != RequestMessageTypePeerInfo {
		log.Printf("First message is not PeerInfo, closing connection")
		return fmt.Errorf("first message is not PeerInfo")
	}

	// Skip the type byte
	msgData = msgData[1:]

	var peerInfo PeerInfo
	err = serializer.Deserialize(msgData, &peerInfo)
	if err != nil {
		log.Printf("Error deserializing PeerInfo: %v", err)
		return err
	}

	log.Printf("Handshake received from fuzzer: %s (App v%d.%d.%d, JAM v%d.%d.%d)",
		string(peerInfo.Name),
		peerInfo.AppVersion.Major, peerInfo.AppVersion.Minor, peerInfo.AppVersion.Patch,
		peerInfo.JamVersion.Major, peerInfo.JamVersion.Minor, peerInfo.JamVersion.Patch)

	// Send our PeerInfo
	resp := ResponseMessage{PeerInfo: &s.peerInfo}
	if err := s.sendMessage(conn, resp); err != nil {
		log.Printf("Error sending PeerInfo: %v", err)
		return err
	}

	// Main communication loop
	for {
		msgData, err := s.receiveMessageData(conn)
		if err != nil {
			if err == io.EOF {
				log.Println("Fuzzer disconnected")
				return err
			}
			log.Printf("Error receiving message data: %v", err)
			return err
		}

		resp, err := s.HandleMessageData(msgData)
		if err != nil {
			log.Printf("Error handling message data: %v", err)
			return err
		}

		if err := s.sendMessage(conn, resp); err != nil {
			log.Printf("Error sending response: %v", err)
			return err
		}
	}
}

// receiveMessage reads a message from the connection
func (s *Server) receiveMessageData(conn net.Conn) ([]byte, error) {
	// Read message length (4 bytes, little-endian)
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return nil, err
	}
	messageLength := binary.LittleEndian.Uint32(lengthBytes)

	// Read message data
	messageData := make([]byte, messageLength)
	if _, err := io.ReadFull(conn, messageData); err != nil {
		return nil, err
	}

	return messageData, nil
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

// HandleMessage processes an incoming message and returns the appropriate response
func (s *Server) HandleMessageData(msgData []byte) (ResponseMessage, error) {
	// Get the message type
	msgType := RequestMessageType(msgData[0])
	// Skip the type byte
	msgData = msgData[1:]

	switch msgType {
	case RequestMessageTypePeerInfo:
		return ResponseMessage{PeerInfo: &s.peerInfo}, nil

	case RequestMessageTypeSetState:
		return s.handleSetState(msgData)

	case RequestMessageTypeImportBlock:
		return s.handleImportBlock(msgData)

	case RequestMessageTypeGetState:
		return s.handleGetState(msgData)

	default:
		return ResponseMessage{}, fmt.Errorf("unknown message type: %d", msgType)
	}
}

// handleSetState handles a SetState request
func (s *Server) handleSetState(setStateData []byte) (ResponseMessage, error) {
	var setState SetState
	err := serializer.Deserialize(setStateData, &setState)
	if err != nil {
		return ResponseMessage{Error: &struct{}{}}, nil
	}
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return ResponseMessage{}, fmt.Errorf("global repository not initialized")
	}

	// Begin a transaction
	globalBatch := staterepository.NewIndexedBatch()
	// Use a separate txErr variable to track transaction errors
	var txSuccess bool
	defer func() {
		if !txSuccess {
			// Rollback if not marked successful
			globalBatch.Close()
		}
	}()
	if err := setState.State.OverwriteCurrentState(globalBatch); err != nil {
		return ResponseMessage{}, err
	}

	reverseDiff, err := block.GenerateReverseBatch(nil, globalBatch)
	if err != nil {
		return ResponseMessage{}, err
	}
	defer reverseDiff.Close()

	blockWithInfo := block.BlockWithInfo{
		Block: block.Block{
			Header: setState.Header,
		},
		Info: block.BlockInfo{
			PosteriorStateRoot: merklizer.MerklizeState(setState.State),
			Height:             0,
			ForwardStateDiff:   globalBatch.Repr(),
			ReverseStateDiff:   reverseDiff.Repr(),
		},
	}

	if err := blockWithInfo.Set(globalBatch); err != nil {
		return ResponseMessage{}, err
	}

	// Commit the transaction
	if err := globalBatch.Commit(nil); err != nil {
		return ResponseMessage{}, err
	}
	txSuccess = true

	// Compute state root
	stateRoot := merklizer.MerklizeState(merklizer.GetState(nil))

	log.Printf("State set successfully, state root: %x", stateRoot)
	return ResponseMessage{StateRoot: (*StateRoot)(&stateRoot)}, nil
}

// handleImportBlock handles an ImportBlock request
func (s *Server) handleImportBlock(importBlockData []byte) (ResponseMessage, error) {
	var importBlock ImportBlock
	err := serializer.Deserialize(importBlockData, &importBlock)
	if err != nil {
		return ResponseMessage{}, err
	}
	err = statetransition.STF(block.Block(importBlock))
	if err != nil {
		if errors.IsProtocolError(err) {
			return ResponseMessage{Error: &struct{}{}}, nil
		} else {
			return ResponseMessage{}, err
		}
	}
	stateRoot := merklizer.MerklizeState(merklizer.GetState(nil))
	return ResponseMessage{StateRoot: (*StateRoot)(&stateRoot)}, nil
}

// handleGetState handles a GetState request
func (s *Server) handleGetState(getStateData []byte) (ResponseMessage, error) {
	state := merklizer.GetState(nil)
	var getState GetState
	err := serializer.Deserialize(getStateData, &getState)
	if err != nil {
		return ResponseMessage{Error: &struct{}{}}, nil
	}
	log.Printf("Returning state for header hash %x with %d key-value pairs", getState, len(state))
	return ResponseMessage{State: &state}, nil
}
