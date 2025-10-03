package fuzzinterface

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"runtime/trace"

	"jam/pkg/block"
	"jam/pkg/errors"
	"jam/pkg/merklizer"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/statetransition"
)

// Server represents a fuzzer interface server
type Server struct {
	peerInfo   PeerInfo
	listener   net.Listener
	cpuProfile *os.File
	traceFile  *os.File
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

	s.listener = listener

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		log.Printf("New fuzzer connection accepted")
		go func(c net.Conn) {
			defer c.Close()
			if err := s.handleConnection(c); err != nil {
				log.Printf("Connection handling error: %v", err)
			}
			log.Printf("Connection closed")
		}(conn)
	}
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
	if len(msgData) < 1 {
		return ResponseMessage{}, fmt.Errorf("message data too short")
	}

	msgType := RequestMessageType(msgData[0])
	// Skip the type byte
	msgData = msgData[1:]

	switch msgType {
	case RequestMessageTypePeerInfo:
		return ResponseMessage{PeerInfo: &s.peerInfo}, nil

	case RequestMessageTypeInitialize:
		return s.handleInitialize(msgData)

	case RequestMessageTypeImportBlock:
		return s.handleImportBlock(msgData)

	case RequestMessageTypeGetState:
		return s.handleGetState(msgData)

	case RequestMessageTypeStartProfiling:
		return s.handleStartProfiling(msgData)

	case RequestMessageTypeStopProfiling:
		return s.handleStopProfiling()

	default:
		return ResponseMessage{}, fmt.Errorf("unknown message type: %d", msgType)
	}
}

// handleInitialize handles an Initialize request
func (s *Server) handleInitialize(initializeData []byte) (ResponseMessage, error) {
	var initialize Initialize
	err := serializer.Deserialize(initializeData, &initialize)
	if err != nil {
		return ResponseMessage{}, err
	}
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return ResponseMessage{}, fmt.Errorf("global repository not initialized")
	}

	// Begin a transaction
	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		return ResponseMessage{}, err
	}
	// Use a separate txErr variable to track transaction errors
	var txSuccess bool
	defer func() {
		if !txSuccess {
			// Rollback if not marked successful
			tx.Close()
		}
	}()
	if err := (&initialize.State).OverwriteCurrentState(tx); err != nil {
		return ResponseMessage{}, err
	}

	root := tx.GetStateRoot()

	blockWithInfo := &block.BlockWithInfo{
		Block: block.Block{
			Header: initialize.Header,
		},
		Info: block.BlockInfo{
			PosteriorStateRoot: root,
			Height:             0,
		},
	}

	if err := blockWithInfo.Set(tx); err != nil {
		return ResponseMessage{}, err
	}

	// Compute state root
	stateRoot := tx.GetStateRoot()

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return ResponseMessage{}, err
	}
	txSuccess = true

	log.Printf("State set successfully, state root: %x", stateRoot)
	return ResponseMessage{StateRoot: (*StateRoot)(&stateRoot)}, nil
}

// handleImportBlock handles an ImportBlock request
func (s *Server) handleImportBlock(importBlockData []byte) (ResponseMessage, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in handleImportBlock: %v", r)
			debug.PrintStack()
		}
	}()

	var importBlock ImportBlock
	err := serializer.Deserialize(importBlockData, &importBlock)
	if err != nil {
		return ResponseMessage{}, err
	}
	merklizedState, err := statetransition.STF(block.Block(importBlock))
	if err != nil {
		if errors.IsProtocolError(err) {
			e := []byte(err.Error())
			return ResponseMessage{Error: &e}, nil
		} else {
			return ResponseMessage{}, err
		}
	}
	return ResponseMessage{StateRoot: (*StateRoot)(&merklizedState)}, nil
}

// handleGetState handles a GetState request
func (s *Server) handleGetState(getStateData []byte) (ResponseMessage, error) {
	var getState GetState
	err := serializer.Deserialize(getStateData, &getState)
	if err != nil {
		return ResponseMessage{}, err
	}
	readTx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		return ResponseMessage{}, err
	}
	defer readTx.Close()
	block, err := block.Get(readTx, getState)
	if err != nil {
		return ResponseMessage{}, err
	}
	readTx.SetStateRoot(block.Info.PosteriorStateRoot)
	state, err := merklizer.GetState(readTx)
	if err != nil {
		return ResponseMessage{}, err
	}
	log.Printf("Returning state for header hash %x with %d key-value pairs", getState, len(*state))
	return ResponseMessage{State: state}, nil
}

// handleStartProfiling starts CPU profiling
func (s *Server) handleStartProfiling(data []byte) (ResponseMessage, error) {
	var startProf StartProfiling
	if err := serializer.Deserialize(data, &startProf); err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to deserialize StartProfiling: %w", err)
	}

	// Stop any existing profiling
	if s.cpuProfile != nil {
		pprof.StopCPUProfile()
		s.cpuProfile.Close()
		s.cpuProfile = nil
	}

	// Enable blocking profile collection
	runtime.SetBlockProfileRate(1) // Capture all blocking events

	// Start new profiling
	profileName := "cpu.prof"

	var err error
	s.cpuProfile, err = os.Create(profileName)
	if err != nil {
		return ResponseMessage{}, fmt.Errorf("failed to create profile file: %w", err)
	}

	if err := pprof.StartCPUProfile(s.cpuProfile); err != nil {
		s.cpuProfile.Close()
		s.cpuProfile = nil
		return ResponseMessage{}, fmt.Errorf("failed to start CPU profile: %w", err)
	}

	// Start execution tracing
	traceName := "trace.out"
	s.traceFile, err = os.Create(traceName)
	if err != nil {
		pprof.StopCPUProfile()
		s.cpuProfile.Close()
		s.cpuProfile = nil
		return ResponseMessage{}, fmt.Errorf("failed to create trace file: %w", err)
	}

	if err := trace.Start(s.traceFile); err != nil {
		pprof.StopCPUProfile()
		s.cpuProfile.Close()
		s.cpuProfile = nil
		s.traceFile.Close()
		s.traceFile = nil
		return ResponseMessage{}, fmt.Errorf("failed to start trace: %w", err)
	}

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	log.Printf("Memory before profiling: Alloc=%d KB, Sys=%d KB, NumGC=%d",
		m1.Alloc/1024, m1.Sys/1024, m1.NumGC)

	log.Printf("Started CPU profiling: %s", profileName)
	log.Printf("Started tracing: %s", traceName)
	log.Printf("Enabled blocking profile collection")
	return ResponseMessage{
		ProfilingStatus: &ProfilingStatus{
			Success: 1,
			Message: []byte(fmt.Sprintf("Started profiling: %s", profileName)),
		},
	}, nil
}

// handleStopProfiling stops CPU profiling
func (s *Server) handleStopProfiling() (ResponseMessage, error) {
	if s.cpuProfile == nil {
		return ResponseMessage{
			ProfilingStatus: &ProfilingStatus{
				Success: 0,
				Message: []byte("No profiling session active"),
			},
		}, nil
	}

	// Stop CPU profiling
	pprof.StopCPUProfile()
	s.cpuProfile.Close()
	s.cpuProfile = nil

	// Stop tracing
	if s.traceFile != nil {
		trace.Stop()
		s.traceFile.Close()
		s.traceFile = nil
	}

	// Save blocking profile
	blockFile, err := os.Create("block.prof")
	if err != nil {
		log.Printf("Failed to create blocking profile: %v", err)
	} else {
		if err := pprof.Lookup("block").WriteTo(blockFile, 0); err != nil {
			log.Printf("Failed to write blocking profile: %v", err)
		}
		blockFile.Close()
		log.Printf("Blocking profile saved to block.prof")
	}

	// Reset blocking profile rate
	runtime.SetBlockProfileRate(0)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	log.Printf("Memory after profiling: Alloc=%d KB, Sys=%d KB, NumGC=%d",
		m2.Alloc/1024, m2.Sys/1024, m2.NumGC)

	log.Printf("Stopped CPU profiling")
	return ResponseMessage{
		ProfilingStatus: &ProfilingStatus{
			Success: 1,
			Message: []byte("Profiling stopped successfully"),
		},
	}, nil
}
