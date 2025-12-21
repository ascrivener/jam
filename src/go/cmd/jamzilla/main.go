package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/merklizer"
	"jam/pkg/net"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"

	"golang.org/x/crypto/blake2b"
)

// Config represents the configuration loaded from the JSON file
type Config struct {
	ProtocolParameters string            `json:"protocol_parameters"` // Protocol parameters as hex string
	Bootnodes          []string          `json:"bootnodes"`           // List of bootnodes
	Id                 string            `json:"id"`                  // Network ID
	GenesisState       map[string]string `json:"genesis_state"`       // Initial genesis state as key-value pairs
	GenesisHeader      string            `json:"genesis_header"`      // Genesis header as hex string
}

// main initializes the application by parsing command-line flags, loading configuration,
// setting up the state repository, generating cryptographic keys, and starting the network
// node to handle incoming and outgoing connections. It uses the configuration to set up
// the genesis state and block, derives validator keys based on the dev validator index,
// and listens for incoming connections indefinitely.
func main() {
	configPath := flag.String("config-path", "", "Path to a JSON configuration file")
	devValidator := flag.Int("dev-validator", -1, "Dev validator index")
	dataPath := flag.String("data-path", "./data", "Path to the data directory")

	flag.Parse()

	if *configPath == "" {
		log.Fatal("Error: --config-path flag is required")
	}

	if *devValidator < 0 || *devValidator > 5 {
		log.Fatal("Error: --dev-validator flag is required")
	}

	var config Config

	// Load from JSON file
	configData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	err = json.Unmarshal(configData, &config)
	if err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	log.Printf("Using dev validator %d", *devValidator)

	// Initialize the global state repository
	err = staterepository.InitializeGlobalRepository(*dataPath)
	if err != nil {
		log.Fatalf("Failed to initialize global state repository: %v", err)
	}
	defer staterepository.CloseGlobalRepository()

	merklizerState := &merklizer.State{}
	for stateKey, stateValue := range config.GenesisState {
		// Convert state key from hex to [31]byte
		keyBytes, err := hex.DecodeString(stateKey)
		if err != nil {
			log.Fatalf("Failed to decode state key %s: %v", stateKey, err)
		}
		if len(keyBytes) != 31 {
			log.Fatalf("Invalid state key length: expected 31 bytes, got %d bytes for key %s", len(keyBytes), stateKey)
		}

		// Convert state value from hex to []byte
		valueBytes, err := hex.DecodeString(stateValue)
		if err != nil {
			log.Fatalf("Failed to decode state value for key %s: %v", stateKey, err)
		}

		// Create a [31]byte array for the key
		var key [31]byte
		copy(key[:], keyBytes)

		// Add to state
		*merklizerState = append(*merklizerState, merklizer.StateKV{
			OriginalKey: key,
			Value:       valueBytes,
		})
	}

	// Begin a transaction
	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}
	// Use a separate txErr variable to track transaction errors
	var txSuccess bool
	defer func() {
		if !txSuccess {
			// Rollback if not marked successful
			tx.Close()
		}
	}()

	if err := merklizerState.OverwriteCurrentState(tx); err != nil {
		log.Fatalf("Failed to overwrite current state: %v", err)
	}

	headerBytes, err := hex.DecodeString(config.GenesisHeader)
	if err != nil {
		log.Fatalf("Failed to decode genesis header: %v", err)
	}

	header := header.Header{}
	if err := serializer.Deserialize(headerBytes, &header); err != nil {
		log.Fatalf("Failed to deserialize genesis header: %v", err)
	}

	root := tx.GetStateRoot()

	blockWithInfo := block.BlockWithInfo{
		Block: block.Block{
			Header: header,
		},
		Info: block.BlockInfo{
			PosteriorStateRoot: root,
			Height:             0,
		},
	}

	if err := blockWithInfo.Set(tx); err != nil {
		log.Fatalf("Failed to store genesis block: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		log.Fatalf("Failed to commit transaction: %v", err)
	}
	txSuccess = true

	var privateKey []byte

	// Create trivial seed as per JIP-5: repeat_8_times(encode_as_32bit_le(i))
	seed := make([]byte, 32)
	for i := 0; i < 32; i += 4 {
		binary.LittleEndian.PutUint32(seed[i:i+4], uint32(*devValidator))
	}

	// Derive ed25519_secret_seed = blake2b("jam_val_key_ed25519" ++ seed)
	h1, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalf("Failed to create BLAKE2b hash: %v", err)
	}
	h1.Write([]byte("jam_val_key_ed25519"))
	h1.Write(seed)
	ed25519SecretSeed := h1.Sum(nil)

	// Derive bandersnatch_secret_seed = blake2b("jam_val_key_bandersnatch" ++ seed)
	h2, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalf("Failed to create BLAKE2b hash: %v", err)
	}
	h2.Write([]byte("jam_val_key_bandersnatch"))
	h2.Write(seed)
	bandersnatchSecretSeed := h2.Sum(nil)

	// Use the derived secret seed to get private key
	// NOTE: Using crypto/ed25519 for key derivation is fine - ZIP-215 compliance
	// only matters for signature VERIFICATION, not key generation.
	// The networking layer will use ed25519consensus for verification if needed.
	privateKey = ed25519.NewKeyFromSeed(ed25519SecretSeed)

	log.Printf("Using JIP-5 derived keys for validator %d", *devValidator)
	log.Printf("Seed: %x", seed)
	log.Printf("Ed25519 secret seed: %x", ed25519SecretSeed)
	log.Printf("Bandersnatch secret seed: %x", bandersnatchSecretSeed)

	// Extract chain ID from genesis header hash (first 8 nibbles/4 bytes)
	genesisHash := blake2b.Sum256(headerBytes)
	chainID := fmt.Sprintf("%x", genesisHash[:4])
	log.Printf("Using chain ID: %s", chainID)

	// Create a network node for both outgoing and incoming connections
	nodeOpts := net.NodeOptions{
		PrivateKey:  privateKey,
		ChainID:     chainID,
		ListenAddr:  ":40000", // Listen on port 40000 for incoming connections
		DialTimeout: 10 * time.Second,
	}

	// Initialize the global singleton node
	err = net.InitializeGlobalNode(nodeOpts)
	if err != nil {
		log.Fatalf("Error creating network node: %v", err)
	}

	// Get reference to the global node for local use
	node := net.GetGlobalNode()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the node. Initiate connections and UP 0 stream
	if err := node.Start(ctx); err != nil {
		log.Fatalf("Error starting network node: %v", err)
	}
	defer node.Close()

	log.Printf("Network node started, listening at %s", node.Addr())

	select {
	case <-ctx.Done():
		log.Println("Context cancelled, shutting down...")
	}
}
