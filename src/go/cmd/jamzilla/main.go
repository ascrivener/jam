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
	"path/filepath"
	"sync"
	"time"

	"jam/pkg/block"
	"jam/pkg/block/header"
	"jam/pkg/merklizer"
	"jam/pkg/net"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"

	"github.com/google/uuid"
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

	// Open the state repository
	repo, err := staterepository.NewPebbleStateRepository(*dataPath)
	if err != nil {
		log.Fatalf("Failed to open state repository: %v", err)
	}
	defer repo.Close()

	state := merklizer.State{}
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
		state = append(state, merklizer.StateKV{
			OriginalKey: key,
			Value:       valueBytes,
		})
	}

	err = state.OverwriteCurrentState(*repo)
	if err != nil {
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

	blockWithInfo := block.BlockWithInfo{
		Block: block.Block{
			Header: header,
		},
		Info: block.BlockInfo{
			PosteriorStateRoot: merklizer.MerklizeState(state),
		},
	}

	if err := blockWithInfo.Set(*repo); err != nil {
		log.Fatalf("Failed to store genesis block: %v", err)
	}

	var privateKey ed25519.PrivateKey

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
	privateKey = ed25519.NewKeyFromSeed(ed25519SecretSeed)

	log.Printf("Using JIP-5 derived keys for validator %d", *devValidator)
	log.Printf("Seed: %x", seed)
	log.Printf("Ed25519 secret seed: %x", ed25519SecretSeed)
	log.Printf("Bandersnatch secret seed: %x", bandersnatchSecretSeed)
	// Note: We can't compute the Bandersnatch public key here without a Bandersnatch library

	// Create the JAMNP-S client
	clientOpts := net.ClientOptions{
		PrivateKey:             privateKey,
		BandersnatchSecretSeed: bandersnatchSecretSeed,
		DialTimeout:            10 * time.Second,
	}

	client, err := net.NewClient(clientOpts)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
}

// listenMode listens for block announcements and assurance distributions
func listenMode(ctx context.Context, client *net.Client, conn net.Connection, timeout time.Duration) error {
	log.Println("Listening for block announcements and assurance distributions...")

	var wg sync.WaitGroup
	wg.Add(2)

	// Handle block announcements
	err := client.HandleBlockAnnouncements(conn, func(announcement *net.BlockAnnouncement) error {
		log.Printf("Block announcement: %d headers, finalized block %x at slot %d",
			len(announcement.Headers),
			announcement.FinalizedRef.Hash,
			announcement.FinalizedRef.Slot)

		// Save headers if present
		for i, header := range announcement.Headers {
			log.Printf("Header %d: %d bytes", i, len(header))
			// Can save headers if needed
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to register block announcement handler: %w", err)
	}

	// Handle assurance distributions
	err = client.HandleAssuranceDistributions(conn, func(assuranceData []byte) error {
		log.Printf("Received assurance distribution: %d bytes", len(assuranceData))
		// Process assurance data if needed
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to register assurance distribution handler: %w", err)
	}

	// Open a block announcement stream
	_, err = client.OpenBlockAnnouncementStream(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to open block announcement stream: %w", err)
	}

	// Open an assurance distribution stream
	_, err = client.OpenAssuranceDistributionStream(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to open assurance distribution stream: %w", err)
	}

	// Wait indefinitely or until timeout
	if timeout > 0 {
		time.Sleep(timeout)
	} else {
		// Wait for interrupt signal or context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// requestWorkReport requests a work report for the given hash
func requestWorkReport(ctx context.Context, client *net.Client, conn net.Connection, hash [32]byte) {
	log.Printf("Requesting work report for hash: %x", hash)

	report, err := client.RequestWorkReport(ctx, conn, hash)
	if err != nil {
		log.Fatalf("Failed to request work report: %v", err)
	}

	log.Printf("Received work report: %d bytes", len(report))
	log.Printf("Work report content: %x", report)
}

// requestBlocks requests blocks in the given direction from the starting hash
func requestBlocks(ctx context.Context, client *net.Client, conn net.Connection, hash [32]byte, direction net.Direction, maxBlocks uint32, saveDir string) {
	log.Printf("Requesting up to %d blocks %s from %x", maxBlocks, directionString(direction), hash)

	blocks, err := client.RequestBlocks(ctx, conn, hash, direction, maxBlocks)
	if err != nil {
		log.Fatalf("Failed to request blocks: %v", err)
	}

	log.Printf("Received %d blocks", len(blocks))

	// Save blocks if requested
	if saveDir != "" {
		err := saveBlocks(blocks, saveDir)
		if err != nil {
			log.Fatalf("Failed to save blocks: %v", err)
		}
	}
}

// requestState requests state for the given root hash
func requestState(ctx context.Context, client *net.Client, conn net.Connection, stateRoot [32]byte) {
	log.Printf("Requesting state for root: %x", stateRoot)

	options := &net.StateRequestOptions{
		StateRoot:   stateRoot[:],
		StartKey:    nil,         // Start from the beginning
		EndKey:      nil,         // No end key (full state)
		MaximumSize: 1024 * 1024, // 1MB max size
	}

	response, err := client.RequestState(ctx, conn, options)
	if err != nil {
		log.Fatalf("Failed to request state: %v", err)
	}

	log.Printf("Received state response:")
	log.Printf("- Boundary nodes: %d bytes", len(response.BoundaryNodes))
	log.Printf("- Key/value pairs: %d", len(response.KeyValuePairs))

	// Print key/value pairs
	for i, kv := range response.KeyValuePairs {
		if i < 10 { // Only print the first 10 pairs
			log.Printf("  %d: Key: %x, Value: %d bytes", i, kv.Key, len(kv.Value))
		} else {
			log.Printf("  ... and %d more pairs", len(response.KeyValuePairs)-10)
			break
		}
	}
}

// parseHash parses a hex-encoded hash
func parseHash(hashStr string) ([32]byte, error) {
	var hash [32]byte

	// Remove 0x prefix if present
	if len(hashStr) > 2 && hashStr[:2] == "0x" {
		hashStr = hashStr[2:]
	}

	// Decode hex
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return hash, fmt.Errorf("invalid hex: %w", err)
	}

	// Validate length
	if len(hashBytes) != 32 {
		return hash, fmt.Errorf("hash must be 32 bytes, got %d", len(hashBytes))
	}

	copy(hash[:], hashBytes)
	return hash, nil
}

// saveBlocks saves blocks to individual files in the specified directory
func saveBlocks(blocks [][]byte, saveDir string) error {
	// Create directory if it doesn't exist
	err := os.MkdirAll(saveDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Save each block to a file
	for i, block := range blocks {
		// Generate a unique filename
		filename := filepath.Join(saveDir, fmt.Sprintf("block_%d_%s.bin", i, uuid.New().String()))

		// Write block to file
		err := os.WriteFile(filename, block, 0644)
		if err != nil {
			return fmt.Errorf("failed to write block %d: %w", i, err)
		}

		log.Printf("Saved block %d (%d bytes) to %s", i, len(block), filename)
	}

	return nil
}

// directionString returns a string representation of the direction
func directionString(direction net.Direction) string {
	if direction == net.DirectionDescendants {
		return "descendants"
	}
	return "ancestors"
}
