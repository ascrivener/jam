package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"jam/pkg/net"

	"github.com/google/uuid"
)

func main() {
	// Parse command line flags
	mode := flag.String("mode", "listen", "Mode to run in: listen, block, report, or state")
	address := flag.String("address", "localhost:40000", "Address to connect to")
	keyPath := flag.String("key", "", "Path to Ed25519 key file")
	blockHash := flag.String("block", "", "Block hash to request (32 bytes, hex-encoded)")
	reportHash := flag.String("report", "", "Report hash to request (32 bytes, hex-encoded)")
	stateHash := flag.String("state", "", "State hash to request (32 bytes, hex-encoded)")
	direction := flag.Int("direction", 0, "Direction for block request (0 = descendants, 1 = ancestors)")
	maxBlocks := flag.Int("max-blocks", 10, "Maximum number of blocks to request")
	saveDir := flag.String("save-dir", "", "Directory to save blocks to")
	timeout := flag.Duration("timeout", 0, "Timeout for the operation (0 = no timeout)")
	insecure := flag.Bool("insecure", false, "Skip peer certificate verification")
	protocolVersion := flag.String("protocol", "jam-1.0", "Protocol version")
	chainHash := flag.String("chain", "polkadot", "Chain hash")
	isBuilder := flag.Bool("builder", false, "Identify as builder")

	flag.Parse()

	// Generate or load Ed25519 keys
	var publicKey ed25519.PublicKey
	var privateKey ed25519.PrivateKey
	var err error

	if *keyPath != "" {
		// Load keys from file
		keyData, err := os.ReadFile(*keyPath)
		if err != nil {
			log.Fatalf("Failed to read key file: %v", err)
		}
		if len(keyData) != ed25519.PrivateKeySize {
			log.Fatalf("Invalid key size: %d", len(keyData))
		}
		privateKey = ed25519.PrivateKey(keyData)
		publicKey = privateKey.Public().(ed25519.PublicKey)
	} else {
		// Generate new keys
		publicKey, privateKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		log.Printf("Generated new Ed25519 keys")
	}

	// Set up a context with timeout if specified
	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	// Create the JAMNP-S client
	clientOpts := net.ClientOptions{
		PublicKey:       publicKey,
		PrivateKey:      privateKey,
		ProtocolVersion: *protocolVersion,
		ChainHash:       *chainHash,
		IsBuilder:       *isBuilder,
		DialTimeout:     10 * time.Second,
		Insecure:        *insecure,
	}

	client, err := net.NewClient(clientOpts)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to the node
	conn, err := client.Connect(ctx, *address)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", *address, err)
	}

	// Display connection info
	log.Printf("Connected to %s (remote peer: %x)", *address, conn.RemoteKey())

	// Handle the requested mode
	switch *mode {
	case "listen":
		err := listenMode(ctx, client, conn, *timeout)
		if err != nil {
			log.Fatalf("Listen mode failed: %v", err)
		}
	case "report":
		if *reportHash == "" {
			log.Fatal("Report hash is required for report mode")
		}
		hash, err := parseHash(*reportHash)
		if err != nil {
			log.Fatalf("Invalid report hash: %v", err)
		}
		requestWorkReport(ctx, client, conn, hash)
	case "block":
		if *blockHash == "" {
			log.Fatal("Block hash is required for block mode")
		}
		hash, err := parseHash(*blockHash)
		if err != nil {
			log.Fatalf("Invalid block hash: %v", err)
		}
		requestBlocks(ctx, client, conn, hash, net.Direction(*direction), uint32(*maxBlocks), *saveDir)
	case "state":
		if *stateHash == "" {
			log.Fatal("State hash is required for state mode")
		}
		hash, err := parseHash(*stateHash)
		if err != nil {
			log.Fatalf("Invalid state hash: %v", err)
		}
		requestState(ctx, client, conn, hash)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
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
