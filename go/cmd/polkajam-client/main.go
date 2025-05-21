package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ascrivener/jam/net"
	"github.com/quic-go/quic-go"
)

func main() {
	// Parse command line flags
	var (
		address    = flag.String("address", "localhost:31234", "Address of the polkajam node (hostname:port)")
		chainHash  = flag.String("chain-hash", "", "First 8 nibbles of the chain's genesis header hash")
		timeout    = flag.Duration("timeout", 30*time.Second, "Connection timeout")
		mode       = flag.String("mode", "listen", "Mode: 'listen' for block announcements or 'report' to request a work report")
		reportHash = flag.String("report-hash", "", "Hash of the work report to request (hex-encoded, required for 'report' mode)")
		insecure   = flag.Bool("insecure", false, "Skip certificate verification (for testing only)")
	)
	flag.Parse()

	if *chainHash == "" {
		log.Fatal("Chain hash is required. Use -chain-hash flag.")
	}

	if *mode == "report" && *reportHash == "" {
		log.Fatal("Report hash is required for 'report' mode. Use -report-hash flag.")
	}

	// Generate Ed25519 key pair
	log.Println("Generating Ed25519 key pair...")
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create client configuration
	config := net.Config{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		ChainHash:  *chainHash,
		Version:    "0",
		IsBuilder:  false,
		Insecure:   *insecure,
	}

	// Create client
	log.Println("Creating JAMNP-S client...")
	client, err := net.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to the polkajam node
	log.Printf("Connecting to %s...", *address)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	session, err := client.Connect(ctx, *address)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	log.Println("Connected successfully!")

	// Handle based on the selected mode
	switch *mode {
	case "listen":
		// Set up block announcement handler
		listenForBlocks(client, session)
	case "report":
		// Request a work report
		requestWorkReport(ctx, client, session, *reportHash)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

func listenForBlocks(client *net.Client, session quic.Connection) {
	// Set up block announcement handler
	blockHandler := &BlockHandler{}
	log.Println("Setting up block announcement handler...")
	handler, err := net.NewBlockHandler(client, session, blockHandler)
	if err != nil {
		log.Fatalf("Failed to create block handler: %v", err)
	}

	// Start the block handler
	log.Println("Starting block handler...")
	err = handler.Start(context.Background())
	if err != nil {
		log.Fatalf("Failed to start block handler: %v", err)
	}
	log.Println("Block handler started. Waiting for block announcements...")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
}

func requestWorkReport(ctx context.Context, client *net.Client, session quic.Connection, hashHex string) {
	// Parse the report hash
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		log.Fatalf("Failed to decode report hash: %v", err)
	}
	if len(hashBytes) != 32 {
		log.Fatalf("Invalid hash length: %d, expected 32", len(hashBytes))
	}

	var reportHash [32]byte
	copy(reportHash[:], hashBytes)

	// Request the work report
	log.Printf("Requesting work report with hash: %x", reportHash)
	reportData, err := net.RequestWorkReport(ctx, client, session, reportHash)
	if err != nil {
		log.Fatalf("Failed to request work report: %v", err)
	}

	// Print work report details
	log.Printf("Received work report: %d bytes", len(reportData))
	if len(reportData) > 0 {
		// Print first 32 bytes (or less if report is smaller)
		previewSize := 32
		if len(reportData) < previewSize {
			previewSize = len(reportData)
		}
		log.Printf("Preview: %x", reportData[:previewSize])

		// Save report to file
		filename := fmt.Sprintf("work_report_%x.bin", reportHash[:4])
		err = os.WriteFile(filename, reportData, 0644)
		if err != nil {
			log.Printf("Failed to save work report: %v", err)
		} else {
			log.Printf("Work report saved to %s", filename)
		}
	}
}

// BlockHandler implements the net.BlockAnnouncementHandler interface
type BlockHandler struct {
	blockCount int
}

func (h *BlockHandler) HandleBlockAnnouncement(header []byte) error {
	h.blockCount++
	log.Printf("Received block announcement #%d: %d bytes", h.blockCount, len(header))

	// Print the first few bytes of the header for identification
	if len(header) > 8 {
		log.Printf("Header starts with: %x", header[:8])
	}

	// Save header to file
	filename := fmt.Sprintf("block_header_%d.bin", h.blockCount)
	err := os.WriteFile(filename, header, 0644)
	if err != nil {
		log.Printf("Failed to save block header: %v", err)
	} else {
		log.Printf("Block header saved to %s", filename)
	}

	return nil
}
