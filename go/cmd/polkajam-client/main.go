package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
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
		mode       = flag.String("mode", "listen", "Mode: 'listen' for block announcements, 'report' to request a work report, 'block' to request blocks, or 'state' to request state components")
		reportHash = flag.String("report-hash", "", "Hash of the work report to request (hex-encoded, required for 'report' mode)")
		blockHash  = flag.String("block-hash", "", "Hash of the block to request (hex-encoded, required for 'block' mode)")
		stateHash  = flag.String("state-hash", "", "Hash of the state to request in hex format")
		direction  = flag.Int("direction", 1, "Direction for block request: 0 for ascending (children), 1 for descending (parents)")
		maxBlocks  = flag.Int("max-blocks", 10, "Maximum number of blocks to request")
		saveDir    = flag.String("save-dir", ".", "Directory to save requested blocks")
		insecure   = flag.Bool("insecure", false, "Skip certificate verification (for testing only)")
		useAlice   = flag.Bool("use-alice", false, "Use Alice's validator credentials instead of generating random keys")
	)
	flag.Parse()

	if *chainHash == "" {
		log.Fatal("Chain hash is required. Use -chain-hash flag.")
	}

	if *mode == "report" && *reportHash == "" {
		log.Fatal("Report hash is required for 'report' mode. Use -report-hash flag.")
	}

	if *mode == "block" && *blockHash == "" {
		log.Fatal("Block hash is required for 'block' mode. Use -block-hash flag.")
	}

	if *mode == "state" && *stateHash == "" {
		log.Fatal("State hash is required for 'state' mode. Use -state-hash flag.")
	}

	var pubKey ed25519.PublicKey
	var privKey ed25519.PrivateKey
	var err error

	if *useAlice {
		// Use Alice's validator credentials (predefined test account)
		log.Println("Using Alice's validator credentials...")

		// Alice's Ed25519 keys
		seedHex := "0000000000000000000000000000000000000000000000000000000000000000"
		pubKeyHex := "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"

		// Convert hex strings to byte arrays
		seedBytes, err := hex.DecodeString(seedHex)
		if err != nil {
			log.Fatalf("Failed to decode Alice's seed: %v", err)
		}
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			log.Fatalf("Failed to decode Alice's public key: %v", err)
		}

		// Create Ed25519 key objects
		// In Ed25519, the private key is the 32-byte seed concatenated with the 32-byte public key
		privKey = make([]byte, ed25519.PrivateKeySize)
		copy(privKey[:32], seedBytes)
		copy(privKey[32:], pubKeyBytes)
		pubKey = ed25519.PublicKey(pubKeyBytes)

		log.Printf("Using Alice's validator credentials:")
		log.Printf("  Public key: %x", pubKey)
		log.Printf("  Expected DNS name: ehnvcppgow2sc2yvdvdicu3ynonsteflxdxrehjr2ybekdc2z3iuq")
	} else {
		// Generate random Ed25519 key pair
		log.Println("Generating Ed25519 key pair...")
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}
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

	// Create the JAMNP-S client
	log.Println("Creating JAMNP-S client...")
	client, err := net.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Create a context that can be cancelled with Ctrl+C
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Connect to the node
	log.Printf("Connecting to %s...", *address)
	conn, err := client.Connect(ctx, *address)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Verify connection details after successful connection
	connState := conn.ConnectionState()
	log.Printf("=== CONNECTION ESTABLISHED ===")
	log.Printf("Using TLS 1.3: %v", connState.TLS.Version == tls.VersionTLS13)
	log.Printf("Handshake complete: %v", connState.TLS.HandshakeComplete)
	log.Printf("Using cipher suite: 0x%04x", connState.TLS.CipherSuite)
	log.Printf("Negotiated protocol: %s", connState.TLS.NegotiatedProtocol)

	if *useAlice {
		log.Printf("=== ALICE CREDENTIALS VERIFICATION ===")
		expectedAlicePubKey := "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
		log.Printf("Using Alice's public key: %v", hex.EncodeToString(pubKey) == expectedAlicePubKey)
	}

	// Handle based on the selected mode
	switch *mode {
	case "listen":
		err := listenMode(client, *address, *timeout)
		if err != nil {
			log.Fatalf("Listen mode failed: %v", err)
		}
	case "report":
		// Request a work report
		requestWorkReport(ctx, client, conn, *reportHash)
	case "block":
		// Request blocks
		requestBlocks(ctx, client, conn, *blockHash, byte(*direction), uint32(*maxBlocks), *saveDir)
	case "state":
		// Request state components
		requestState(ctx, client, conn, *stateHash)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

func listenMode(client *net.Client, address string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a context that can be cancelled with Ctrl+C
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalCh
		log.Println("Received interrupt signal. Shutting down...")
		cancel()
	}()

	// Connect to the node
	log.Printf("Connecting to %s...", address)
	conn, err := client.Connect(ctx, address)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	log.Println("Connected successfully!")

	// Set up handlers for different stream types
	var wg sync.WaitGroup
	wg.Add(1) // One for block announcements

	// Handle block announcements (UP 0)
	go func() {
		defer wg.Done()
		log.Println("Setting up block announcement handler...")
		err := handleBlockAnnouncements(ctx, conn)
		if err != nil {
			log.Printf("Block announcement handler failed: %v", err)
		}
	}()

	// Accept and handle incoming streams
	// go func() {
	// 	defer wg.Done()
	// 	log.Println("Setting up stream acceptor...")
	// 	streamErrors := 0
	// 	for {
	// 		stream, err := conn.AcceptStream(ctx)
	// 		if err != nil {
	// 			if ctx.Err() != nil {
	// 				log.Println("Context cancelled, stopping stream acceptor")
	// 				return
	// 			}

	// 			// Enhanced error logging
	// 			streamErrors++
	// 			log.Printf("Error accepting stream (%d): %v (type: %T)", streamErrors, err, err)

	// 			if streamErrors%10 == 0 {
	// 				log.Printf("DIAGNOSTIC: Received %d stream accept errors, connection state: handshake=%v",
	// 					streamErrors, conn.ConnectionState().TLS.HandshakeComplete)
	// 			}

	// 			// Check if this is a temporary error that we can retry
	// 			if streamErrors > 100 {
	// 				log.Printf("WARNING: High number of stream accept errors (%d), but continuing", streamErrors)
	// 			}

	// 			// Short pause before retrying to avoid tight loops
	// 			time.Sleep(100 * time.Millisecond)
	// 			continue
	// 		}

	// 		// Reset error counter on successful accept
	// 		if streamErrors > 0 {
	// 			log.Printf("Successfully accepted stream after %d errors", streamErrors)
	// 			streamErrors = 0
	// 		}

	// 		// Read the stream kind byte
	// 		kindBuf := make([]byte, 1)
	// 		_, err = stream.Read(kindBuf)
	// 		if err != nil {
	// 			log.Printf("Error reading stream kind: %v", err)
	// 			stream.Close()
	// 			continue
	// 		}

	// 		streamKind := kindBuf[0]
	// 		log.Printf("Received stream with kind: %d", streamKind)

	// 		// Handle different stream kinds
	// 		switch streamKind {
	// 		case 141: // CE 141: Assurance distribution
	// 			go handleAssuranceDistribution(stream)
	// 		case 131, 132: // CE 131/132: Safrole ticket distribution
	// 			go handleTicketDistribution(stream, int(streamKind))
	// 		case 129: // CE 129: State request
	// 			go handleStateRequest(stream)
	// 		default:
	// 			log.Printf("Unsupported stream kind: %d, closing", streamKind)
	// 			stream.Close()
	// 		}
	// 	}
	// }()

	wg.Wait()
	return nil
}

// Handle the Block Announcement protocol (UP 0)
func handleBlockAnnouncements(ctx context.Context, conn quic.Connection) error {
	// Open the block announcement stream (UP 0)
	log.Println("Starting block handler...")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open block announcement stream: %w", err)
	}
	defer stream.Close()

	// Send the stream kind byte for UP 0
	_, err = stream.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("failed to write stream kind: %w", err)
	}

	// Send handshake message
	// For now, we'll send an empty set of leaves with a zero finalized hash
	finalizedHash := make([]byte, 32)
	finalizedSlot := uint32(0)

	handshakeMsg := make([]byte, 40) // 32 bytes hash + 4 bytes slot + 4 bytes leaf count (0)
	copy(handshakeMsg[0:32], finalizedHash)
	binary.LittleEndian.PutUint32(handshakeMsg[32:36], finalizedSlot)
	binary.LittleEndian.PutUint32(handshakeMsg[36:40], 0) // No leaves

	// Write message size (4 bytes) followed by message
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(handshakeMsg)))

	fmt.Printf("Sending handshake message: %d bytes, finalized hash: %x, slot: %d\n",
		len(handshakeMsg), finalizedHash, finalizedSlot)

	_, err = stream.Write(sizeBytes)
	if err != nil {
		return fmt.Errorf("failed to write handshake message size: %w", err)
	}

	_, err = stream.Write(handshakeMsg)
	if err != nil {
		return fmt.Errorf("failed to write handshake message: %w", err)
	}

	fmt.Println("Handshake message sent successfully")
	log.Println("Block handler started. Waiting for block announcements...")

	// Read and process messages
	sizeBuffer := make([]byte, 4)
	for {
		// Read message size
		_, err := io.ReadFull(stream, sizeBuffer)
		if err != nil {
			return fmt.Errorf("failed to read message size: %w", err)
		}

		messageSize := binary.LittleEndian.Uint32(sizeBuffer)
		message := make([]byte, messageSize)

		// Read message content
		_, err = io.ReadFull(stream, message)
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}

		fmt.Printf("Received message of %d bytes\n", messageSize)

		// Parse as handshake or announcement
		if messageSize >= 36 {
			// Extract finalized block info
			finalHash := message[messageSize-36 : messageSize-4]
			finalSlot := binary.LittleEndian.Uint32(message[messageSize-4:])
			fmt.Printf("Received finalized block info: hash %x, slot %d\n", finalHash, finalSlot)

			// If it's an announcement (contains a header)
			if messageSize > 36 {
				// Parse header (simplified, would need more parsing in reality)
				fmt.Printf("Number of leaves in message: %d\n", binary.LittleEndian.Uint32(message[36:40]))
			}
		} else {
			fmt.Printf("Error processing message: message too short (%d bytes)\n", messageSize)
		}
	}
}

// Handle the Assurance Distribution protocol (CE 141)
func handleAssuranceDistribution(stream quic.Stream) {
	defer stream.Close()

	// Read message size
	sizeBuffer := make([]byte, 4)
	_, err := io.ReadFull(stream, sizeBuffer)
	if err != nil {
		log.Printf("Error reading assurance message size: %v", err)
		return
	}

	messageSize := binary.LittleEndian.Uint32(sizeBuffer)
	message := make([]byte, messageSize)

	// Read message content
	_, err = io.ReadFull(stream, message)
	if err != nil {
		log.Printf("Error reading assurance message: %v", err)
		return
	}

	// Parse the assurance message
	// Format: Header Hash (32 bytes) + Bitfield (variable) + Ed25519 Signature (64 bytes)
	if messageSize < 96 { // Minimum size check (32 + 64)
		log.Printf("Assurance message too short: %d bytes", messageSize)
		return
	}

	anchorHash := message[:32]
	signatureStart := messageSize - 64
	bitfield := message[32:signatureStart]
	signature := message[signatureStart:]

	log.Printf("Received assurance:")
	log.Printf("  Anchor hash: %x", anchorHash)
	log.Printf("  Bitfield size: %d bytes", len(bitfield))
	log.Printf("  Signature: %x", signature)

	// Respond with FIN
	stream.Close()
}

// Handle the Safrole Ticket Distribution protocol (CE 131/132)
func handleTicketDistribution(stream quic.Stream, kind int) {
	defer stream.Close()

	kindName := "Generator→Proxy"
	if kind == 132 {
		kindName = "Proxy→Validator"
	}

	// Read message size
	sizeBuffer := make([]byte, 4)
	_, err := io.ReadFull(stream, sizeBuffer)
	if err != nil {
		log.Printf("Error reading ticket message size: %v", err)
		return
	}

	messageSize := binary.LittleEndian.Uint32(sizeBuffer)
	message := make([]byte, messageSize)

	// Read message content
	_, err = io.ReadFull(stream, message)
	if err != nil {
		log.Printf("Error reading ticket message: %v", err)
		return
	}

	// According to the JAMNP-S protocol:
	// Epoch Index (u32) + Ticket
	// where Ticket = Attempt (1 byte) + Bandersnatch RingVRF Proof (784 bytes)
	if messageSize < 789 { // 4 + 1 + 784
		log.Printf("Ticket message too short: %d bytes (expected at least 789 bytes)", messageSize)
		return
	}

	// Extract components
	epochIndex := binary.LittleEndian.Uint32(message[:4])
	attempt := message[4]
	proof := message[5:789]

	log.Printf("Received Safrole ticket (%s):", kindName)
	log.Printf("  Epoch index: %d", epochIndex)
	log.Printf("  Attempt: %d", attempt)
	log.Printf("  Proof size: %d bytes", len(proof))

	// In a full implementation, you would verify the proof and handle appropriately

	// According to the spec, if verification succeeds, you would:
	// 1. If this is CE 131 (generator→proxy), you would schedule forwarding to all validators
	// 2. If this is CE 132 (proxy→validator), you would verify it's not already included in a block

	// For now, we just log receipt and acknowledge
	log.Printf("Successfully processed Safrole ticket for epoch %d", epochIndex)

	// Respond with FIN (already handled by defer stream.Close())
}

// Handle the State Request protocol (CE 129)
func handleStateRequest(stream quic.Stream) {
	defer stream.Close()

	// Read message size
	sizeBuffer := make([]byte, 4)
	_, err := io.ReadFull(stream, sizeBuffer)
	if err != nil {
		log.Printf("Error reading state request message size: %v", err)
		return
	}

	messageSize := binary.LittleEndian.Uint32(sizeBuffer)
	message := make([]byte, messageSize)

	// Read message content
	_, err = io.ReadFull(stream, message)
	if err != nil {
		log.Printf("Error reading state request message: %v", err)
		return
	}

	// Parse the state request message
	// Format: State Root (32 bytes) + Components bitfield (variable length)
	if messageSize < 32 { // Minimum size check (32 bytes for state root)
		log.Printf("State request message too short: %d bytes", messageSize)
		return
	}

	stateRoot := message[:32]
	bitfield := message[32:]

	log.Printf("Received state request:")
	log.Printf("  State root: %x", stateRoot)
	log.Printf("  Bitfield size: %d bytes", len(bitfield))

	// In a full implementation, you would:
	// 1. Parse the bitfield to determine which components are requested
	// 2. Retrieve the requested components from your state storage
	// 3. Construct a response message with the components

	// For now, we just log receipt and acknowledge
	log.Printf("Successfully processed state request")

	// Respond with FIN (already handled by defer stream.Close())
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

func requestBlocks(ctx context.Context, client *net.Client, session quic.Connection, hashHex string, direction byte, maxBlocks uint32, saveDir string) {
	// Parse the block hash
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		log.Fatalf("Failed to decode block hash: %v", err)
	}
	if len(hashBytes) != 32 {
		log.Fatalf("Invalid hash length: %d, expected 32", len(hashBytes))
	}

	var blockHash [32]byte
	copy(blockHash[:], hashBytes)

	log.Printf("Requesting blocks with hash: %x, direction: %d, max blocks: %d", blockHash, direction, maxBlocks)

	// Open a CE 128 stream
	stream, err := client.OpenStream(ctx, session, 128) // CE 128 is Block request
	if err != nil {
		log.Fatalf("Failed to open block request stream: %v", err)
	}
	defer stream.Close()

	// Prepare request message: Header Hash ++ Direction ++ Maximum Blocks
	requestMsg := make([]byte, 0, 32+1+4)
	requestMsg = append(requestMsg, blockHash[:]...)
	requestMsg = append(requestMsg, direction)

	// Add maximum blocks (uint32, little-endian)
	maxBlocksBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxBlocksBytes, maxBlocks)
	requestMsg = append(requestMsg, maxBlocksBytes...)

	// Send the request
	err = net.SendMessage(stream, requestMsg)
	if err != nil {
		log.Fatalf("Failed to send block request: %v", err)
	}

	// Signal end of request by closing the sending side of the stream
	// This sends a FIN to the server but keeps the read side open
	err = stream.Close()
	if err != nil {
		log.Fatalf("Failed to close send stream: %v", err)
	}

	log.Println("Block request sent, waiting for response...")

	// Create a file to save all received blocks
	filename := fmt.Sprintf("%s/blocks_%x_%d.bin", saveDir, blockHash[:4], direction)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	// Create a hexdump file
	hexdumpFilename := fmt.Sprintf("%s/blocks_%x_%d_hexdump.txt", saveDir, blockHash[:4], direction)
	hexdumpFile, err := os.Create(hexdumpFilename)
	if err != nil {
		log.Printf("Failed to create hexdump file: %v", err)
	} else {
		defer hexdumpFile.Close()
	}

	// Read blocks from the stream until EOF
	blockCount := 0
	totalBytes := 0

	for {
		// Read a block message
		blockData, err := net.ReadMessage(stream)
		if err != nil {
			if err == io.EOF {
				log.Println("End of stream reached")
				break
			}
			// Handle other errors
			log.Printf("Error reading block response: %v", err)
			break // Continue with what we have rather than fatally exiting
		}

		blockCount++
		totalBytes += len(blockData)
		log.Printf("Received block %d: %d bytes", blockCount, len(blockData))

		// Check if the block data is empty
		if len(blockData) == 0 {
			log.Printf("Warning: Received empty block data. This might indicate the block doesn't exist or there's no data to return.")
			continue
		}

		// Write to the output file
		_, err = file.Write(blockData)
		if err != nil {
			log.Fatalf("Failed to write block data to file: %v", err)
		}

		// Write to hexdump file if it was created successfully
		if hexdumpFile != nil {
			// Add a block header to the hexdump
			fmt.Fprintf(hexdumpFile, "=== BLOCK %d (%d bytes) ===\n", blockCount, len(blockData))

			// Create a simple hexdump with 16 bytes per line
			for i := 0; i < len(blockData); i += 16 {
				// Print offset
				fmt.Fprintf(hexdumpFile, "%08x  ", i)

				// Print hex bytes
				end := min(i+16, len(blockData))
				for j := i; j < end; j++ {
					fmt.Fprintf(hexdumpFile, "%02x ", blockData[j])
					if j == i+7 {
						fmt.Fprintf(hexdumpFile, " ")
					}
				}

				// Pad with spaces if needed
				for j := end; j < i+16; j++ {
					fmt.Fprintf(hexdumpFile, "   ")
					if j == i+7 {
						fmt.Fprintf(hexdumpFile, " ")
					}
				}

				// Print ASCII representation
				fmt.Fprintf(hexdumpFile, " |")
				for j := i; j < end; j++ {
					if blockData[j] >= 32 && blockData[j] <= 126 {
						fmt.Fprintf(hexdumpFile, "%c", blockData[j])
					} else {
						fmt.Fprintf(hexdumpFile, ".")
					}
				}
				fmt.Fprintf(hexdumpFile, "|\n")
			}

			// Add a separator between blocks
			fmt.Fprintf(hexdumpFile, "\n")
		}
	}

	log.Printf("Received %d blocks, total %d bytes", blockCount, totalBytes)
	log.Printf("Blocks saved to %s", filename)
	if hexdumpFile != nil {
		log.Printf("Hexdump saved to %s", hexdumpFilename)
	}
}

func requestState(ctx context.Context, client *net.Client, session quic.Connection, hashHex string) {
	// Parse the state hash
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		log.Fatalf("Invalid state hash: %v", err)
	}
	if len(hashBytes) != 32 {
		log.Fatalf("State hash must be 32 bytes (64 hex characters)")
	}

	log.Printf("Requesting state for hash: %s", hashHex)

	// Open a stream for the state request (CE 129)
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// Write the stream kind (CE 129)
	_, err = stream.Write([]byte{129})
	if err != nil {
		log.Fatalf("Failed to write stream kind: %v", err)
	}

	// Prepare the state request message
	// Format: Header Hash (32 bytes) + Start Key (31 bytes) + End Key (31 bytes) + Maximum Size (4 bytes)

	// Create empty start key (get from beginning)
	startKey := make([]byte, 31)

	// Create end key with all 0xFF (get everything up to the end)
	endKey := make([]byte, 31)
	for i := range endKey {
		endKey[i] = 0xFF
	}

	// Set maximum size (e.g., 1MB)
	maxSize := uint32(1024 * 1024)
	maxSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(maxSizeBytes, maxSize)

	// Construct the message: Header Hash + Start Key + End Key + Maximum Size
	message := append(hashBytes, startKey...)
	message = append(message, endKey...)
	message = append(message, maxSizeBytes...)

	// Write the message size as a u32
	messageSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageSizeBytes, uint32(len(message)))
	_, err = stream.Write(messageSizeBytes)
	if err != nil {
		log.Fatalf("Failed to write message size: %v", err)
	}

	// Write the message
	_, err = stream.Write(message)
	if err != nil {
		log.Fatalf("Failed to write message: %v", err)
	}

	log.Printf("State request sent successfully. Waiting for response...")

	// Signal that we're done writing by closing the write side of the stream
	// This sends a FIN to the server but keeps the read side open
	if stream, ok := stream.(quic.Stream); ok {
		log.Printf("Explicitly closing write side of stream")
		stream.Close()
	} else {
		log.Printf("Warning: Stream doesn't support proper half-close, using extended timeout instead")
	}

	// Increase the read timeout to give the server more time to respond
	readCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Declare boundary nodes data in outer scope
	var boundaryNodesData []byte

	// Read with timeout
	readErr := make(chan error, 1)
	go func() {
		// Read the boundary nodes first
		sizeBuffer := make([]byte, 4)
		_, err := io.ReadFull(stream, sizeBuffer)
		if err != nil {
			readErr <- fmt.Errorf("failed to read boundary nodes message size: %w", err)
			return
		}

		boundaryNodesSize := binary.LittleEndian.Uint32(sizeBuffer)
		log.Printf("Boundary nodes message size: %d bytes", boundaryNodesSize)

		// Populate the outer scope variable
		boundaryNodesData = make([]byte, boundaryNodesSize)
		_, err = io.ReadFull(stream, boundaryNodesData)
		if err != nil {
			readErr <- fmt.Errorf("failed to read boundary nodes data: %w", err)
			return
		}
		log.Printf("Received %d bytes of boundary nodes data", len(boundaryNodesData))

		// Signal successful read
		readErr <- nil
	}()

	// Wait for read completion or timeout
	select {
	case err := <-readErr:
		if err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("Successfully read boundary nodes")
	case <-readCtx.Done():
		log.Fatalf("Timed out waiting for response (60s)")
	}

	// Now read the key/value pairs
	sizeBuffer := make([]byte, 4)
	_, err = io.ReadFull(stream, sizeBuffer)
	if err != nil {
		log.Fatalf("Failed to read key/value pairs message size: %v", err)
	}
	kvPairsSize := binary.LittleEndian.Uint32(sizeBuffer)
	log.Printf("Key/value pairs message size: %d bytes", kvPairsSize)

	kvPairsData := make([]byte, kvPairsSize)
	_, err = io.ReadFull(stream, kvPairsData)
	if err != nil {
		log.Fatalf("Failed to read key/value pairs data: %v", err)
	}
	log.Printf("Received %d bytes of key/value pairs data", len(kvPairsData))

	// Create a directory for state data
	stateDir := fmt.Sprintf("state_%s", hashHex[:8])
	err = os.MkdirAll(stateDir, 0755)
	if err != nil {
		log.Printf("Warning: Failed to create directory for state data: %v", err)
	}

	// Save the binary data first
	if err == nil {
		// Save boundary nodes
		boundaryNodesFile := fmt.Sprintf("%s/boundary_nodes.bin", stateDir)
		err = os.WriteFile(boundaryNodesFile, boundaryNodesData, 0644)
		if err != nil {
			log.Printf("Warning: Failed to save boundary nodes: %v", err)
		} else {
			log.Printf("Boundary nodes saved to %s", boundaryNodesFile)
		}

		// Save key/value pairs
		kvPairsFile := fmt.Sprintf("%s/key_value_pairs.bin", stateDir)
		err = os.WriteFile(kvPairsFile, kvPairsData, 0644)
		if err != nil {
			log.Printf("Warning: Failed to save key/value pairs: %v", err)
		} else {
			log.Printf("Key/value pairs saved to %s", kvPairsFile)
		}
	}

	// Now parse and convert to JSON format
	// First, parse the boundary nodes (as a simple hex dump)
	boundaryNodesJSON, err := json.MarshalIndent(generateHexDump(boundaryNodesData), "", "  ")
	if err != nil {
		log.Printf("Warning: Failed to convert boundary nodes to JSON: %v", err)
	} else {
		boundaryNodesJSONFile := fmt.Sprintf("%s/boundary_nodes.json", stateDir)
		err = os.WriteFile(boundaryNodesJSONFile, boundaryNodesJSON, 0644)
		if err != nil {
			log.Printf("Warning: Failed to save boundary nodes JSON: %v", err)
		} else {
			log.Printf("Boundary nodes JSON saved to %s", boundaryNodesJSONFile)
		}
	}

	// Then, parse the key/value pairs
	kvEntries, err := parseKeyValuePairs(kvPairsData)
	if err != nil {
		log.Printf("Warning: Failed to parse key/value pairs: %v", err)
	} else {
		log.Printf("Successfully parsed %d key/value pairs", len(kvEntries))

		// Convert to JSON
		kvPairsJSON, err := json.MarshalIndent(kvEntries, "", "  ")
		if err != nil {
			log.Printf("Warning: Failed to convert key/value pairs to JSON: %v", err)
		} else {
			kvPairsJSONFile := fmt.Sprintf("%s/key_value_pairs.json", stateDir)
			err = os.WriteFile(kvPairsJSONFile, kvPairsJSON, 0644)
			if err != nil {
				log.Printf("Warning: Failed to save key/value pairs JSON: %v", err)
			} else {
				log.Printf("Key/value pairs JSON saved to %s", kvPairsJSONFile)
			}
		}
	}

	log.Printf("State request completed successfully")
}

// StateEntry represents a key/value pair in the state data
type StateEntry struct {
	Key       []byte `json:"-"`
	Value     []byte `json:"-"`
	KeyHex    string `json:"key"`
	ValueHex  string `json:"value"`
	Position  uint32 `json:"position"`
	ValueSize uint32 `json:"value_size"`
}

// parseKeyValuePairs tries to parse the binary data as key/value pairs
func parseKeyValuePairs(data []byte) ([]StateEntry, error) {
	var entries []StateEntry
	var pos uint32 = 0
	dataSize := uint32(len(data))
	var kvCount int = 0

	for pos+31 < dataSize {
		startPos := pos

		// Each key is 31 bytes
		if pos+31 > dataSize {
			break
		}
		key := make([]byte, 31)
		copy(key, data[pos:pos+31])
		pos += 31

		// Value length is a u32
		if pos+4 > dataSize {
			break
		}

		// Try multiple interpretations of the value length
		lenBytes := data[pos : pos+4]
		littleEndianLen := binary.LittleEndian.Uint32(lenBytes)
		bigEndianLen := binary.BigEndian.Uint32(lenBytes)

		log.Printf("Value length bytes at position %d: %x", pos, lenBytes)

		// Determine the most likely value length
		var valueLen uint32

		// Check if either interpretation gives a reasonable result
		if littleEndianLen < 100000 && pos+4+littleEndianLen <= dataSize {
			valueLen = littleEndianLen
		} else if bigEndianLen < 100000 && pos+4+bigEndianLen <= dataSize {
			log.Printf("Using big-endian interpretation for value length")
			valueLen = bigEndianLen
		} else {
			// If both interpretations are problematic, use a reasonable cap
			log.Printf("Suspicious value length: %d bytes (little-endian), %d bytes (big-endian)",
				littleEndianLen, bigEndianLen)

			// Special case: if the first bytes are zeros, it's likely a small big-endian number
			if lenBytes[0] == 0 && lenBytes[1] == 0 && lenBytes[2] == 0 {
				valueLen = uint32(lenBytes[3])
				log.Printf("Using single-byte value length: %d", valueLen)
			} else {
				log.Printf("Both length interpretations are problematic, capping to reasonable size")
				valueLen = uint32(min(int(uint32(1024)), int(dataSize-pos-4)))
			}
		}

		pos += 4 // Skip the length bytes

		// Final safety check - ensure we don't exceed data boundaries
		if pos+valueLen > dataSize {
			log.Printf("Value length still exceeds remaining data, truncating to available bytes")
			valueLen = dataSize - pos
		}

		// Extract the value
		value := make([]byte, valueLen)
		copy(value, data[pos:pos+valueLen])
		pos += valueLen

		// Create entry with both binary and hex-encoded data
		entry := StateEntry{
			Key:       key,
			Value:     value,
			KeyHex:    hex.EncodeToString(key),
			ValueHex:  hex.EncodeToString(value),
			Position:  startPos,
			ValueSize: valueLen,
		}

		entries = append(entries, entry)
		kvCount++

		// Display the first few key/value pairs with detailed info
		if kvCount <= 5 {
			log.Printf("Key/Value Pair #%d (at position %d):", kvCount, startPos)
			log.Printf("  Key (%d bytes): %x", len(key), key)
			if valueLen <= 64 {
				log.Printf("  Value (%d bytes): %x", valueLen, value)
			} else {
				log.Printf("  Value (%d bytes): %x...", valueLen, value[:64])
			}
		}
	}

	log.Printf("Total key/value pairs parsed: %d", kvCount)
	return entries, nil
}

// generateHexDump creates a hex dump with position information
func generateHexDump(data []byte) []map[string]interface{} {
	var result []map[string]interface{}

	// Process data in chunks of 16 bytes
	for i := 0; i < len(data); i += 16 {
		end := min(i+16, len(data))
		chunk := data[i:end]

		entry := map[string]interface{}{
			"position": i,
			"hex":      hex.EncodeToString(chunk),
			"ascii":    formatASCII(chunk),
		}

		result = append(result, entry)
	}

	return result
}

// formatASCII converts a byte slice to printable ASCII, replacing non-printable characters with dots
func formatASCII(data []byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			result[i] = b
		} else {
			result[i] = '.'
		}
	}
	return string(result)
}

// BlockHandler implements the net.BlockAnnouncementHandler interface
type BlockHandler struct {
	blockCount int
}

func (h *BlockHandler) HandleBlockAnnouncement(header []byte) error {
	h.blockCount++
	log.Printf("Received block announcement #%d: %d bytes", h.blockCount, len(header))

	// Add detailed debugging information
	log.Printf("Header raw bytes (first 50): % x", header[:min(50, len(header))])

	// Check if we have a proper header format (hash + slot)
	if len(header) >= 36 {
		// First 32 bytes are the block hash
		blockHash := header[:32]
		// Next 4 bytes are the slot number (little-endian uint32)
		slotBytes := header[32:36]
		slot := binary.LittleEndian.Uint32(slotBytes)

		log.Printf("Block hash: %x", blockHash)
		log.Printf("Block slot: %d", slot)
	} else {
		log.Printf("Header too short to contain hash+slot (%d bytes)", len(header))
	}

	// Save the complete header for offline analysis
	filename := fmt.Sprintf("block_header_%d.bin", h.blockCount)
	err := os.WriteFile(filename, header, 0644)
	if err != nil {
		log.Printf("Failed to save block header: %v", err)
	} else {
		log.Printf("Block header saved to %s", filename)
	}

	// Try to do a more extensive hexdump of the header
	hexdumpFilename := fmt.Sprintf("block_header_%d_hexdump.txt", h.blockCount)
	hexdumpFile, err := os.Create(hexdumpFilename)
	if err != nil {
		log.Printf("Failed to create hexdump file: %v", err)
	} else {
		defer hexdumpFile.Close()

		// Create a simple hexdump with 16 bytes per line
		for i := 0; i < len(header); i += 16 {
			// Print offset
			fmt.Fprintf(hexdumpFile, "%08x  ", i)

			// Print hex bytes
			end := min(i+16, len(header))
			for j := i; j < end; j++ {
				fmt.Fprintf(hexdumpFile, "%02x ", header[j])
				if j == i+7 {
					fmt.Fprintf(hexdumpFile, " ")
				}
			}

			// Pad with spaces if needed
			for j := end; j < i+16; j++ {
				fmt.Fprintf(hexdumpFile, "   ")
				if j == i+7 {
					fmt.Fprintf(hexdumpFile, " ")
				}
			}

			// Print ASCII representation
			fmt.Fprintf(hexdumpFile, " |")
			for j := i; j < end; j++ {
				if header[j] >= 32 && header[j] <= 126 {
					fmt.Fprintf(hexdumpFile, "%c", header[j])
				} else {
					fmt.Fprintf(hexdumpFile, ".")
				}
			}
			fmt.Fprintf(hexdumpFile, "|\n")
		}

		log.Printf("Hexdump saved to %s", hexdumpFilename)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
