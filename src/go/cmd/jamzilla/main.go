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
	"jam/pkg/blockproducer"
	"jam/pkg/mempool"
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
	Peers              []net.ConfigPeer  `json:"peers"`               // Peer list for testnet mode
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

	err = staterepository.InitializeGlobalRepository(*dataPath)
	if err != nil {
		log.Fatalf("Failed to initialize global state repository: %v", err)
	}
	defer staterepository.CloseGlobalRepository()

	merklizerState := &merklizer.State{}
	for stateKey, stateValue := range config.GenesisState {
		keyBytes, err := hex.DecodeString(stateKey)
		if err != nil {
			log.Fatalf("Failed to decode state key %s: %v", stateKey, err)
		}
		if len(keyBytes) != 31 {
			log.Fatalf("Invalid state key length: expected 31 bytes, got %d bytes for key %s", len(keyBytes), stateKey)
		}

		valueBytes, err := hex.DecodeString(stateValue)
		if err != nil {
			log.Fatalf("Failed to decode state value for key %s: %v", stateKey, err)
		}

		var key [31]byte
		copy(key[:], keyBytes)

		*merklizerState = append(*merklizerState, merklizer.StateKV{
			OriginalKey: key,
			Value:       valueBytes,
		})
	}

	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}
	var txSuccess bool
	defer func() {
		if !txSuccess {
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

	genesisHeader := header.Header{}
	if err := serializer.Deserialize(headerBytes, &genesisHeader); err != nil {
		log.Fatalf("Failed to deserialize genesis header: %v", err)
	}

	root := tx.GetStateRoot()

	blockWithInfo := block.BlockWithInfo{
		Block: block.Block{
			Header: genesisHeader,
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

	privateKey = ed25519.NewKeyFromSeed(ed25519SecretSeed)

	log.Printf("Using JIP-5 derived keys for validator %d", *devValidator)
	log.Printf("Seed: %x", seed)
	log.Printf("Ed25519 secret seed: %x", ed25519SecretSeed)
	log.Printf("Bandersnatch secret seed: %x", bandersnatchSecretSeed)

	genesisHash := blake2b.Sum256(headerBytes)
	chainID := fmt.Sprintf("%x", genesisHash[:4])
	log.Printf("Using chain ID: %s", chainID)

	listenAddr := fmt.Sprintf(":%d", 40000+*devValidator)

	nodeOpts := net.NodeOptions{
		PrivateKey:  privateKey,
		ChainID:     chainID,
		ListenAddr:  listenAddr,
		DialTimeout: 10 * time.Second,
	}

	err = net.InitializeGlobalNode(nodeOpts)
	if err != nil {
		log.Fatalf("Error creating network node: %v", err)
	}

	node := net.GetGlobalNode()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var peerProvider net.PeerProvider
	if len(config.Peers) > 0 {
		log.Printf("Using testnet mode with %d configured peers", len(config.Peers))
		peerProvider = net.NewConfigPeerProvider(*devValidator, privateKey, config.Peers)
	} else {
		log.Printf("Using production mode with chain state peer discovery")
		peerProvider, err = net.NewChainStatePeerProvider(privateKey)
		if err != nil {
			log.Fatalf("Failed to create chain state peer provider: %v", err)
		}
	}

	if err := node.StartWithProvider(ctx, peerProvider); err != nil {
		log.Fatalf("Error starting network node: %v", err)
	}
	defer node.Close()

	log.Printf("Network node started, listening at %s", node.Addr())

	broadcastFunc := func(hdr header.Header) error {
		tx, err := staterepository.NewTrackedTx([32]byte{})
		if err != nil {
			return err
		}
		defer tx.Close()

		tip, err := block.GetTip(tx)
		if err != nil {
			return err
		}

		return node.BroadcastBlockAnnouncement(hdr, tip.Block.Header.Hash(), tip.Block.Header.TimeSlot)
	}

	mp := mempool.New()
	protocolHandler := net.NewProtocolHandler(mp, *devValidator)
	node.SetProtocolHandler(protocolHandler)

	producer := blockproducer.NewProducer(*devValidator, bandersnatchSecretSeed, broadcastFunc, mp)
	producer.Start(ctx)
	defer producer.Stop()

	log.Printf("Block producer started for validator %d", *devValidator)
	log.Printf("Mempool initialized - ready to receive extrinsics via CE protocols")

	// Keep running until interrupted
	log.Printf("Node %d running. Press Ctrl+C to stop.", *devValidator)
	select {
	case <-ctx.Done():
		log.Println("Context cancelled, shutting down...")
	}
}
