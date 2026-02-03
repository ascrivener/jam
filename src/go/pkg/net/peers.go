package net

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"jam/pkg/state"
	"jam/pkg/staterepository"
	"jam/pkg/types"

	"golang.org/x/crypto/blake2b"
)

// PeerInfo contains information about a peer
type PeerInfo struct {
	Index   int
	Address string // "[::1]:40000" or derived from keyset
	Ed25519 [32]byte
	Keyset  *types.ValidatorKeyset // nil for non-validators or config-based peers
}

// PeerProvider abstracts peer discovery for different environments
type PeerProvider interface {
	// GetPeers returns all peers we should connect to (excluding ourselves)
	GetPeers() ([]PeerInfo, error)
	// GetMyInfo returns our own validator info
	GetMyInfo() (*ValidatorInfo, error)
	// GetTotalValidators returns the total number of validators
	GetTotalValidators() int
}

// ConfigPeerProvider provides peers from a static configuration
// Used for testnet/dev environments
type ConfigPeerProvider struct {
	myIndex    int
	myKey      []byte // Ed25519 private key (64 bytes)
	peers      []ConfigPeer
	totalCount int
}

// ConfigPeer represents a peer from configuration
type ConfigPeer struct {
	Index   int    `json:"index"`
	Address string `json:"address"`
}

// NewConfigPeerProvider creates a PeerProvider from config-based peer list
func NewConfigPeerProvider(myIndex int, myPrivateKey []byte, peers []ConfigPeer) *ConfigPeerProvider {
	return &ConfigPeerProvider{
		myIndex:    myIndex,
		myKey:      myPrivateKey,
		peers:      peers,
		totalCount: len(peers),
	}
}

// GetPeers returns all configured peers except ourselves
func (p *ConfigPeerProvider) GetPeers() ([]PeerInfo, error) {
	var result []PeerInfo

	for _, peer := range p.peers {
		if peer.Index == p.myIndex {
			continue // Skip ourselves
		}

		// Derive Ed25519 public key from peer index using JIP-5
		pubKey := deriveEd25519PublicKey(peer.Index)

		result = append(result, PeerInfo{
			Index:   peer.Index,
			Address: peer.Address,
			Ed25519: pubKey,
			Keyset:  nil, // Config-based peers don't have full keysets
		})
	}

	return result, nil
}

// GetMyInfo returns our own validator info
func (p *ConfigPeerProvider) GetMyInfo() (*ValidatorInfo, error) {
	// Extract public key from private key (last 32 bytes)
	var pubKey [32]byte
	copy(pubKey[:], p.myKey[32:])

	// For config-based provider, we create a minimal keyset with just the Ed25519 key
	var keyset types.ValidatorKeyset
	copy(keyset[32:64], pubKey[:]) // Ed25519 key is at offset 32-64

	return &ValidatorInfo{
		Keyset: keyset,
		Index:  p.myIndex,
	}, nil
}

// GetTotalValidators returns the total number of validators
func (p *ConfigPeerProvider) GetTotalValidators() int {
	return p.totalCount
}

// ChainStatePeerProvider provides peers from on-chain state
// Used for production environments
type ChainStatePeerProvider struct {
	myKey []byte // Ed25519 private key (64 bytes)
	state *state.State
}

// NewChainStatePeerProvider creates a PeerProvider from chain state
func NewChainStatePeerProvider(myPrivateKey []byte) (*ChainStatePeerProvider, error) {
	readTx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to create read transaction: %w", err)
	}
	defer readTx.Close()

	chainState, err := state.GetState(readTx)
	if err != nil {
		return nil, fmt.Errorf("failed to get state: %w", err)
	}

	return &ChainStatePeerProvider{
		myKey: myPrivateKey,
		state: chainState,
	}, nil
}

// GetPeers returns all validators from chain state except ourselves
func (p *ChainStatePeerProvider) GetPeers() ([]PeerInfo, error) {
	myPubKey := p.myKey[32:] // Extract public key from private key
	var result []PeerInfo

	for idx, keyset := range p.state.ValidatorKeysetsActive {
		pubKey := keyset.ToEd25519PublicKey()

		// Skip ourselves
		if bytesEqual(pubKey[:], myPubKey) {
			continue
		}

		// Extract network info from keyset (last 128 bytes)
		networkInfo := keyset[len(keyset)-128:]
		ipv6Addr := networkInfo[:16]
		port := binary.LittleEndian.Uint16(networkInfo[16:18])
		address := fmt.Sprintf("[%s]:%d", formatIPv6(ipv6Addr), port)

		result = append(result, PeerInfo{
			Index:   idx,
			Address: address,
			Ed25519: pubKey,
			Keyset:  &keyset,
		})
	}

	return result, nil
}

// GetMyInfo returns our own validator info from chain state
func (p *ChainStatePeerProvider) GetMyInfo() (*ValidatorInfo, error) {
	myPubKey := p.myKey[32:] // Extract public key from private key

	for idx, keyset := range p.state.ValidatorKeysetsActive {
		pubKey := keyset.ToEd25519PublicKey()
		if bytesEqual(pubKey[:], myPubKey) {
			return &ValidatorInfo{
				Keyset: keyset,
				Index:  idx,
			}, nil
		}
	}

	return nil, fmt.Errorf("own public key not found in validator set")
}

// GetTotalValidators returns the total number of validators
func (p *ChainStatePeerProvider) GetTotalValidators() int {
	return len(p.state.ValidatorKeysetsActive)
}

// deriveEd25519PublicKey derives an Ed25519 public key from a validator index using JIP-5
func deriveEd25519PublicKey(index int) [32]byte {
	// Create trivial seed as per JIP-5: repeat_8_times(encode_as_32bit_le(i))
	seed := make([]byte, 32)
	for i := 0; i < 32; i += 4 {
		binary.LittleEndian.PutUint32(seed[i:i+4], uint32(index))
	}

	// Derive ed25519_secret_seed = blake2b("jam_val_key_ed25519" ++ seed)
	h, _ := blake2b.New256(nil)
	h.Write([]byte("jam_val_key_ed25519"))
	h.Write(seed)
	ed25519SecretSeed := h.Sum(nil)

	// Derive private key and extract public key
	privateKey := ed25519.NewKeyFromSeed(ed25519SecretSeed)
	var pubKey [32]byte
	copy(pubKey[:], privateKey[32:])

	return pubKey
}

// formatIPv6 formats an IPv6 address from bytes
func formatIPv6(addr []byte) string {
	if len(addr) != 16 {
		return "::1"
	}
	// Simple formatting - could be improved
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5], addr[6], addr[7],
		addr[8], addr[9], addr[10], addr[11],
		addr[12], addr[13], addr[14], addr[15])
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
