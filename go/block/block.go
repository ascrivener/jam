package block

import (
	"fmt"
	"time"

	"github.com/ascrivener/jam/bandersnatch"
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/merklizer"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/state"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/types"
	"github.com/cockroachdb/pebble"
	"golang.org/x/crypto/blake2b"
)

type Block struct {
	Header     header.Header
	Extrinsics extrinsics.Extrinsics
}

func (b Block) Verify(repo staterepository.PebbleStateRepository) error {

	parentBlock, err := Get(repo, b.Header.ParentHash)
	// (5.2) implicitly, there is no block whose header hash is equal to b.Header.ParentHash
	if err != nil {
		return fmt.Errorf("failed to get parent block: %w", err)
	}

	// (5.4)
	if b.Header.ExtrinsicHash != b.Extrinsics.MerkleCommitment() {
		return fmt.Errorf("extrinsic hash does not match actual extrinsic hash")
	}

	// (5.7)
	if b.Header.TimeSlot <= parentBlock.Block.Header.TimeSlot {
		return fmt.Errorf("time slot is not greater than parent block time slot")
	}

	if b.Header.TimeSlot*types.Timeslot(constants.SlotPeriodInSeconds) > types.Timeslot(time.Now().Unix()-constants.JamCommonEraStartUnixTime) {
		return fmt.Errorf("block timestamp is in the future relative to current time")
	}

	// (5.8)
	merklizedState := merklizer.MerklizeState(repo)

	if parentBlock.Info.PosteriorStateRoot != merklizedState {
		return fmt.Errorf("parent block state root does not match merklized state")
	}

	return nil
}

func (b Block) VerifyPostStateTransition(postState state.State) error {
	// Calculate time slot position within epoch (shared between both verification paths)
	slotIndexInEpoch := b.Header.TimeSlot % types.Timeslot(constants.NumTimeslotsPerEpoch)
	authorKey := postState.ValidatorKeysetsActive[b.Header.BandersnatchBlockAuthorIndex].ToBandersnatchPublicKey()

	if postState.SafroleBasicState.SealingKeySequence.IsSealKeyTickets() {
		// (6.15)
		// Verify block seal matches the expected ticket's VRF output
		expectedTicket := postState.SafroleBasicState.SealingKeySequence.SealKeyTickets[slotIndexInEpoch]
		actualVRFOutput, err := bandersnatch.BandersnatchVRFSignatureOutput(b.Header.BlockSeal)
		if err != nil {
			return fmt.Errorf("failed to extract VRF output from block seal: %w", err)
		}

		if expectedTicket.VerifiablyRandomIdentifier != actualVRFOutput {
			return fmt.Errorf("block seal VRF output does not match the expected ticket's identifier in sealing key sequence")
		}

		verified, err := bandersnatch.VerifySignature(authorKey, append(append([]byte("jam_ticket_seal"), postState.EntropyAccumulator[3][:]...), byte(expectedTicket.EntryIndex)), serializer.Serialize(b.Header.UnsignedHeader), b.Header.BlockSeal)
		if err != nil {
			return fmt.Errorf("failed to verify block seal: %w", err)
		}
		if !verified {
			return fmt.Errorf("block seal verification failed")
		}
	} else {
		// (6.16)
		// Verify block author matches the expected Bandersnatch key
		expectedKey := postState.SafroleBasicState.SealingKeySequence.BandersnatchKeys[slotIndexInEpoch]

		if expectedKey != authorKey {
			return fmt.Errorf("block author's Bandersnatch key does not match the expected key in sealing key sequence")
		}

		verified, err := bandersnatch.VerifySignature(authorKey, append([]byte("jam_fallback_seal"), postState.EntropyAccumulator[3][:]...), serializer.Serialize(b.Header.UnsignedHeader), b.Header.BlockSeal)
		if err != nil {
			return fmt.Errorf("failed to verify block seal: %w", err)
		}
		if !verified {
			return fmt.Errorf("block seal verification failed")
		}
	}
	return nil
}

type BlockWithInfo struct {
	Block Block
	Info  BlockInfo
}

type BlockInfo struct {
	PosteriorStateRoot [32]byte
}

func Get(repo staterepository.PebbleStateRepository, headerHash [32]byte) (*BlockWithInfo, error) {
	// Create a key with a prefix to separate block data from state data
	key := makeBlockKey(headerHash)

	// Retrieve the serialized block from the repository
	data, closer, err := repo.Get(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get block %x: %w", headerHash, err)
	}
	defer closer.Close()

	// Make a copy of the data since it's only valid until closer.Close()
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	var blockWithInfo BlockWithInfo
	if err := serializer.Deserialize(dataCopy, &blockWithInfo); err != nil {
		return nil, fmt.Errorf("failed to deserialize block %x: %w", headerHash, err)
	}

	return &blockWithInfo, nil
}

func (block BlockWithInfo) Set(repo staterepository.PebbleStateRepository) error {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Calculate the header hash
	headerBytes := serializer.Serialize(block.Block.Header)
	headerHash := blake2b.Sum256(headerBytes)

	// Create a key with a prefix
	key := makeBlockKey(headerHash)

	// Serialize the block
	data := serializer.Serialize(block)

	// Store the serialized block in the repository
	if err := batch.Set(key, data, nil); err != nil { // Use batch instead of repo
		return fmt.Errorf("failed to store block %x: %w", headerHash, err)
	}

	// Commit the batch if we created it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch: %w", err)
		}
	}

	return nil
}

// Helper functions for key construction
func makeBlockKey(headerHash [32]byte) []byte {
	return append([]byte("block:"), headerHash[:]...)
}
