package blockproducer

import (
	"context"
	"fmt"
	"log"
	"time"

	"jam/pkg/block"
	"jam/pkg/block/extrinsics"
	"jam/pkg/block/header"
	"jam/pkg/constants"
	"jam/pkg/serializer"
	"jam/pkg/state"
	"jam/pkg/staterepository"
	"jam/pkg/statetransition"
	"jam/pkg/types"
)

// Producer handles block production for a validator
type Producer struct {
	validatorIndex    int
	bandersnatchSeed  []byte
	broadcastFunc     func(header.Header) error
	ctx               context.Context
	cancel            context.CancelFunc
}

// NewProducer creates a new block producer
func NewProducer(validatorIndex int, bandersnatchSeed []byte, broadcastFunc func(header.Header) error) *Producer {
	return &Producer{
		validatorIndex:   validatorIndex,
		bandersnatchSeed: bandersnatchSeed,
		broadcastFunc:    broadcastFunc,
	}
}

// Start begins the slot timing loop
func (p *Producer) Start(ctx context.Context) {
	p.ctx, p.cancel = context.WithCancel(ctx)

	go p.slotLoop()
}

// Stop stops the block producer
func (p *Producer) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

// slotLoop runs the main slot timing loop
func (p *Producer) slotLoop() {
	slotDuration := time.Duration(constants.SlotPeriodInSeconds) * time.Second

	// Calculate time until next slot boundary
	now := time.Now()
	jamEpochStart := time.Unix(constants.JamCommonEraStartUnixTime, 0)
	timeSinceEpoch := now.Sub(jamEpochStart)
	currentSlotTime := timeSinceEpoch / slotDuration
	nextSlotTime := jamEpochStart.Add(time.Duration(currentSlotTime+1) * slotDuration)
	timeUntilNextSlot := nextSlotTime.Sub(now)

	log.Printf("[BlockProducer] Starting slot loop, first slot in %v", timeUntilNextSlot)

	// Wait until next slot boundary
	select {
	case <-time.After(timeUntilNextSlot):
	case <-p.ctx.Done():
		return
	}

	// Now run on slot boundaries
	ticker := time.NewTicker(slotDuration)
	defer ticker.Stop()

	// Process the first slot immediately
	p.processSlot()

	for {
		select {
		case <-ticker.C:
			p.processSlot()
		case <-p.ctx.Done():
			log.Printf("[BlockProducer] Stopping slot loop")
			return
		}
	}
}

// processSlot checks if we should produce a block for the current slot
func (p *Producer) processSlot() {
	currentSlot := p.getCurrentSlot()
	log.Printf("[BlockProducer] Processing slot %d", currentSlot)

	// Get current state
	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		log.Printf("[BlockProducer] Failed to create transaction: %v", err)
		return
	}
	defer tx.Close()

	currentState, err := state.GetState(tx)
	if err != nil {
		log.Printf("[BlockProducer] Failed to get state: %v", err)
		return
	}

	// Check if we're the slot leader
	isLeader, err := p.isSlotLeader(currentSlot, currentState)
	if err != nil {
		log.Printf("[BlockProducer] Failed to check slot leader: %v", err)
		return
	}

	if !isLeader {
		log.Printf("[BlockProducer] Not slot leader for slot %d", currentSlot)
		return
	}

	log.Printf("[BlockProducer] We are slot leader for slot %d! Producing block...", currentSlot)

	// Produce the block
	if err := p.produceBlock(currentSlot); err != nil {
		log.Printf("[BlockProducer] Failed to produce block: %v", err)
		return
	}
}

// getCurrentSlot calculates the current slot number
func (p *Producer) getCurrentSlot() types.Timeslot {
	now := time.Now().Unix()
	slotsSinceEpoch := (now - constants.JamCommonEraStartUnixTime) / int64(constants.SlotPeriodInSeconds)
	return types.Timeslot(slotsSinceEpoch)
}

// isSlotLeader checks if this validator should produce a block for the given slot
func (p *Producer) isSlotLeader(slot types.Timeslot, currentState *state.State) (bool, error) {
	// Calculate slot index within epoch
	slotIndexInEpoch := int(slot % types.Timeslot(constants.NumTimeslotsPerEpoch))

	// Get our Bandersnatch public key from the active validator keysets
	if p.validatorIndex >= len(currentState.ValidatorKeysetsActive) {
		return false, fmt.Errorf("validator index %d out of range", p.validatorIndex)
	}
	myBandersnatchKey := currentState.ValidatorKeysetsActive[p.validatorIndex].ToBandersnatchPublicKey()

	sks := currentState.SafroleBasicState.SealingKeySequence

	if sks.IsSealKeyTickets() {
		// Ticket-based mode: check if we own the ticket for this slot
		// The ticket contains a VerifiablyRandomIdentifier which is derived from our VRF
		// For now, we check if the ticket's entry index matches our validator index
		// This is a simplification - full implementation would verify VRF ownership
		ticket := sks.SealKeyTickets[slotIndexInEpoch]
		// TODO: Proper ticket ownership verification requires VRF proof
		// For now, we can't produce blocks in ticket mode without VRF signing capability
		log.Printf("[BlockProducer] Ticket mode - ticket entry index: %d, our index: %d",
			ticket.EntryIndex, p.validatorIndex)
		return false, nil
	} else {
		// Fallback mode: check if our Bandersnatch key matches the expected key
		expectedKey := sks.BandersnatchKeys[slotIndexInEpoch]
		isLeader := myBandersnatchKey == expectedKey
		if isLeader {
			log.Printf("[BlockProducer] Fallback mode - our key matches slot %d", slotIndexInEpoch)
		}
		return isLeader, nil
	}
}

// produceBlock creates and broadcasts a new block
func (p *Producer) produceBlock(slot types.Timeslot) error {
	// Get the current chain tip
	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Close()

	tip, err := block.GetTip(tx)
	if err != nil {
		return fmt.Errorf("failed to get chain tip: %w", err)
	}

	// Create empty extrinsics for now
	// TODO: Gather pending guarantees, assurances, tickets, etc.
	extrinsic := extrinsics.Extrinsics{
		Tickets:    extrinsics.Tickets{},
		Preimages:  extrinsics.Preimages{},
		Guarantees: extrinsics.Guarantees{},
		Assurances: extrinsics.Assurances{},
		Disputes:   extrinsics.Disputes{},
	}

	// Calculate extrinsic hash
	extrinsicHash := extrinsic.MerkleCommitment()

	// Create the unsigned header
	unsignedHeader := header.UnsignedHeader{
		ParentHash:                   tip.Block.Header.Hash(),
		PriorStateRoot:               tip.Info.PosteriorStateRoot,
		ExtrinsicHash:                extrinsicHash,
		TimeSlot:                     slot,
		EpochMarker:                  nil, // TODO: Set on epoch boundary
		WinningTicketsMarker:         nil, // TODO: Set when tickets are ready
		BandersnatchBlockAuthorIndex: types.ValidatorIndex(p.validatorIndex),
		VRFSignature:                 types.BandersnatchVRFSignature{}, // TODO: Sign with Bandersnatch
		OffendersMarker:              nil,
	}

	// Create the full header with block seal
	// TODO: Sign with Bandersnatch to create proper block seal
	newHeader := header.Header{
		UnsignedHeader: unsignedHeader,
		BlockSeal:      types.BandersnatchVRFSignature{}, // TODO: Sign
	}

	// Create the block
	newBlock := block.Block{
		Header:     newHeader,
		Extrinsics: extrinsic,
	}

	log.Printf("[BlockProducer] Created block: slot=%d, parent=%x", slot, newBlock.Header.ParentHash[:8])

	// Validate and import via STF
	stateRoot, err := statetransition.STF(newBlock)
	if err != nil {
		return fmt.Errorf("STF validation failed: %w", err)
	}

	log.Printf("[BlockProducer] Block validated, state root: %x", stateRoot[:8])

	// Broadcast the block header to grid neighbors
	if p.broadcastFunc != nil {
		if err := p.broadcastFunc(newHeader); err != nil {
			log.Printf("[BlockProducer] Failed to broadcast block: %v", err)
			// Don't return error - block is already imported locally
		} else {
			log.Printf("[BlockProducer] Block broadcast to grid neighbors")
		}
	}

	return nil
}

// SerializeBlock serializes a block for transmission
func SerializeBlock(blk block.Block) []byte {
	return serializer.Serialize(blk)
}
