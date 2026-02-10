package blockproducer

import (
	"context"
	"fmt"
	"log"
	"time"

	"jam/pkg/bandersnatch"
	"jam/pkg/block"
	"jam/pkg/block/extrinsics"
	"jam/pkg/block/header"
	"jam/pkg/constants"
	"jam/pkg/mempool"
	"jam/pkg/serializer"
	"jam/pkg/state"
	"jam/pkg/staterepository"
	"jam/pkg/statetransition"
	"jam/pkg/ticket"
	"jam/pkg/types"
)

// Producer handles block production for a validator
type Producer struct {
	validatorIndex   int
	bandersnatchSeed []byte
	broadcastFunc    func(header.Header) error
	ctx              context.Context
	cancel           context.CancelFunc
	mempool          *mempool.Mempool
}

// SlotLeaderInfo contains information needed to produce a block when we're the slot leader
type SlotLeaderInfo struct {
	IsLeader   bool
	IsTicketed bool             // true if ticket mode, false if fallback mode
	EntryIndex types.GenericNum // Ticket entry index (only valid in ticket mode)
}

// NewProducer creates a new block producer
func NewProducer(validatorIndex int, bandersnatchSeed []byte, broadcastFunc func(header.Header) error, mp *mempool.Mempool) *Producer {
	return &Producer{
		validatorIndex:   validatorIndex,
		bandersnatchSeed: bandersnatchSeed,
		broadcastFunc:    broadcastFunc,
		mempool:          mp,
	}
}

// SetMempool sets the mempool for the producer (for late initialization)
func (p *Producer) SetMempool(mp *mempool.Mempool) {
	p.mempool = mp
}

// GetMempool returns the producer's mempool
func (p *Producer) GetMempool() *mempool.Mempool {
	return p.mempool
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

	leaderInfo, err := p.checkSlotLeader(currentSlot, currentState)
	if err != nil {
		log.Printf("[BlockProducer] Failed to check slot leader: %v", err)
		return
	}

	if !leaderInfo.IsLeader {
		log.Printf("[BlockProducer] Not slot leader for slot %d", currentSlot)
		return
	}

	log.Printf("[BlockProducer] We are slot leader for slot %d! Producing block...", currentSlot)

	if err := p.produceBlock(currentSlot, currentState, leaderInfo); err != nil {
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

// checkSlotLeader checks if this validator should produce a block for the given slot.
func (p *Producer) checkSlotLeader(slot types.Timeslot, currentState *state.State) (SlotLeaderInfo, error) {
	notLeader := SlotLeaderInfo{IsLeader: false}

	// Calculate slot index within epoch
	slotIndexInEpoch := int(slot % types.Timeslot(constants.NumTimeslotsPerEpoch))

	// Get our Bandersnatch public key from the active validator keysets
	if p.validatorIndex >= len(currentState.ValidatorKeysetsActive) {
		return notLeader, fmt.Errorf("validator index %d out of range", p.validatorIndex)
	}
	myBandersnatchKey := currentState.ValidatorKeysetsActive[p.validatorIndex].ToBandersnatchPublicKey()

	sks := currentState.SafroleBasicState.SealingKeySequence

	if sks.IsSealKeyTickets() {
		// Ticket mode: sign with message "jam_ticket_seal" || entropy[3] || ticket.EntryIndex
		// and check if VRF output matches ticket.VerifiablyRandomIdentifier
		ticket := sks.SealKeyTickets[slotIndexInEpoch]

		message := append([]byte("jam_ticket_seal"), currentState.EntropyAccumulator[3][:]...)
		message = append(message, byte(ticket.EntryIndex))

		vrfOutput, err := bandersnatch.VRFOutputFromSeed(p.bandersnatchSeed, message)
		if err != nil {
			return notLeader, fmt.Errorf("failed to compute VRF output: %w", err)
		}

		if vrfOutput != ticket.VerifiablyRandomIdentifier {
			return notLeader, nil
		}

		log.Printf("[BlockProducer] Ticket mode - we own ticket for slot %d (entry index: %d)",
			slotIndexInEpoch, ticket.EntryIndex)

		return SlotLeaderInfo{
			IsLeader:   true,
			IsTicketed: true,
			EntryIndex: ticket.EntryIndex,
		}, nil
	} else {
		// Fallback mode: check if our Bandersnatch key matches the expected key
		expectedKey := sks.BandersnatchKeys[slotIndexInEpoch]
		if myBandersnatchKey != expectedKey {
			return notLeader, nil
		}

		log.Printf("[BlockProducer] Fallback mode - we are slot leader for slot %d", slotIndexInEpoch)

		return SlotLeaderInfo{
			IsLeader:   true,
			IsTicketed: false,
		}, nil
	}
}

// produceBlock creates and broadcasts a new block
func (p *Producer) produceBlock(slot types.Timeslot, currentState *state.State, leaderInfo SlotLeaderInfo) error {
	tx, err := staterepository.NewTrackedTx([32]byte{})
	if err != nil {
		return fmt.Errorf("failed to create transaction: %w", err)
	}
	defer tx.Close()

	tip, err := block.GetTip(tx)
	if err != nil {
		return fmt.Errorf("failed to get chain tip: %w", err)
	}

	extrinsic := p.gatherExtrinsics(slot, currentState, tip.Block.Header.Hash())
	extrinsicHash := extrinsic.MerkleCommitment()

	var sealMessage []byte
	if leaderInfo.IsTicketed {
		// Ticket mode: message = "jam_ticket_seal" || entropy[3] || entry_index
		sealMessage = append([]byte("jam_ticket_seal"), currentState.EntropyAccumulator[3][:]...)
		sealMessage = append(sealMessage, byte(leaderInfo.EntryIndex))
	} else {
		// Fallback mode: message = "jam_fallback_seal" || entropy[3]
		sealMessage = append([]byte("jam_fallback_seal"), currentState.EntropyAccumulator[3][:]...)
	}

	sealVRFOutput, err := bandersnatch.VRFOutputFromSeed(p.bandersnatchSeed, sealMessage)
	if err != nil {
		return fmt.Errorf("failed to compute seal VRF output: %w", err)
	}

	entropyMessage := append([]byte("jam_entropy"), sealVRFOutput[:]...)
	vrfSignature, err := bandersnatch.VRFSign(p.bandersnatchSeed, entropyMessage, []byte{})
	if err != nil {
		return fmt.Errorf("failed to sign VRF signature: %w", err)
	}

	var winningTicketsMarker *[constants.NumTimeslotsPerEpoch]header.Ticket
	priorSlot := currentState.MostRecentBlockTimeslot
	if slot.EpochIndex() == priorSlot.EpochIndex() &&
		uint32(priorSlot.SlotPhaseIndex()) < constants.TicketSubmissionEndingSlotPhaseNumber &&
		uint32(slot.SlotPhaseIndex()) >= constants.TicketSubmissionEndingSlotPhaseNumber &&
		uint32(len(currentState.SafroleBasicState.TicketAccumulator)) == constants.NumTimeslotsPerEpoch {

		reordered := ticket.ReorderTicketsOutsideIn(currentState.SafroleBasicState.TicketAccumulator)
		var marker [constants.NumTimeslotsPerEpoch]header.Ticket
		for i, t := range reordered {
			marker[i] = header.Ticket{
				VerifiablyRandomIdentifier: t.VerifiablyRandomIdentifier,
				EntryIndex:                 t.EntryIndex,
			}
		}
		winningTicketsMarker = &marker
		log.Printf("[BlockProducer] Setting WinningTicketsMarker at slot %d", slot)
	}

	unsignedHeader := header.UnsignedHeader{
		ParentHash:                   tip.Block.Header.Hash(),
		PriorStateRoot:               tip.Info.PosteriorStateRoot,
		ExtrinsicHash:                extrinsicHash,
		TimeSlot:                     slot,
		EpochMarker:                  nil, // TODO: epoch boundary handling (requires disputes)
		WinningTicketsMarker:         winningTicketsMarker,
		BandersnatchBlockAuthorIndex: types.ValidatorIndex(p.validatorIndex),
		VRFSignature:                 vrfSignature,
		OffendersMarker:              nil,
	}

	unsignedHeaderBytes := serializer.Serialize(&unsignedHeader)
	blockSeal, err := bandersnatch.VRFSign(p.bandersnatchSeed, sealMessage, unsignedHeaderBytes)
	if err != nil {
		return fmt.Errorf("failed to sign block seal: %w", err)
	}

	newHeader := header.Header{
		UnsignedHeader: unsignedHeader,
		BlockSeal:      blockSeal,
	}

	newBlock := block.Block{
		Header:     newHeader,
		Extrinsics: extrinsic,
	}

	log.Printf("[BlockProducer] Created block: slot=%d, parent=%x", slot, newBlock.Header.ParentHash[:8])

	stateRoot, err := statetransition.STF(newBlock)
	if err != nil {
		return fmt.Errorf("STF validation failed: %w", err)
	}

	log.Printf("[BlockProducer] Block validated, state root: %x", stateRoot[:8])

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

// gatherExtrinsics collects pending extrinsics from the mempool
func (p *Producer) gatherExtrinsics(slot types.Timeslot, currentState *state.State, parentHash [32]byte) extrinsics.Extrinsics {
	result := extrinsics.Extrinsics{
		Tickets:    extrinsics.Tickets{},
		Preimages:  extrinsics.Preimages{},
		Guarantees: extrinsics.Guarantees{},
		Assurances: extrinsics.Assurances{},
		Disputes:   extrinsics.Disputes{},
	}

	if p.mempool == nil {
		return result
	}

	currentEpoch := uint32(slot / types.Timeslot(constants.NumTimeslotsPerEpoch))
	nextEpoch := currentEpoch + 1

	slotInEpoch := uint32(slot % types.Timeslot(constants.NumTimeslotsPerEpoch))
	if slotInEpoch < constants.TicketSubmissionEndingSlotPhaseNumber {
		tickets := p.mempool.GetTickets(nextEpoch)
		maxTickets := int(constants.MaxTicketsPerExtrinsic)
		if len(tickets) > maxTickets {
			tickets = tickets[:maxTickets]
		}
		result.Tickets = tickets
	}

	guarantees := p.mempool.GetGuarantees()
	maxGuarantees := int(constants.NumCores)
	if len(guarantees) > maxGuarantees {
		guarantees = guarantees[:maxGuarantees]
	}
	result.Guarantees = guarantees

	assurances := p.mempool.GetAssurances(parentHash)
	maxAssurances := int(constants.NumValidators)
	if len(assurances) > maxAssurances {
		assurances = assurances[:maxAssurances]
	}
	result.Assurances = assurances

	preimages := p.mempool.GetPreimages()
	var selectedPreimages extrinsics.Preimages
	totalSize := 0
	maxPreimageSize := 4096
	for _, preimage := range preimages {
		if totalSize+len(preimage.Data) <= maxPreimageSize {
			selectedPreimages = append(selectedPreimages, preimage)
			totalSize += len(preimage.Data)
		}
	}
	result.Preimages = selectedPreimages

	verdicts := p.mempool.GetVerdicts()
	culprits := p.mempool.GetCulprits()
	faults := p.mempool.GetFaults()

	result.Disputes = extrinsics.Disputes{
		Verdicts: verdicts,
		Culprits: culprits,
		Faults:   faults,
	}

	stats := p.mempool.Stats()
	if stats.TicketCount > 0 || stats.GuaranteeCount > 0 || stats.AssuranceCount > 0 ||
		stats.PreimageCount > 0 || stats.VerdictCount > 0 {
		log.Printf("[BlockProducer] Gathered extrinsics: %d tickets, %d guarantees, %d assurances, %d preimages, %d verdicts",
			len(result.Tickets), len(result.Guarantees), len(result.Assurances),
			len(result.Preimages), len(result.Disputes.Verdicts))
	}

	return result
}
