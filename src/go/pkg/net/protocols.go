package net

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"jam/pkg/bitsequence"
	"jam/pkg/block/extrinsics"
	"jam/pkg/mempool"
	"jam/pkg/serializer"
	"jam/pkg/types"
	"log"
	"time"
)

// ProtocolHandler manages CE protocol handlers
type ProtocolHandler struct {
	mempool        *mempool.Mempool
	validatorIndex int
}

// NewProtocolHandler creates a new ProtocolHandler
func NewProtocolHandler(mp *mempool.Mempool, validatorIndex int) *ProtocolHandler {
	return &ProtocolHandler{
		mempool:        mp,
		validatorIndex: validatorIndex,
	}
}

// RegisterHandlers registers CE protocol handlers on a connection
func (ph *ProtocolHandler) RegisterHandlers(conn *jamnpsConnection) {
	// CE 131: Ticket distribution (generator -> proxy)
	conn.registerHandler(StreamKindCE131TicketDistribution, func(stream Stream) error {
		return ph.handleTicketFromGenerator(stream, conn.ValidatorIdx())
	})

	// CE 132: Ticket distribution (proxy -> validators)
	conn.registerHandler(StreamKindCE132TicketDistribution, func(stream Stream) error {
		return ph.handleTicketFromProxy(stream, conn.ValidatorIdx())
	})

	// CE 135: Work-report distribution
	conn.registerHandler(StreamKindCE135WorkReportDistribution, func(stream Stream) error {
		return ph.handleWorkReportDistribution(stream, conn.ValidatorIdx())
	})

	// CE 141: Assurance distribution
	conn.registerHandler(StreamKindCE141AssuranceDistribution, func(stream Stream) error {
		return ph.handleAssuranceDistribution(stream, conn.ValidatorIdx())
	})

	// CE 142: Preimage announcement
	conn.registerHandler(StreamKindCE142PreimageAnnouncement, func(stream Stream) error {
		return ph.handlePreimageAnnouncement(stream, conn)
	})

	// CE 143: Preimage request
	conn.registerHandler(StreamKindCE143PreimageRequest, func(stream Stream) error {
		return ph.handlePreimageRequest(stream)
	})

	// CE 144: Audit announcement
	conn.registerHandler(StreamKindCE144AuditAnnouncement, func(stream Stream) error {
		return ph.handleAuditAnnouncement(stream, conn.ValidatorIdx())
	})

	// CE 145: Judgment publication
	conn.registerHandler(StreamKindCE145JudgmentPublication, func(stream Stream) error {
		return ph.handleJudgmentPublication(stream, conn.ValidatorIdx())
	})
}

// parseTicketMessage parses a ticket message
func parseTicketMessage(msg []byte) (uint32, extrinsics.Ticket, error) {
	if len(msg) < 4+1+784 {
		return 0, extrinsics.Ticket{}, fmt.Errorf("ticket message too short: %d bytes", len(msg))
	}

	epochIndex := binary.LittleEndian.Uint32(msg[0:4])
	ticket := extrinsics.Ticket{
		EntryIndex: msg[4],
	}
	copy(ticket.ValidityProof[:], msg[5:5+784])

	return epochIndex, ticket, nil
}

// handleTicket handles CE 131/132 ticket distribution
func (ph *ProtocolHandler) handleTicket(stream Stream, fromValidator int, label string) (uint32, extrinsics.Ticket, bool, error) {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, extrinsics.Ticket{}, false, nil
		}
		return 0, extrinsics.Ticket{}, false, fmt.Errorf("failed to read ticket message: %w", err)
	}

	epochIndex, ticket, err := parseTicketMessage(msg)
	if err != nil {
		return 0, extrinsics.Ticket{}, false, err
	}

	isNew := ph.mempool.AddTicket(epochIndex, ticket, time.Now().Unix())
	if isNew {
		log.Printf("[%s] Added ticket from validator %d for epoch %d (entry index: %d)",
			label, fromValidator, epochIndex, ticket.EntryIndex)
	}

	stream.CloseWrite()
	return epochIndex, ticket, isNew, nil
}

// handleTicketFromGenerator handles CE 131 (generator -> proxy)
func (ph *ProtocolHandler) handleTicketFromGenerator(stream Stream, fromValidator int) error {
	epochIndex, ticket, isNew, err := ph.handleTicket(stream, fromValidator, "CE 131")
	if err != nil {
		return err
	}

	// Forward new tickets to grid neighbors
	if isNew {
		if node := GetGlobalNode(); node != nil {
			go node.BroadcastTicket(epochIndex, ticket)
		}
	}
	return nil
}

// handleTicketFromProxy handles CE 132 (proxy -> validators)
func (ph *ProtocolHandler) handleTicketFromProxy(stream Stream, fromValidator int) error {
	_, _, _, err := ph.handleTicket(stream, fromValidator, "CE 132")
	return err
}

// handleWorkReportDistribution handles CE 135 guaranteed work-report distribution
// Protocol: --> Guaranteed Work-Report
//
//	--> FIN
//	<-- FIN
func (ph *ProtocolHandler) handleWorkReportDistribution(stream Stream, fromValidator int) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read work-report message: %w", err)
	}

	guarantee, err := parseGuaranteedWorkReport(msg)
	if err != nil {
		return fmt.Errorf("failed to parse guaranteed work-report: %w", err)
	}

	receivedAt := time.Now().Unix()
	if ph.mempool.AddGuarantee(guarantee, receivedAt) {
		log.Printf("[CE 135] Added guaranteed work-report from validator %d (core: %d)",
			fromValidator, guarantee.WorkReport.CoreIndex)
	}

	stream.CloseWrite()
	return nil
}

// handleAssuranceDistribution handles CE 141 availability assurance distribution
// Protocol: --> Assurance (Header Hash ++ Bitfield ++ Ed25519 Signature)
//
//	--> FIN
//	<-- FIN
func (ph *ProtocolHandler) handleAssuranceDistribution(stream Stream, fromValidator int) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read assurance message: %w", err)
	}

	assurance, err := parseAssurance(msg, types.ValidatorIndex(fromValidator))
	if err != nil {
		return fmt.Errorf("failed to parse assurance: %w", err)
	}

	receivedAt := time.Now().Unix()
	if ph.mempool.AddAssurance(assurance, receivedAt) {
		log.Printf("[CE 141] Added assurance from validator %d for parent %x",
			fromValidator, assurance.ParentHash[:8])
	}

	stream.CloseWrite()
	return nil
}

// handlePreimageAnnouncement handles CE 142 preimage announcement
// Protocol: --> Service ID ++ Hash ++ Preimage Length
//
//	--> FIN
//	<-- FIN
func (ph *ProtocolHandler) handlePreimageAnnouncement(stream Stream, conn *jamnpsConnection) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read preimage announcement: %w", err)
	}
	if len(msg) < 4+32+4 {
		return fmt.Errorf("preimage announcement too short: %d bytes", len(msg))
	}

	serviceID := types.ServiceIndex(binary.LittleEndian.Uint32(msg[0:4]))
	var hash [32]byte
	copy(hash[:], msg[4:36])
	preimageLength := binary.LittleEndian.Uint32(msg[36:40])

	log.Printf("[CE 142] Received preimage announcement: service=%d, hash=%x, length=%d",
		serviceID, hash[:8], preimageLength)

	// TODO: Preimage handling requires (per spec):
	// 1. Check if preimage was requested on-chain by the given service
	// 2. Check if we already have this preimage in storage
	// 3. If needed and not possessed, request via CE 143 on this connection
	// 4. After obtaining, announce possession to grid neighbors

	stream.CloseWrite()
	return nil
}

// handlePreimageRequest handles CE 143 preimage request
// Protocol: --> Hash
//
//	--> FIN
//	<-- Preimage
//	<-- FIN
func (ph *ProtocolHandler) handlePreimageRequest(stream Stream) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read preimage request: %w", err)
	}

	if len(msg) != 32 {
		return fmt.Errorf("invalid preimage request length: %d", len(msg))
	}

	var hash [32]byte
	copy(hash[:], msg)

	log.Printf("[CE 143] Received preimage request for hash %x", hash[:8])

	// TODO: Preimage serving requires:
	// 1. Preimage storage layer to look up by hash
	// 2. Send preimage data back if found
	stream.CloseWrite()
	return nil
}

// handleAuditAnnouncement handles CE 144 audit announcement
// Protocol: --> Header Hash ++ Tranche ++ Announcement ++ Evidence
//
//	--> FIN
//	<-- FIN
func (ph *ProtocolHandler) handleAuditAnnouncement(stream Stream, fromValidator int) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read audit announcement: %w", err)
	}
	if len(msg) < 33 {
		return fmt.Errorf("audit announcement too short: %d bytes", len(msg))
	}

	var headerHash [32]byte
	copy(headerHash[:], msg[0:32])
	tranche := msg[32]

	log.Printf("[CE 144] Received audit announcement from validator %d: block=%x, tranche=%d",
		fromValidator, headerHash[:8], tranche)

	// TODO: Full audit announcement handling requires (per spec):
	// 1. Parse full message: Header Hash ++ Tranche ++ Announcement ++ Evidence
	//    - Announcement = len++[Core Index ++ Work-Report Hash] ++ Ed25519 Signature
	//    - Evidence = Bandersnatch sig (tranche 0) or no-show proofs (later tranches)
	// 2. Verify evidence (Bandersnatch signature or no-show claims)
	// 3. Track which work-reports are being audited by which validators
	// 4. Detect no-shows and potentially trigger our own auditing

	stream.CloseWrite()
	return nil
}

// handleJudgmentPublication handles CE 145 judgment publication
// Protocol: --> Epoch Index ++ Validator Index ++ Validity ++ Work-Report Hash ++ Ed25519 Signature
//
//	--> FIN
//	<-- FIN
func (ph *ProtocolHandler) handleJudgmentPublication(stream Stream, fromValidator int) error {
	msg, err := ReadMessage(stream)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("failed to read judgment: %w", err)
	}
	if len(msg) < 4+2+1+32+64 {
		return fmt.Errorf("judgment message too short: %d bytes", len(msg))
	}

	epochIndex := binary.LittleEndian.Uint32(msg[0:4])
	validatorIndex := types.ValidatorIndex(binary.LittleEndian.Uint16(msg[4:6]))
	validity := msg[6] == 1
	var workReportHash [32]byte
	copy(workReportHash[:], msg[7:39])
	var signature types.Ed25519Signature
	copy(signature[:], msg[39:103])

	judgment := extrinsics.Judgement{
		Valid:          validity,
		ValidatorIndex: validatorIndex,
		Signature:      signature,
	}

	receivedAt := time.Now().Unix()
	isNew, isNegative, verdictFormed := ph.mempool.AddJudgment(workReportHash, epochIndex, judgment, receivedAt)

	if isNew {
		log.Printf("[CE 145] Added judgment from validator %d: epoch=%d, validator=%d, valid=%v, report=%x",
			fromValidator, epochIndex, validatorIndex, validity, workReportHash[:8])

		if isNegative {
			log.Printf("[CE 145] Negative judgment - forwarding to grid neighbors")
			if node := GetGlobalNode(); node != nil {
				go node.BroadcastJudgment(epochIndex, validatorIndex, validity, workReportHash, signature)
			}
		}

		if verdictFormed {
			log.Printf("[CE 145] Verdict formed for work-report %x", workReportHash[:8])
		}
	}

	stream.CloseWrite()
	return nil
}

// parseGuaranteedWorkReport parses a guaranteed work-report
func parseGuaranteedWorkReport(data []byte) (extrinsics.Guarantee, error) {
	var guarantee extrinsics.Guarantee
	err := serializer.Deserialize(data, &guarantee)
	if err != nil {
		return extrinsics.Guarantee{}, fmt.Errorf("failed to deserialize guarantee: %w", err)
	}

	return guarantee, nil
}

// parseAssurance parses an assurance
func parseAssurance(data []byte, validatorIndex types.ValidatorIndex) (extrinsics.Assurance, error) {
	if len(data) < 32+64 {
		return extrinsics.Assurance{}, fmt.Errorf("assurance data too short: %d bytes", len(data))
	}

	var assurance extrinsics.Assurance

	copy(assurance.ParentHash[:], data[0:32])

	bitfieldSize := len(data) - 32 - 64
	if bitfieldSize > 0 {
		coreBitMask, err := bitsequence.CoreBitMaskFromBytesLSB(data[32 : 32+bitfieldSize])
		if err != nil {
			return extrinsics.Assurance{}, fmt.Errorf("failed to parse bitfield: %w", err)
		}
		assurance.CoreAvailabilityContributions = *coreBitMask
	}

	copy(assurance.Signature[:], data[len(data)-64:])
	assurance.ValidatorIndex = validatorIndex

	return assurance, nil
}

// EncodeTicket encodes a ticket for CE 131/132
func EncodeTicket(epochIndex uint32, ticket extrinsics.Ticket) []byte {
	data := make([]byte, 4+1+784)
	binary.LittleEndian.PutUint32(data[0:4], epochIndex)
	data[4] = ticket.EntryIndex
	copy(data[5:], ticket.ValidityProof[:])
	return data
}

// EncodeAssurance encodes an assurance for CE 141
func EncodeAssurance(assurance extrinsics.Assurance) []byte {
	bitfield := serializer.Serialize(assurance.CoreAvailabilityContributions)
	data := make([]byte, 32+len(bitfield)+64)
	copy(data[0:32], assurance.ParentHash[:])
	copy(data[32:32+len(bitfield)], bitfield)
	copy(data[32+len(bitfield):], assurance.Signature[:])
	return data
}

// EncodeJudgment encodes a judgment for CE 145
func EncodeJudgment(epochIndex uint32, validatorIndex types.ValidatorIndex, validity bool, workReportHash [32]byte, signature types.Ed25519Signature) []byte {
	data := make([]byte, 4+2+1+32+64)
	binary.LittleEndian.PutUint32(data[0:4], epochIndex)
	binary.LittleEndian.PutUint16(data[4:6], uint16(validatorIndex))
	if validity {
		data[6] = 1
	} else {
		data[6] = 0
	}
	copy(data[7:39], workReportHash[:])
	copy(data[39:103], signature[:])
	return data
}
