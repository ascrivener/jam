package mempool

import (
	"jam/pkg/block/extrinsics"
	"jam/pkg/constants"
	"jam/pkg/types"
	"sync"
)

// Mempool holds pending extrinsics for block inclusion.
type Mempool struct {
	mu sync.RWMutex

	// Pending tickets received via CE 131/132
	tickets map[ticketKey]PendingTicket

	// Pending guarantees (work-reports) received via CE 135
	guarantees map[[32]byte]PendingGuarantee

	// Pending assurances received via CE 141
	assurances map[assuranceKey]PendingAssurance

	// Pending preimages received via CE 142/143
	preimages map[preimageKey]PendingPreimage

	// Pending judgments received via CE 145 (aggregated into verdicts)
	judgments map[judgmentKey]PendingJudgment

	// Pending verdicts (aggregated from judgments)
	verdicts map[[32]byte]PendingVerdict

	// Pending culprits
	culprits map[types.Ed25519PublicKey]PendingCulprit

	// Pending faults
	faults map[faultKey]PendingFault
}

// judgmentKey identifies a judgment
type judgmentKey struct {
	WorkReportHash [32]byte
	ValidatorIndex types.ValidatorIndex
}

// PendingJudgment is a judgment awaiting aggregation
type PendingJudgment struct {
	WorkReportHash [32]byte
	Judgment       extrinsics.Judgement
	ReceivedAt     int64
}

// ticketKey identifies a ticket
type ticketKey struct {
	EpochIndex uint32
	VRFOutput  [32]byte
}

// assuranceKey identifies an assurance
type assuranceKey struct {
	ValidatorIndex types.ValidatorIndex
	ParentHash     [32]byte
}

// preimageKey identifies a preimage
type preimageKey struct {
	ServiceIndex types.ServiceIndex
	Hash         [32]byte
}

// faultKey identifies a fault
type faultKey struct {
	WorkReportHash [32]byte
	ValidatorKey   types.Ed25519PublicKey
}

// PendingTicket is a ticket awaiting inclusion
type PendingTicket struct {
	EpochIndex uint32 // The epoch this ticket will be used in
	Ticket     extrinsics.Ticket
	ReceivedAt int64 // Unix timestamp
}

// PendingGuarantee is a guarantee awaiting inclusion
type PendingGuarantee struct {
	Guarantee  extrinsics.Guarantee
	ReceivedAt int64
}

// PendingAssurance is an assurance awaiting inclusion
type PendingAssurance struct {
	Assurance  extrinsics.Assurance
	ReceivedAt int64
}

// PendingPreimage is a preimage awaiting inclusion
type PendingPreimage struct {
	Preimage   extrinsics.Preimage
	ReceivedAt int64
}

// PendingVerdict is a verdict awaiting inclusion
type PendingVerdict struct {
	Verdict    extrinsics.Verdict
	ReceivedAt int64
}

// PendingCulprit is a culprit awaiting inclusion
type PendingCulprit struct {
	Culprit    extrinsics.Culprit
	ReceivedAt int64
}

// PendingFault is a fault awaiting inclusion
type PendingFault struct {
	Fault      extrinsics.Fault
	ReceivedAt int64
}

// New creates a new Mempool
func New() *Mempool {
	return &Mempool{
		tickets:    make(map[ticketKey]PendingTicket),
		guarantees: make(map[[32]byte]PendingGuarantee),
		assurances: make(map[assuranceKey]PendingAssurance),
		preimages:  make(map[preimageKey]PendingPreimage),
		judgments:  make(map[judgmentKey]PendingJudgment),
		verdicts:   make(map[[32]byte]PendingVerdict),
		culprits:   make(map[types.Ed25519PublicKey]PendingCulprit),
		faults:     make(map[faultKey]PendingFault),
	}
}

// AddTicket adds a ticket
func (m *Mempool) AddTicket(epochIndex uint32, ticket extrinsics.Ticket, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Derive VRF output from the proof for keying
	// The VRF output is the first 32 bytes of the proof
	var vrfOutput [32]byte
	copy(vrfOutput[:], ticket.ValidityProof[:32])

	key := ticketKey{EpochIndex: epochIndex, VRFOutput: vrfOutput}
	if _, exists := m.tickets[key]; exists {
		return false // Already have this ticket
	}

	m.tickets[key] = PendingTicket{
		EpochIndex: epochIndex,
		Ticket:     ticket,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetTickets returns tickets for the given epoch
func (m *Mempool) GetTickets(epochIndex uint32) []extrinsics.Ticket {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []extrinsics.Ticket
	for key, pending := range m.tickets {
		if key.EpochIndex == epochIndex {
			result = append(result, pending.Ticket)
		}
	}
	return result
}

// RemoveTicket removes a ticket
func (m *Mempool) RemoveTicket(epochIndex uint32, vrfOutput [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tickets, ticketKey{EpochIndex: epochIndex, VRFOutput: vrfOutput})
}

// AddGuarantee adds a guarantee
func (m *Mempool) AddGuarantee(guarantee extrinsics.Guarantee, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash := guarantee.WorkReport.WorkPackageSpecification.WorkPackageHash
	if _, exists := m.guarantees[hash]; exists {
		return false
	}

	m.guarantees[hash] = PendingGuarantee{
		Guarantee:  guarantee,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetGuarantees returns all guarantees
func (m *Mempool) GetGuarantees() []extrinsics.Guarantee {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]extrinsics.Guarantee, 0, len(m.guarantees))
	for _, pending := range m.guarantees {
		result = append(result, pending.Guarantee)
	}
	return result
}

// RemoveGuarantee removes a guarantee
func (m *Mempool) RemoveGuarantee(workPackageHash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.guarantees, workPackageHash)
}

// AddAssurance adds an assurance
func (m *Mempool) AddAssurance(assurance extrinsics.Assurance, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := assuranceKey{
		ValidatorIndex: assurance.ValidatorIndex,
		ParentHash:     assurance.ParentHash,
	}
	if _, exists := m.assurances[key]; exists {
		return false
	}

	m.assurances[key] = PendingAssurance{
		Assurance:  assurance,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetAssurances returns assurances for the given parent hash
func (m *Mempool) GetAssurances(parentHash [32]byte) []extrinsics.Assurance {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []extrinsics.Assurance
	for key, pending := range m.assurances {
		if key.ParentHash == parentHash {
			result = append(result, pending.Assurance)
		}
	}
	return result
}

// RemoveAssurance removes an assurance
func (m *Mempool) RemoveAssurance(validatorIndex types.ValidatorIndex, parentHash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.assurances, assuranceKey{ValidatorIndex: validatorIndex, ParentHash: parentHash})
}

// AddPreimage adds a preimage
func (m *Mempool) AddPreimage(preimage extrinsics.Preimage, hash [32]byte, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := preimageKey{ServiceIndex: preimage.ServiceIndex, Hash: hash}
	if _, exists := m.preimages[key]; exists {
		return false
	}

	m.preimages[key] = PendingPreimage{
		Preimage:   preimage,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetPreimages returns all preimages
func (m *Mempool) GetPreimages() []extrinsics.Preimage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]extrinsics.Preimage, 0, len(m.preimages))
	for _, pending := range m.preimages {
		result = append(result, pending.Preimage)
	}
	return result
}

// RemovePreimage removes a preimage
func (m *Mempool) RemovePreimage(serviceIndex types.ServiceIndex, hash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.preimages, preimageKey{ServiceIndex: serviceIndex, Hash: hash})
}

// AddJudgment adds a judgment, returns (isNew, isNegative, verdictFormed)
func (m *Mempool) AddJudgment(workReportHash [32]byte, epochIndex uint32, judgment extrinsics.Judgement, receivedAt int64) (bool, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := judgmentKey{WorkReportHash: workReportHash, ValidatorIndex: judgment.ValidatorIndex}

	// Check if we already have this judgment
	if _, exists := m.judgments[key]; exists {
		return false, false, false
	}

	// Add the judgment
	m.judgments[key] = PendingJudgment{
		WorkReportHash: workReportHash,
		Judgment:       judgment,
		ReceivedAt:     receivedAt,
	}

	isNegative := !judgment.Valid

	// Check if we already have a verdict for this work-report
	if _, exists := m.verdicts[workReportHash]; exists {
		return true, isNegative, false
	}

	// Count judgments for this work-report
	var judgmentsForReport []extrinsics.Judgement
	for k, pj := range m.judgments {
		if k.WorkReportHash == workReportHash {
			judgmentsForReport = append(judgmentsForReport, pj.Judgment)
		}
	}

	// Check if we have enough for a verdict (2/3 + 1 threshold)
	threshold := int(constants.NumValidatorSafetyThreshold)
	if len(judgmentsForReport) >= threshold {
		// Create verdict with exactly threshold judgments
		var verdictJudgments [constants.NumValidatorSafetyThreshold]extrinsics.Judgement
		for i := 0; i < threshold && i < len(judgmentsForReport); i++ {
			verdictJudgments[i] = judgmentsForReport[i]
		}

		verdict := extrinsics.Verdict{
			WorkReportHash: workReportHash,
			EpochIndex:     epochIndex,
			Judgements:     verdictJudgments,
		}

		m.verdicts[workReportHash] = PendingVerdict{
			Verdict:    verdict,
			ReceivedAt: receivedAt,
		}

		return true, isNegative, true
	}

	return true, isNegative, false
}

// GetJudgmentsForWorkReport returns judgments for a work-report
func (m *Mempool) GetJudgmentsForWorkReport(workReportHash [32]byte) []extrinsics.Judgement {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []extrinsics.Judgement
	for k, pj := range m.judgments {
		if k.WorkReportHash == workReportHash {
			result = append(result, pj.Judgment)
		}
	}
	return result
}

// AddVerdict adds a verdict
func (m *Mempool) AddVerdict(verdict extrinsics.Verdict, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.verdicts[verdict.WorkReportHash]; exists {
		return false
	}

	m.verdicts[verdict.WorkReportHash] = PendingVerdict{
		Verdict:    verdict,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetVerdicts returns all verdicts
func (m *Mempool) GetVerdicts() []extrinsics.Verdict {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]extrinsics.Verdict, 0, len(m.verdicts))
	for _, pending := range m.verdicts {
		result = append(result, pending.Verdict)
	}
	return result
}

// RemoveVerdict removes a verdict
func (m *Mempool) RemoveVerdict(workReportHash [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.verdicts, workReportHash)
}

// AddCulprit adds a culprit
func (m *Mempool) AddCulprit(culprit extrinsics.Culprit, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.culprits[culprit.ValidatorKey]; exists {
		return false
	}

	m.culprits[culprit.ValidatorKey] = PendingCulprit{
		Culprit:    culprit,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetCulprits returns all culprits
func (m *Mempool) GetCulprits() []extrinsics.Culprit {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]extrinsics.Culprit, 0, len(m.culprits))
	for _, pending := range m.culprits {
		result = append(result, pending.Culprit)
	}
	return result
}

// RemoveCulprit removes a culprit
func (m *Mempool) RemoveCulprit(validatorKey types.Ed25519PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.culprits, validatorKey)
}

// AddFault adds a fault
func (m *Mempool) AddFault(fault extrinsics.Fault, receivedAt int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := faultKey{WorkReportHash: fault.WorkReportHash, ValidatorKey: fault.ValidatorKey}
	if _, exists := m.faults[key]; exists {
		return false
	}

	m.faults[key] = PendingFault{
		Fault:      fault,
		ReceivedAt: receivedAt,
	}
	return true
}

// GetFaults returns all faults
func (m *Mempool) GetFaults() []extrinsics.Fault {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]extrinsics.Fault, 0, len(m.faults))
	for _, pending := range m.faults {
		result = append(result, pending.Fault)
	}
	return result
}

// RemoveFault removes a fault
func (m *Mempool) RemoveFault(workReportHash [32]byte, validatorKey types.Ed25519PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.faults, faultKey{WorkReportHash: workReportHash, ValidatorKey: validatorKey})
}

// Clear removes all items
func (m *Mempool) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tickets = make(map[ticketKey]PendingTicket)
	m.guarantees = make(map[[32]byte]PendingGuarantee)
	m.assurances = make(map[assuranceKey]PendingAssurance)
	m.preimages = make(map[preimageKey]PendingPreimage)
	m.judgments = make(map[judgmentKey]PendingJudgment)
	m.verdicts = make(map[[32]byte]PendingVerdict)
	m.culprits = make(map[types.Ed25519PublicKey]PendingCulprit)
	m.faults = make(map[faultKey]PendingFault)
}

// Stats returns mempool statistics
func (m *Mempool) Stats() MempoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MempoolStats{
		TicketCount:    len(m.tickets),
		GuaranteeCount: len(m.guarantees),
		AssuranceCount: len(m.assurances),
		PreimageCount:  len(m.preimages),
		JudgmentCount:  len(m.judgments),
		VerdictCount:   len(m.verdicts),
		CulpritCount:   len(m.culprits),
		FaultCount:     len(m.faults),
	}
}

// MempoolStats contains mempool statistics
type MempoolStats struct {
	TicketCount    int
	GuaranteeCount int
	AssuranceCount int
	PreimageCount  int
	JudgmentCount  int
	VerdictCount   int
	CulpritCount   int
	FaultCount     int
}
