package statedb

import (
	"sync"

	"github.com/ascrivener/jam/serviceaccount"
	"github.com/ascrivener/jam/types"
	"github.com/ascrivener/jam/workpackage"
)

// StateDatabase manages historical service account states
type StateDatabase struct {
	states map[types.Timeslot]serviceaccount.ServiceAccounts
	mu     sync.RWMutex
}

// NewStateDatabase creates a new StateDatabase
func NewStateDatabase() *StateDatabase {
	return &StateDatabase{
		states: make(map[types.Timeslot]serviceaccount.ServiceAccounts),
	}
}

// AddState adds a service account state for a specific timeslot
func (db *StateDatabase) AddState(timeslot types.Timeslot, accounts serviceaccount.ServiceAccounts) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Deep copy the accounts to avoid later modifications affecting our history
	accountsCopy := make(serviceaccount.ServiceAccounts)
	for idx, account := range accounts {
		accountsCopy[idx] = deepCopyAccount(account)
	}

	db.states[timeslot] = accountsCopy
}

// GetStateForWorkPackage returns the appropriate state for a workpackage
// based on its LookupAnchorHeaderHash and Timeslot
func (db *StateDatabase) GetStateForWorkPackage(wp workpackage.WorkPackage) serviceaccount.ServiceAccounts {
	db.mu.RLock()
	defer db.mu.RUnlock()

	targetTimeslot := wp.RefinementContext.Timeslot

	// Check for exact match
	if accounts, ok := db.states[targetTimeslot]; ok {
		return accounts
	}

	// If no exact match, find the smallest timeslot ≥ target
	var bestTimeslot types.Timeslot
	found := false

	for timeslot := range db.states {
		if timeslot >= targetTimeslot && (!found || timeslot < bestTimeslot) {
			bestTimeslot = timeslot
			found = true
		}
	}

	if found {
		return db.states[bestTimeslot]
	}

	panic("No valid state found")
}

// CleanupOldStates removes states older than the oldest needed timeslot
func (db *StateDatabase) CleanupOldStates(oldestNeededTimeslot types.Timeslot) {
	db.mu.Lock()
	defer db.mu.Unlock()

	for timeslot := range db.states {
		if timeslot < oldestNeededTimeslot {
			delete(db.states, timeslot)
		}
	}
}

// deepCopyAccount creates a deep copy of a ServiceAccount to ensure
// historical states are not affected by future modifications
func deepCopyAccount(account *serviceaccount.ServiceAccount) *serviceaccount.ServiceAccount {
	// Create a new account
	newAccount := &serviceaccount.ServiceAccount{
		StorageDictionary:              make(map[[32]byte][]byte),
		PreimageLookup:                 make(map[[32]byte][]byte),
		PreimageLookupHistoricalStatus: make(map[serviceaccount.PreimageLookupHistoricalStatusKey][]types.Timeslot),
		CodeHash:                       account.CodeHash,
		Balance:                        account.Balance,
		MinimumGasForAccumulate:        account.MinimumGasForAccumulate,
		MinimumGasForOnTransfer:        account.MinimumGasForOnTransfer,
	}

	// Deep copy StorageDictionary
	for key, value := range account.StorageDictionary {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		newAccount.StorageDictionary[key] = valueCopy
	}

	// Deep copy PreimageLookup
	for key, value := range account.PreimageLookup {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		newAccount.PreimageLookup[key] = valueCopy
	}

	// Deep copy PreimageLookupHistoricalStatus
	for key, timeslots := range account.PreimageLookupHistoricalStatus {
		timeslotsCopy := make([]types.Timeslot, len(timeslots))
		copy(timeslotsCopy, timeslots)
		newAccount.PreimageLookupHistoricalStatus[key] = timeslotsCopy
	}

	return newAccount
}
