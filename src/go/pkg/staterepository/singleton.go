package staterepository

import (
	"sync"
)

var (
	globalRepo     *BoltStateRepository
	globalRepoOnce sync.Once
	globalRepoMu   sync.RWMutex
)

// InitializeGlobalRepository initializes the global repository singleton
// This should be called once during application startup
func InitializeGlobalRepository(dbPath string) error {
	var err error
	globalRepoOnce.Do(func() {
		globalRepo, err = newBoltStateRepository(dbPath)
	})
	return err
}

// GetGlobalRepository returns the global repository instance
// Returns nil if the repository hasn't been initialized
func GetGlobalRepository() *BoltStateRepository {
	globalRepoMu.RLock()
	defer globalRepoMu.RUnlock()
	return globalRepo
}

// IsGlobalRepositoryInitialized checks if the global repository has been initialized
func IsGlobalRepositoryInitialized() bool {
	globalRepoMu.RLock()
	defer globalRepoMu.RUnlock()
	return globalRepo != nil
}

// CloseGlobalRepository closes the global repository and cleans up resources
func CloseGlobalRepository() error {
	globalRepoMu.Lock()
	defer globalRepoMu.Unlock()

	if globalRepo != nil {
		err := globalRepo.Close()
		globalRepo = nil
		return err
	}
	return nil
}

// SetGlobalRepository allows setting the global repository instance
// This is primarily for testing purposes
func SetGlobalRepository(repo *BoltStateRepository) {
	globalRepoMu.Lock()
	defer globalRepoMu.Unlock()
	globalRepo = repo
}
