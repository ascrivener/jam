package staterepository

import (
	"fmt"
	"io"
	"sync"

	"github.com/cockroachdb/pebble"
)

var (
	globalRepo     *PebbleStateRepository
	globalRepoOnce sync.Once
	globalRepoMu   sync.RWMutex
)

// InitializeGlobalRepository initializes the global repository singleton
// This should be called once during application startup
func InitializeGlobalRepository(dbPath string) error {
	var err error
	globalRepoOnce.Do(func() {
		globalRepo, err = newPebbleStateRepository(dbPath)
	})
	return err
}

// GetGlobalRepository returns the global repository instance
// Returns nil if the repository hasn't been initialized
func GetGlobalRepository() *PebbleStateRepository {
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
func SetGlobalRepository(repo *PebbleStateRepository) {
	globalRepoMu.Lock()
	defer globalRepoMu.Unlock()
	globalRepo = repo
}

// Get retrieves a value using batch if provided, otherwise direct database access
func get(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil, nil, fmt.Errorf("global repository not initialized")
	}

	if batch != nil {
		return batch.Get(key)
	} else {
		return repo.db.Get(key)
	}
}

// NewIter creates an iterator using batch if provided, otherwise direct database access
func NewIter(batch *pebble.Batch, opts *pebble.IterOptions) (*pebble.Iterator, error) {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil, fmt.Errorf("global repository not initialized")
	}

	if batch != nil {
		return batch.NewIter(opts)
	} else {
		return repo.db.NewIter(opts)
	}
}

// Set writes a key-value pair using batch if provided, otherwise creates a temporary batch
func set(batch *pebble.Batch, key, value []byte) error {
	if batch != nil {
		return batch.Set(key, value, nil)
	} else {
		// For one-off writes, create a temporary batch and commit immediately
		repo := GetGlobalRepository()
		if repo == nil {
			return fmt.Errorf("global repository not initialized")
		}
		tempBatch := repo.db.NewBatch()
		defer tempBatch.Close()
		if err := tempBatch.Set(key, value, nil); err != nil {
			return err
		}
		return tempBatch.Commit(nil)
	}
}

// Delete removes a key using batch if provided, otherwise creates a temporary batch
func delete(batch *pebble.Batch, key []byte) error {
	if batch != nil {
		return batch.Delete(key, nil)
	} else {
		// For one-off deletes, create a temporary batch and commit immediately
		repo := GetGlobalRepository()
		if repo == nil {
			return fmt.Errorf("global repository not initialized")
		}
		tempBatch := repo.db.NewBatch()
		defer tempBatch.Close()
		if err := tempBatch.Delete(key, nil); err != nil {
			return err
		}
		return tempBatch.Commit(nil)
	}
}

// NewBatch creates a new write-only batch
func NewBatch() *pebble.Batch {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil
	}
	return repo.db.NewBatch()
}

// NewIndexedBatch creates a new batch that supports both reads and writes
func NewIndexedBatch() *pebble.Batch {
	repo := GetGlobalRepository()
	if repo == nil {
		return nil
	}
	return repo.db.NewIndexedBatch()
}
