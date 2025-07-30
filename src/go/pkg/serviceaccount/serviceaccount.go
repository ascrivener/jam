package serviceaccount

import (
	"errors"
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

// R
func (s *ServiceAccounts) IsNewPreimage(serviceIndex types.ServiceIndex, hash [32]byte, dataLen types.BlobLength) (bool, error) {
	serviceAccount := (*s)[serviceIndex]
	_, exists, err := serviceAccount.GetPreimageForHash(hash)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	availabilityTimeslots, exists, err := serviceAccount.GetPreimageLookupHistoricalStatus(uint32(dataLen), hash)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if len(availabilityTimeslots) > 0 {
		return false, nil
	}
	return true, nil
}

type PreimageLookupHistoricalStatusKey struct {
	HashedPreimage [23]byte
	BlobLength     types.BlobLength
}

type ServiceAccount struct {
	ServiceIndex             types.ServiceIndex
	CodeHash                 [32]byte       // c
	Balance                  types.Balance  // b
	MinimumGasForAccumulate  types.GasValue // g
	MinimumGasForOnTransfer  types.GasValue // m
	TotalOctetsUsedInStorage uint64         // o
	TotalItemsUsedInStorage  uint32         // i
}

// // o
// func (s ServiceAccount) TotalOctetsUsedInStorage() uint64 {
// 	total := uint64(0)
// 	for key := range s.PreimageLookupHistoricalStatus {
// 		total += 81 + uint64(key.BlobLength)
// 	}
// 	for _, blob := range s.StorageDictionary {
// 		total += 32 + uint64(len(blob))
// 	}
// 	return total
// }

// // i
// func (s ServiceAccount) TotalItemsUsedInStorage() uint32 {
// 	return uint32(2)*uint32(len(s.PreimageLookupHistoricalStatus)) + uint32(len(s.StorageDictionary))
// }

// t
func (s ServiceAccount) ThresholdBalanceNeeded() types.Balance {
	return types.Balance(constants.ServiceMinimumBalance + constants.ServiceMinimumBalancePerItem*uint64(s.TotalItemsUsedInStorage) + constants.ServiceMinimumBalancePerOctet*uint64(s.TotalOctetsUsedInStorage))
}

// bold m, bold c

func (s *ServiceAccount) MetadataAndCode() (*[]byte, *[]byte, error) {
	preimage, ok, err := s.GetPreimageForHash(s.CodeHash)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, nil
	}
	offset := 0
	L_m, n, ok := serializer.DecodeGeneralNatural(preimage[offset:])
	if !ok {
		panic("failed to decode metadata length")
	}
	offset += n
	m := preimage[offset : offset+int(L_m)]
	offset += int(L_m)
	c := preimage[offset:]

	// Convert types.Blob to []byte before taking address
	mBytes := []byte(m)
	cBytes := []byte(c)
	return &mBytes, &cBytes, nil
}

// GetServiceStorageItem retrieves a storage item for a service account
func (s *ServiceAccount) GetServiceStorageItem(key [32]byte) ([]byte, bool, error) {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return nil, false, errors.New("global repository not initialized")
	}
	// Create the key
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := repo.Get(prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil // Return nil for non-existent keys
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to get storage item for service %d: %w", s.ServiceIndex, err)
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	return result, true, nil
}

// SetServiceStorageItem sets a storage item for a service account
func (s *ServiceAccount) SetServiceStorageItem(key [32]byte, value []byte) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if this is a new key or an update
	oldItem, exists, err := s.GetServiceStorageItem(key)
	if err != nil {
		return err
	}

	// Update storage metrics
	if !exists {
		// New item
		s.TotalItemsUsedInStorage++
		s.TotalOctetsUsedInStorage += 32 + uint64(len(value)) // Key + value
	} else {
		// Update existing - subtract old size, add new size
		s.TotalOctetsUsedInStorage -= uint64(len(oldItem))
		s.TotalOctetsUsedInStorage += uint64(len(value))
	}

	// Set the storage item
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Set(prefixedKey, value, nil); err != nil {
		panic(fmt.Errorf("failed to set storage item for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
	return nil
}

// DeleteServiceStorageItem deletes a storage item for a service account
func (s *ServiceAccount) DeleteServiceStorageItem(key [32]byte) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if the item exists
	oldItem, exists, err := s.GetServiceStorageItem(key)
	if err != nil {
		return err
	}
	if !exists {
		return nil // Item doesn't exist, nothing to do
	}

	// Update storage metrics
	s.TotalItemsUsedInStorage--
	s.TotalOctetsUsedInStorage -= (32 + uint64(len(oldItem))) // Key + value

	// Delete the storage item
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Delete(prefixedKey, nil); err != nil {
		return fmt.Errorf("failed to delete storage item for service %d: %w", s.ServiceIndex, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err)
		}
	}
	return nil
}

// GetPreimageForHash retrieves a preimage for a given hash
func (s *ServiceAccount) GetPreimageForHash(hash [32]byte) ([]byte, bool, error) {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return nil, false, errors.New("global repository not initialized")
	}
	// Create the key
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := repo.Get(prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil // Return nil for non-existent keys
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to get preimage for hash in service %d: %w", s.ServiceIndex, err)
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	return result, true, nil
}

// SetPreimageForHash sets a preimage for a given hash
func (s *ServiceAccount) SetPreimageForHash(hash [32]byte, preimage []byte) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Set the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Set(prefixedKey, preimage, nil); err != nil {
		return fmt.Errorf("failed to set preimage for service %d: %w", s.ServiceIndex, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err)
		}
	}
	return nil
}

// DeletePreimageForHash deletes a preimage for a given hash
func (s *ServiceAccount) DeletePreimageForHash(hash [32]byte) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Delete the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Delete(prefixedKey, nil); err != nil {
		panic(fmt.Errorf("failed to delete preimage for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
	return nil
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func (s *ServiceAccount) GetPreimageLookupHistoricalStatus(blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return nil, false, errors.New("global repository not initialized")
	}
	// Create the key
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := repo.Get(prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil // Return nil for non-existent keys
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to get historical status for service %d: %w", s.ServiceIndex, err)
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	var status []types.Timeslot
	if err := serializer.Deserialize(result, &status); err != nil {
		return nil, false, fmt.Errorf("failed to deserialize historical status for service %d: %w", s.ServiceIndex, err)
	}
	return status, true, nil
}

// SetPreimageLookupHistoricalStatus sets historical status for a preimage lookup
func (s *ServiceAccount) SetPreimageLookupHistoricalStatus(blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if this is a new key or an update
	_, exists, err := s.GetPreimageLookupHistoricalStatus(blobLength, hashedPreimage)
	if err != nil {
		return fmt.Errorf("failed to get preimage lookup historical status for service %d: %w", s.ServiceIndex, err)
	}

	// Update storage metrics
	if !exists {
		// New status
		s.TotalItemsUsedInStorage += 2
		// 81 bytes (4 for blobLength + 32 for hashedPreimage + 45 for the key structure)
		s.TotalOctetsUsedInStorage += 81 + uint64(blobLength)
	}

	// Set the historical status
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Set(prefixedKey, serializer.Serialize(status), nil); err != nil {
		return fmt.Errorf("failed to set historical status for service %d: %w", s.ServiceIndex, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err)
		}
	}

	return nil
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func (s *ServiceAccount) DeletePreimageLookupHistoricalStatus(blobLength uint32, hashedPreimage [32]byte) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if the status exists
	_, exists, err := s.GetPreimageLookupHistoricalStatus(blobLength, hashedPreimage)
	if err != nil {
		return fmt.Errorf("failed to get preimage lookup historical status for service %d: %w", s.ServiceIndex, err)
	}

	if !exists {
		return nil // Status doesn't exist, nothing to do
	}

	// Update storage metrics
	s.TotalItemsUsedInStorage -= 2
	// 81 bytes (4 for blobLength + 32 for hashedPreimage + 45 for the key structure) + status size
	s.TotalOctetsUsedInStorage -= (81 + uint64(blobLength))

	// Delete the status
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Delete(prefixedKey, nil); err != nil {
		return fmt.Errorf("failed to delete historical status for service %d: %w", s.ServiceIndex, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err)
		}
	}

	return nil
}

func DeleteServiceAccountByServiceIndex(serviceIndex types.ServiceIndex) error {
	repo := staterepository.GetGlobalRepository()
	if repo == nil {
		return errors.New("global repository not initialized")
	}
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Delete the service account
	dbKey := staterepository.StateKeyConstructor(255, serviceIndex)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := batch.Delete(prefixedKey, nil); err != nil {
		return fmt.Errorf("failed to delete service account %d: %w", serviceIndex, err)
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			return fmt.Errorf("failed to commit batch for service %d: %w", serviceIndex, err)
		}
	}

	return nil
}
