package serviceaccount

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/staterepository"
	"github.com/ascrivener/jam/types"
	"github.com/cockroachdb/pebble"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

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

func (s *ServiceAccount) MetadataAndCode(repo staterepository.PebbleStateRepository) (*[]byte, *[]byte) {
	if preimage, ok := s.GetPreimageForHash(repo, s.CodeHash); ok {
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
		return &mBytes, &cBytes
	}
	return nil, nil
}

// GetServiceStorageItem retrieves a storage item for a service account
func (s *ServiceAccount) GetServiceStorageItem(repo staterepository.PebbleStateRepository, key [32]byte) ([]byte, bool) {
	// Create the key
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Fetch the value
	value, closer, err := repo.Get(dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false // Return nil for non-existent keys
	} else if err != nil {
		panic(fmt.Errorf("failed to get storage item for service %d: %w", s.ServiceIndex, err))
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	return result, true
}

// SetServiceStorageItem sets a storage item for a service account
func (s *ServiceAccount) SetServiceStorageItem(repo staterepository.PebbleStateRepository, key [32]byte, value []byte) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if this is a new key or an update
	oldItem, exists := s.GetServiceStorageItem(repo, key)

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
	if err := batch.Set(dbKey[:], value, nil); err != nil {
		panic(fmt.Errorf("failed to set storage item for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}

// DeleteServiceStorageItem deletes a storage item for a service account
func (s *ServiceAccount) DeleteServiceStorageItem(repo staterepository.PebbleStateRepository, key [32]byte) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if the item exists
	oldItem, exists := s.GetServiceStorageItem(repo, key)

	if !exists {
		return // Item doesn't exist, nothing to do
	}

	// Update storage metrics
	s.TotalItemsUsedInStorage--
	s.TotalOctetsUsedInStorage -= (32 + uint64(len(oldItem))) // Key + value

	// Delete the storage item
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)
	if err := batch.Delete(dbKey[:], nil); err != nil {
		panic(fmt.Errorf("failed to delete storage item for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}

// GetPreimageForHash retrieves a preimage for a given hash
func (s *ServiceAccount) GetPreimageForHash(repo staterepository.PebbleStateRepository, hash [32]byte) ([]byte, bool) {
	// Create the key
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Fetch the value
	value, closer, err := repo.Get(dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false // Return nil for non-existent keys
	} else if err != nil {
		panic(fmt.Errorf("failed to get preimage for hash in service %d: %w", s.ServiceIndex, err))
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	return result, true
}

// SetPreimageForHash sets a preimage for a given hash
func (s *ServiceAccount) SetPreimageForHash(repo staterepository.PebbleStateRepository, hash [32]byte, preimage []byte) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Set the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)
	if err := batch.Set(dbKey[:], preimage, nil); err != nil {
		panic(fmt.Errorf("failed to set preimage for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}

// DeletePreimageForHash deletes a preimage for a given hash
func (s *ServiceAccount) DeletePreimageForHash(repo staterepository.PebbleStateRepository, hash [32]byte) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Delete the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)
	if err := batch.Delete(dbKey[:], nil); err != nil {
		panic(fmt.Errorf("failed to delete preimage for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func (s *ServiceAccount) GetPreimageLookupHistoricalStatus(repo staterepository.PebbleStateRepository, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool) {
	// Create the key
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)

	// Fetch the value
	value, closer, err := repo.Get(dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false // Return nil for non-existent keys
	} else if err != nil {
		panic(fmt.Errorf("failed to get historical status for service %d: %w", s.ServiceIndex, err))
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	var status []types.Timeslot
	if err := serializer.Deserialize(result, &status); err != nil {
		panic(fmt.Errorf("failed to deserialize historical status for service %d: %w", s.ServiceIndex, err))
	}
	return status, true
}

// SetPreimageLookupHistoricalStatus sets historical status for a preimage lookup
func (s *ServiceAccount) SetPreimageLookupHistoricalStatus(repo staterepository.PebbleStateRepository, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if this is a new key or an update
	_, exists := s.GetPreimageLookupHistoricalStatus(repo, blobLength, hashedPreimage)

	// Update storage metrics
	if !exists {
		// New status
		s.TotalItemsUsedInStorage += 2
		// 81 bytes (4 for blobLength + 32 for hashedPreimage + 45 for the key structure)
		s.TotalOctetsUsedInStorage += 81 + uint64(blobLength)
	}

	// Set the historical status
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)
	if err := batch.Set(dbKey[:], serializer.Serialize(status), nil); err != nil {
		panic(fmt.Errorf("failed to set historical status for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func (s *ServiceAccount) DeletePreimageLookupHistoricalStatus(repo staterepository.PebbleStateRepository, blobLength uint32, hashedPreimage [32]byte) {
	// Create a new batch if one isn't already in progress
	batch := repo.GetBatch()
	ownBatch := batch == nil
	if ownBatch {
		batch = repo.NewBatch()
		defer batch.Close()
	}

	// Check if the status exists
	_, exists := s.GetPreimageLookupHistoricalStatus(repo, blobLength, hashedPreimage)

	if !exists {
		return // Status doesn't exist, nothing to do
	}

	// Update storage metrics
	s.TotalItemsUsedInStorage -= 2
	// 81 bytes (4 for blobLength + 32 for hashedPreimage + 45 for the key structure) + status size
	s.TotalOctetsUsedInStorage -= (81 + uint64(blobLength))

	// Delete the status
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)
	if err := batch.Delete(dbKey[:], nil); err != nil {
		panic(fmt.Errorf("failed to delete historical status for service %d: %w", s.ServiceIndex, err))
	}

	// If we created our own batch, commit it
	if ownBatch {
		if err := batch.Commit(pebble.Sync); err != nil {
			panic(fmt.Errorf("failed to commit batch for service %d: %w", s.ServiceIndex, err))
		}
	}
}
