package serviceaccount

import (
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

// R
func (s *ServiceAccounts) IsNewPreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte, dataLen types.BlobLength) (bool, error) {
	serviceAccount, exists := (*s)[serviceIndex]
	if !exists {
		return false, fmt.Errorf("service account %d does not exist", serviceIndex)
	}
	_, exists, err := serviceAccount.GetPreimageForHash(batch, hash)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	availabilityTimeslots, exists, err := serviceAccount.GetPreimageLookupHistoricalStatus(batch, uint32(dataLen), hash)
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
	ServiceIndex                   types.ServiceIndex
	CodeHash                       [32]byte           // c
	Balance                        types.Balance      // b
	MinimumGasForAccumulate        types.GasValue     // g
	MinimumGasForOnTransfer        types.GasValue     // m
	TotalOctetsUsedInStorage       uint64             // o
	GratisStorageOffset            types.Balance      // f
	TotalItemsUsedInStorage        uint32             // i
	CreatedTimeSlot                types.Timeslot     // r
	MostRecentAccumulationTimeslot types.Timeslot     // a
	ParentServiceIndex             types.ServiceIndex // p
}

// t
func (s ServiceAccount) ThresholdBalanceNeeded() types.Balance {
	balanceNeededWithoutOffset := constants.ServiceMinimumBalance + constants.ServiceMinimumBalancePerItem*uint64(s.TotalItemsUsedInStorage) + constants.ServiceMinimumBalancePerOctet*uint64(s.TotalOctetsUsedInStorage)
	if balanceNeededWithoutOffset <= uint64(s.GratisStorageOffset) {
		return 0
	}
	return types.Balance(balanceNeededWithoutOffset - uint64(s.GratisStorageOffset))
}

// bold m, bold c

func (s *ServiceAccount) MetadataAndCode(batch *pebble.Batch) (*[]byte, *[]byte, error) {
	preimage, ok, err := s.GetPreimageForHash(batch, s.CodeHash)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, nil
	}
	offset := 0
	L_m, n, ok := serializer.DecodeGeneralNatural(preimage[offset:])
	if !ok {
		return nil, nil, nil
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
func (s *ServiceAccount) GetServiceStorageItem(batch *pebble.Batch, key []byte) ([]byte, bool, error) {
	// Create the key
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := staterepository.Get(batch, prefixedKey)
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
func (s *ServiceAccount) SetServiceStorageItem(batch *pebble.Batch, key []byte, value []byte) error {
	// Check if this is a new key or an update
	oldItem, exists, err := s.GetServiceStorageItem(batch, key)
	if err != nil {
		return err
	}

	// Update storage metrics
	if !exists {
		// New item
		s.TotalItemsUsedInStorage++
		s.TotalOctetsUsedInStorage += 34 + uint64(len(key)) + uint64(len(value)) // Key + value
	} else {
		// Update existing - subtract old size, add new size
		s.TotalOctetsUsedInStorage -= uint64(len(oldItem))
		s.TotalOctetsUsedInStorage += uint64(len(value))
	}

	// Set the storage item
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := staterepository.Set(batch, prefixedKey, value); err != nil {
		return err
	}

	return nil
}

// DeleteServiceStorageItem deletes a storage item for a service account
func (s *ServiceAccount) DeleteServiceStorageItem(batch *pebble.Batch, key []byte) error {
	// Check if the item exists
	oldItem, exists, err := s.GetServiceStorageItem(batch, key)
	if err != nil {
		return err
	}
	if !exists {
		return nil // Item doesn't exist, nothing to do
	}

	// Update storage metrics
	s.TotalItemsUsedInStorage--
	s.TotalOctetsUsedInStorage -= (34 + uint64(len(key)) + uint64(len(oldItem))) // Key + value

	// Delete the storage item
	dbKey := staterepository.MakeServiceStorageKey(s.ServiceIndex, key)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := staterepository.Delete(batch, prefixedKey); err != nil {
		return err
	}

	return nil
}

// GetPreimageForHash retrieves a preimage for a given hash
func (s *ServiceAccount) GetPreimageForHash(batch *pebble.Batch, hash [32]byte) ([]byte, bool, error) {
	// Create the key
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := staterepository.Get(batch, prefixedKey)
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
func (s *ServiceAccount) SetPreimageForHash(batch *pebble.Batch, hash [32]byte, preimage []byte) error {
	// Set the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Set the preimage
	if err := staterepository.Set(batch, prefixedKey, preimage); err != nil {
		return fmt.Errorf("failed to set preimage for service %d: %w", s.ServiceIndex, err)
	}

	return nil
}

// DeletePreimageForHash deletes a preimage for a given hash
func (s *ServiceAccount) DeletePreimageForHash(batch *pebble.Batch, hash [32]byte) error {
	// Delete the preimage
	dbKey := staterepository.MakePreimageKey(s.ServiceIndex, hash)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := staterepository.Delete(batch, prefixedKey); err != nil {
		return fmt.Errorf("failed to delete preimage for service %d: %w", s.ServiceIndex, err)
	}

	return nil
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func (s *ServiceAccount) GetPreimageLookupHistoricalStatus(batch *pebble.Batch, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	// Create the key
	dbKey := staterepository.MakeHistoricalStatusKey(s.ServiceIndex, blobLength, hashedPreimage)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	// Fetch the value
	value, closer, err := staterepository.Get(batch, prefixedKey)
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
func (s *ServiceAccount) SetPreimageLookupHistoricalStatus(batch *pebble.Batch, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	// Check if this is a new key or an update
	_, exists, err := s.GetPreimageLookupHistoricalStatus(batch, blobLength, hashedPreimage)
	if err != nil {
		return fmt.Errorf("failed to get historical status for service %d: %w", s.ServiceIndex, err)
	}
	if batch == nil {
		return fmt.Errorf("Not in batch")
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

	if err := staterepository.Set(batch, prefixedKey, serializer.Serialize(status)); err != nil {
		return fmt.Errorf("failed to set historical status for service %d: %w", s.ServiceIndex, err)
	}

	return nil
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func (s *ServiceAccount) DeletePreimageLookupHistoricalStatus(batch *pebble.Batch, blobLength uint32, hashedPreimage [32]byte) error {
	// Check if the status exists
	_, exists, err := s.GetPreimageLookupHistoricalStatus(batch, blobLength, hashedPreimage)
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

	if err := staterepository.Delete(batch, prefixedKey); err != nil {
		return fmt.Errorf("failed to delete historical status for service %d: %w", s.ServiceIndex, err)
	}

	return nil
}

func DeleteServiceAccountByServiceIndex(batch *pebble.Batch, serviceIndex types.ServiceIndex) error {
	// Delete the service account
	dbKey := staterepository.StateKeyConstructorFromServiceIndex(serviceIndex)

	// Add state: prefix
	prefixedKey := append([]byte("state:"), dbKey[:]...)

	if err := staterepository.Delete(batch, prefixedKey); err != nil {
		return fmt.Errorf("failed to delete service account %d: %w", serviceIndex, err)
	}

	return nil
}
