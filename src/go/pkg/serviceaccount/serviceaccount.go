package serviceaccount

import (
	"fmt"

	"jam/pkg/constants"
	"jam/pkg/errors"
	"jam/pkg/serializer"
	"jam/pkg/staterepository"
	"jam/pkg/types"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

// R
func IsNewPreimage(tx *staterepository.TrackedTx, serviceIndex types.ServiceIndex, hash [32]byte, dataLen types.BlobLength) (bool, error) {
	serviceAccount, exists, err := GetServiceAccount(tx, serviceIndex)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errors.ProtocolErrorf("service account %d does not exist", serviceIndex)
	}
	_, exists, err = serviceAccount.GetPreimageForHash(tx, hash)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	availabilityTimeslots, exists, err := serviceAccount.GetPreimageLookupHistoricalStatus(tx, uint32(dataLen), hash)
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

type ServiceAccountData struct {
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

type ServiceAccount struct {
	ServiceIndex types.ServiceIndex
	ServiceAccountData
}

func GetServiceAccount(tx *staterepository.TrackedTx, serviceIndex types.ServiceIndex) (*ServiceAccount, bool, error) {
	if serviceAccount, exists, err := staterepository.GetServiceAccount(tx, serviceIndex); err != nil {
		return nil, false, err
	} else if !exists {
		return nil, false, nil
	} else {
		var serviceAccountData ServiceAccountData
		if err := serializer.Deserialize(serviceAccount, &serviceAccountData); err != nil {
			return nil, false, err
		}
		return &ServiceAccount{
			ServiceIndex:       serviceIndex,
			ServiceAccountData: serviceAccountData,
		}, true, nil
	}
}

func SetServiceAccount(tx *staterepository.TrackedTx, serviceAccount *ServiceAccount) {
	staterepository.SetServiceAccount(tx, serviceAccount.ServiceIndex, serializer.Serialize(serviceAccount.ServiceAccountData))
}

func DeleteServiceAccount(tx *staterepository.TrackedTx, serviceIndex types.ServiceIndex) {
	staterepository.DeleteServiceAccount(tx, serviceIndex)
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

func (s *ServiceAccount) MetadataAndCode(tx *staterepository.TrackedTx) (*[]byte, *[]byte, error) {
	preimage, ok, err := s.GetPreimageForHash(tx, s.CodeHash)
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
func (s *ServiceAccount) GetServiceStorageItem(tx *staterepository.TrackedTx, key []byte) ([]byte, bool, error) {
	return staterepository.GetServiceStorageItem(tx, s.ServiceIndex, key)
}

// SetServiceStorageItem sets a storage item for a service account
func (s *ServiceAccount) SetServiceStorageItem(tx *staterepository.TrackedTx, key []byte, value []byte) error {
	// Check if this is a new key or an update
	oldItem, exists, err := s.GetServiceStorageItem(tx, key)
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
	staterepository.SetServiceStorageItem(tx, s.ServiceIndex, key, value)
	return nil
}

// DeleteServiceStorageItem deletes a storage item for a service account
func (s *ServiceAccount) DeleteServiceStorageItem(tx *staterepository.TrackedTx, key []byte) error {
	// Check if the item exists
	oldItem, exists, err := s.GetServiceStorageItem(tx, key)
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
	staterepository.DeleteServiceStorageItem(tx, s.ServiceIndex, key)
	return nil
}

// GetPreimageForHash retrieves a preimage for a given hash
func (s *ServiceAccount) GetPreimageForHash(tx *staterepository.TrackedTx, hash [32]byte) ([]byte, bool, error) {
	return staterepository.GetServicePreimage(tx, s.ServiceIndex, hash)
}

// SetPreimageForHash sets a preimage for a given hash
func (s *ServiceAccount) SetPreimageForHash(tx *staterepository.TrackedTx, hash [32]byte, preimage []byte) {
	staterepository.SetServicePreimage(tx, s.ServiceIndex, hash, preimage)
}

// DeletePreimageForHash deletes a preimage for a given hash
func (s *ServiceAccount) DeletePreimageForHash(tx *staterepository.TrackedTx, hash [32]byte) {
	staterepository.DeleteServicePreimage(tx, s.ServiceIndex, hash)
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func (s *ServiceAccount) GetPreimageLookupHistoricalStatus(tx *staterepository.TrackedTx, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	return staterepository.GetPreimageLookupHistoricalStatus(tx, s.ServiceIndex, blobLength, hashedPreimage)
}

// SetPreimageLookupHistoricalStatus sets historical status for a preimage lookup
func (s *ServiceAccount) SetPreimageLookupHistoricalStatus(tx *staterepository.TrackedTx, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	// Check if this is a new key or an update
	_, exists, err := s.GetPreimageLookupHistoricalStatus(tx, blobLength, hashedPreimage)
	if err != nil {
		return fmt.Errorf("failed to get historical status for service %d: %w", s.ServiceIndex, err)
	}

	// Update storage metrics
	if !exists {
		// New status
		s.TotalItemsUsedInStorage += 2
		// 81 bytes (4 for blobLength + 32 for hashedPreimage + 45 for the key structure)
		s.TotalOctetsUsedInStorage += 81 + uint64(blobLength)
	}

	// Set the historical status
	staterepository.SetPreimageLookupHistoricalStatus(tx, s.ServiceIndex, blobLength, hashedPreimage, status)

	return nil
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func (s *ServiceAccount) DeletePreimageLookupHistoricalStatus(tx *staterepository.TrackedTx, blobLength uint32, hashedPreimage [32]byte) error {
	// Check if the status exists
	_, exists, err := s.GetPreimageLookupHistoricalStatus(tx, blobLength, hashedPreimage)
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

	// Delete using StateKV function (replaces manual key construction)
	staterepository.DeletePreimageLookupHistoricalStatus(tx, s.ServiceIndex, blobLength, hashedPreimage)

	return nil
}
