package serviceaccount

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/serializer"
	"github.com/ascrivener/jam/types"
)

type ServiceAccounts map[types.ServiceIndex]*ServiceAccount

type PreimageLookupHistoricalStatusKey struct {
	HashedPreimage [23]byte
	BlobLength     types.BlobLength
}

type ServiceAccount struct {
	ServiceIndex                   types.ServiceIndex
	Storage                        map[[31]byte]types.Blob
	GratisStorageOffset            types.Balance      // f
	CodeHash                       [32]byte           // c
	Balance                        types.Balance      // b
	MinimumGasForAccumulate        types.GasValue     // g
	MinimumGasForOnTransfer        types.GasValue     // m
	CreatedTimeSlot                types.Timeslot     // r
	MostRecentAccumulationTimeslot types.Timeslot     // a
	ParentServiceIndex             types.ServiceIndex // p
	TotalOctetsUsedInStorage       uint64             // o
	TotalItemsUsedInStorage        uint32             // i
}

func (s *ServiceAccount) storageDictionaryKeyFromFullKey(k []byte) [31]byte {
	ones := serializer.EncodeLittleEndian(4, ^uint64(0))
	combined := append(ones, k[:]...)
	return serializer.StateKeyConstructorFromHash(s.ServiceIndex, combined)
}

func (s *ServiceAccount) StorageDictionaryGet(k []byte) (types.Blob, bool) {
	key := s.storageDictionaryKeyFromFullKey(k)
	v, exists := s.Storage[key]
	return v, exists
}

func (s *ServiceAccount) StorageDictionarySet(k []byte, v types.Blob) {
	key := s.storageDictionaryKeyFromFullKey(k)

	// Update storage usage tracking
	oldValue, exists := s.Storage[key]

	// Add new value's storage contribution
	s.TotalOctetsUsedInStorage += uint64(34 + len(k) + len(v))
	s.TotalItemsUsedInStorage++

	// Subtract old value's storage contribution if it existed
	if exists {
		s.TotalOctetsUsedInStorage -= uint64(34 + len(k) + len(oldValue))
		s.TotalItemsUsedInStorage--
	}

	s.Storage[key] = v
}

func (s *ServiceAccount) StorageDictionaryDelete(k []byte) {
	key := s.storageDictionaryKeyFromFullKey(k)

	// Check if the key exists
	oldValue, exists := s.Storage[key]
	if exists {
		// Subtract the storage contribution
		s.TotalOctetsUsedInStorage -= uint64(34 + len(k) + len(oldValue))
		s.TotalItemsUsedInStorage--

		// Delete the entry
		delete(s.Storage, key)
	}
}

func (s *ServiceAccount) preimageLookupKeyFromFullKey(h [32]byte) [31]byte {
	onesMinusOne := serializer.EncodeLittleEndian(4, uint64(1<<32-2))
	combined := append(onesMinusOne, h[:]...)
	return serializer.StateKeyConstructorFromHash(s.ServiceIndex, combined)
}

func (s *ServiceAccount) PreimageLookupGet(h [32]byte) (types.Blob, bool) {
	key := s.preimageLookupKeyFromFullKey(h)
	v, exists := s.Storage[key]
	return v, exists
}

func (s *ServiceAccount) PreimageLookupSet(h [32]byte, v types.Blob) {
	key := s.preimageLookupKeyFromFullKey(h)
	s.Storage[key] = v
}

func (s *ServiceAccount) PreimageLookupDelete(h [32]byte) {
	key := s.preimageLookupKeyFromFullKey(h)
	delete(s.Storage, key)
}

func (s *ServiceAccount) preimageLookupHistoricalStatusKeyFromFullKey(h [32]byte, blobLength types.BlobLength) [31]byte {
	blobLengthBytes := serializer.EncodeLittleEndian(4, uint64(blobLength))
	combined := append(blobLengthBytes, h[:]...)
	return serializer.StateKeyConstructorFromHash(s.ServiceIndex, combined)
}

func (s *ServiceAccount) PreimageLookupHistoricalStatusGet(h [32]byte, blobLength types.BlobLength) ([]types.Timeslot, bool) {
	key := s.preimageLookupHistoricalStatusKeyFromFullKey(h, blobLength)
	v, exists := s.Storage[key]
	if !exists {
		return nil, false
	}

	timeslots := []types.Timeslot{}
	err := serializer.Deserialize(v, &timeslots)
	if err != nil {
		panic(fmt.Errorf("invalid serialization for timeslots (hash=%x, length=%d): %w", h, blobLength, err))
	}
	return timeslots, exists
}

func (s *ServiceAccount) PreimageLookupHistoricalStatusSet(h [32]byte, blobLength types.BlobLength, timeslots []types.Timeslot) {
	key := s.preimageLookupHistoricalStatusKeyFromFullKey(h, blobLength)

	// Update storage usage tracking
	_, exists := s.Storage[key]

	// Add new value's storage contribution
	s.TotalOctetsUsedInStorage += uint64(81 + blobLength)
	s.TotalItemsUsedInStorage += 2

	// Subtract old value's storage contribution if it existed
	if exists {
		s.TotalOctetsUsedInStorage -= uint64(81 + blobLength)
		s.TotalItemsUsedInStorage -= 2
	}

	s.Storage[key] = serializer.Serialize(timeslots)
}

func (s *ServiceAccount) PreimageLookupHistoricalStatusDelete(h [32]byte, blobLength types.BlobLength) {
	key := s.preimageLookupHistoricalStatusKeyFromFullKey(h, blobLength)

	// Check if the key exists
	oldValue, exists := s.Storage[key]
	if exists {
		// Subtract the storage contribution
		s.TotalOctetsUsedInStorage -= uint64(81 + len(oldValue))
		s.TotalItemsUsedInStorage -= 2

		// Delete the entry
		delete(s.Storage, key)
	}
}

// t
func (s ServiceAccount) ThresholdBalanceNeeded() types.Balance {
	return types.Balance(max(0, constants.ServiceMinimumBalance+constants.ServiceMinimumBalancePerItem*uint64(s.TotalItemsUsedInStorage)+constants.ServiceMinimumBalancePerOctet*uint64(s.TotalOctetsUsedInStorage)-uint64(s.GratisStorageOffset)))
}

// bold m, bold c

func (s *ServiceAccount) MetadataAndCode() (*[]byte, *[]byte) {
	if preimage, ok := s.PreimageLookupGet(s.CodeHash); ok {
		offset := 0
		L_m, n, ok := serializer.DecodeGeneralNatural(preimage[offset:])
		if !ok {
			return nil, nil
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
