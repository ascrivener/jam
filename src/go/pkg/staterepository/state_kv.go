package staterepository

import (
	"io"
	"jam/pkg/serializer"
	"jam/pkg/types"

	"github.com/cockroachdb/pebble"
)

// Get retrieves a value for the given key with automatic "state:" prefixing
func GetStateKV(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	prefixedKey := addStatePrefix(key)
	return get(batch, prefixedKey)
}

// Set stores a key-value pair with automatic "state:" prefixing
func SetStateKV(batch *pebble.Batch, key, value []byte) error {
	prefixedKey := addStatePrefix(key)
	return set(batch, prefixedKey, value)
}

// Delete removes a key with automatic "state:" prefixing
func DeleteStateKV(batch *pebble.Batch, key []byte) error {
	prefixedKey := addStatePrefix(key)
	return delete(batch, prefixedKey)
}

// Exists checks if a key exists
func ExistsStateKV(batch *pebble.Batch, key []byte) (bool, error) {
	_, closer, err := GetStateKV(batch, key)
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer closer.Close()
	return true, nil
}

// SetServiceAccount stores service account data
func SetServiceAccount(batch *pebble.Batch, serviceIndex types.ServiceIndex, data []byte) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return SetStateKV(batch, dbKey[:], data)
}

// DeleteServiceAccount deletes a service account
func DeleteServiceAccount(batch *pebble.Batch, serviceIndex types.ServiceIndex) error {
	dbKey := stateKeyConstructorFromServiceIndex(serviceIndex)
	return DeleteStateKV(batch, dbKey[:])
}

// GetServiceStorageItem retrieves a service storage item with proper error handling
func GetServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey []byte) ([]byte, bool, error) {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	value, closer, err := GetStateKV(batch, dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetServiceStorageItem stores a service storage item
func SetServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey, value []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return SetStateKV(batch, dbKey[:], value)
}

// DeleteServiceStorageItem deletes a service storage item
func DeleteServiceStorageItem(batch *pebble.Batch, serviceIndex types.ServiceIndex, storageKey []byte) error {
	dbKey := makeServiceStorageKey(serviceIndex, storageKey)
	return DeleteStateKV(batch, dbKey[:])
}

// GetPreimage retrieves a preimage for a given hash
func GetPreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte) ([]byte, bool, error) {
	dbKey := makePreimageKey(serviceIndex, hash)
	value, closer, err := GetStateKV(batch, dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetPreimage stores a preimage for a given hash
func SetPreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte, preimage []byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return SetStateKV(batch, dbKey[:], preimage)
}

// DeletePreimage deletes a preimage for a given hash
func DeletePreimage(batch *pebble.Batch, serviceIndex types.ServiceIndex, hash [32]byte) error {
	dbKey := makePreimageKey(serviceIndex, hash)
	return DeleteStateKV(batch, dbKey[:])
}

// GetPreimageLookupHistoricalStatus retrieves historical status for a preimage lookup
func GetPreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) ([]types.Timeslot, bool, error) {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	value, closer, err := GetStateKV(batch, dbKey[:])
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)

	var status []types.Timeslot
	if err := serializer.Deserialize(result, &status); err != nil {
		return nil, false, err
	}
	return status, true, nil
}

// SetPreimageLookupHistoricalStatus stores historical status for a preimage lookup
func SetPreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte, status []types.Timeslot) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	serializedStatus := serializer.Serialize(status)
	return SetStateKV(batch, dbKey[:], serializedStatus)
}

// DeletePreimageLookupHistoricalStatus deletes historical status for a preimage lookup
func DeletePreimageLookupHistoricalStatus(batch *pebble.Batch, serviceIndex types.ServiceIndex, blobLength uint32, hashedPreimage [32]byte) error {
	dbKey := makeHistoricalStatusKey(serviceIndex, blobLength, hashedPreimage)
	return DeleteStateKV(batch, dbKey[:])
}

// NewIterator creates an iterator with "state:" prefix filtering
func NewIterator(batch *pebble.Batch) (*pebble.Iterator, error) {
	opts := &pebble.IterOptions{
		LowerBound: []byte("state:"),
		UpperBound: []byte("state;"), // Next ASCII character after ':'
	}
	return NewIter(batch, opts)
}

// addStatePrefix adds the "state:" prefix to a key
func addStatePrefix(key []byte) []byte {
	return append([]byte("state:"), key...)
}

// GetBlock retrieves block data with automatic "block:" prefixing
func GetBlock(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	prefixedKey := addBlockPrefix(key)
	return get(batch, prefixedKey)
}

// addBlockPrefix adds the "block:" prefix to a key
func addBlockPrefix(key []byte) []byte {
	return append([]byte("block:"), key...)
}

func GetTip(batch *pebble.Batch) ([]byte, io.Closer, error) {
	return get(batch, []byte("meta:chaintip"))
}

// GetRaw retrieves a value using the exact key without any prefixing
func GetRaw(batch *pebble.Batch, key []byte) ([]byte, io.Closer, error) {
	return get(batch, key)
}

// DeleteRaw deletes a value using the exact key without any prefixing
func DeleteRaw(batch *pebble.Batch, key []byte) error {
	return delete(batch, key)
}

// GetPreimageByHash retrieves a preimage by its hash with automatic "preimage:" prefixing
func GetPreimageByHash(batch *pebble.Batch, hash [32]byte) ([]byte, bool, error) {
	prefixedKey := addPreimagePrefix(hash[:])
	value, closer, err := get(batch, prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetPreimageByHash stores a preimage by its hash with automatic "preimage:" prefixing
func SetPreimageByHash(batch *pebble.Batch, hash [32]byte, preimage []byte) error {
	prefixedKey := addPreimagePrefix(hash[:])
	return set(batch, prefixedKey, preimage)
}

// addPreimagePrefix adds the "preimage:" prefix to a key
func addPreimagePrefix(key []byte) []byte {
	return append([]byte("preimage:"), key...)
}

// GetWorkReport retrieves a work report with automatic "workreport:" prefixing
func GetWorkReport(batch *pebble.Batch, key []byte) ([]byte, bool, error) {
	prefixedKey := addWorkReportPrefix(key)
	value, closer, err := get(batch, prefixedKey)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// SetWorkReportBySegmentRoot stores a work report by segment root
func SetWorkReportBySegmentRoot(batch *pebble.Batch, segmentRoot [32]byte, workReportData []byte) error {
	key := append([]byte("workreport:sr:"), segmentRoot[:]...)
	return set(batch, key, workReportData)
}

// SetWorkReportIndex stores a work package hash -> segment root mapping
func SetWorkReportIndex(batch *pebble.Batch, workPackageHash [32]byte, segmentRoot [32]byte) error {
	key := append([]byte("workreport:wph:"), workPackageHash[:]...)
	return set(batch, key, segmentRoot[:])
}

// GetWorkReportBySegmentRoot retrieves a work report by segment root
func GetWorkReportBySegmentRoot(batch *pebble.Batch, segmentRoot [32]byte) ([]byte, bool, error) {
	key := append([]byte("workreport:sr:"), segmentRoot[:]...)
	value, closer, err := get(batch, key)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// GetWorkReportIndex retrieves segment root by work package hash
func GetWorkReportIndex(batch *pebble.Batch, workPackageHash [32]byte) ([]byte, bool, error) {
	key := append([]byte("workreport:wph:"), workPackageHash[:]...)
	value, closer, err := get(batch, key)
	if err == pebble.ErrNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer closer.Close()

	// Make a copy since value is only valid until closer.Close()
	result := make([]byte, len(value))
	copy(result, value)
	return result, true, nil
}

// addWorkReportPrefix adds the "workreport:" prefix to a key
func addWorkReportPrefix(key []byte) []byte {
	return append([]byte("workreport:"), key...)
}
