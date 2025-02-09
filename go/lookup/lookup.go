// Package lookup provides an in-memory, thread-safe store for mapping
// a composite key—(service index, [32]byte hash)—to its corresponding preimage data.
package lookup

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/ascrivener/jam/types"
)

// PreimageData holds the preimage and its availability information.
// Availability is a slice that may contain up to 3 Timeslot elements.
type PreimageData struct {
	Preimage     []byte
	Availability []types.Timeslot
}

// PreimageKey is a composite key consisting of a service index and a 32-byte hash.
type PreimageKey struct {
	Service types.ServiceIndex
	Hash    [32]byte
}

// String returns a string representation of the PreimageKey.
// This is optional but can be useful if you need to log or use the key in a string-based cache.
func (pk PreimageKey) String() string {
	return fmt.Sprintf("%d:%s", pk.Service, hex.EncodeToString(pk.Hash[:]))
}

// PreimageLookup provides a thread-safe mapping from a composite key to PreimageData.
type PreimageLookup struct {
	store sync.Map // keys: PreimageKey, values: PreimageData
}

// NewPreimageLookup creates a new PreimageLookup instance.
func NewPreimageLookup() *PreimageLookup {
	return &PreimageLookup{}
}

// SetPreimage stores the given PreimageData under the specified composite key.
func (pl *PreimageLookup) SetPreimage(key PreimageKey, data PreimageData) {
	pl.store.Store(key, data)
}

// GetPreimage retrieves the PreimageData for the specified composite key.
// It returns the data along with a boolean indicating if the key was found.
func (pl *PreimageLookup) GetPreimage(key PreimageKey) (PreimageData, bool) {
	value, ok := pl.store.Load(key)
	if !ok {
		return PreimageData{}, false
	}
	data, ok := value.(PreimageData)
	return data, ok
}
