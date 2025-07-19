package erasurecoding

import (
	"fmt"

	"github.com/ascrivener/jam/constants"
	"github.com/ascrivener/jam/types"
	"github.com/klauspost/reedsolomon"
)

func CreateRecoveryForErasureCodedPiecesCount(erasureCodedPiecesCount int) func(chunks map[types.ValidatorIndex][]byte) ([]byte, error) {
	return func(chunks map[types.ValidatorIndex][]byte) ([]byte, error) {
		for _, chunk := range chunks {
			if len(chunk) != 2*erasureCodedPiecesCount {
				return nil, fmt.Errorf("invalid data size: expected %d, got %d", 2*erasureCodedPiecesCount, len(chunk))
			}
		}
		if len(chunks) != int(constants.RecoveryThreshold) {
			return nil, fmt.Errorf("invalid number of items: expected %d, got %d", int(constants.RecoveryThreshold), len(chunks))
		}

		enc, err := reedsolomon.New(len(chunks), int(constants.NumValidators)-len(chunks))
		if err != nil {
			return nil, fmt.Errorf("failed to create Reed-Solomon encoder: %v", err)
		}

		// Create result with exact size needed - holds just the recovery threshold amount
		result := make([]byte, len(chunks)*erasureCodedPiecesCount*2)

		// Check if we can use the shortcut (if we have exactly the first RecoveryThreshold validators)
		canUseShortcut := true
		for i := range len(chunks) {
			if _, exists := chunks[types.ValidatorIndex(i)]; !exists {
				canUseShortcut = false
				break
			}
		}

		if canUseShortcut {
			for i := range len(chunks) {
				validatorIdx := types.ValidatorIndex(i)
				copy(result[i*erasureCodedPiecesCount*2:], chunks[validatorIdx])
			}
			return result, nil
		}

		// Process each 2-byte piece position
		for p := range erasureCodedPiecesCount {
			// Calculate the offset for this piece once
			pieceOffset := p * 2

			// Initialize shards array for Reed-Solomon reconstruction
			shards := make([][]byte, constants.NumValidators)
			for validatorIndex, data := range chunks {
				shards[validatorIndex] = []byte{data[pieceOffset], data[pieceOffset+1]}
			}

			// Reconstruct the missing shards
			if err := enc.Reconstruct(shards); err != nil {
				return nil, fmt.Errorf("failed to reconstruct data: %v", err)
			}

			// We only care about the first RecoveryThreshold shards
			for validatorIdx := range len(chunks) {
				baseOffset := validatorIdx * erasureCodedPiecesCount * 2
				result[baseOffset+pieceOffset] = shards[validatorIdx][0]
				result[baseOffset+pieceOffset+1] = shards[validatorIdx][1]
			}
		}

		return result, nil
	}
}
