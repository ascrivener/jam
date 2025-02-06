package merklizer

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
)

func Merklize(serializedState map[[32]byte][]byte) ([32]byte, error) {
	if len(serializedState) == 0 {
		return [32]byte{}, nil
	}
	if len(serializedState) == 1 {
		for key, value := range serializedState {
			if len(value) <= 32 {
				serializedEmbeddedValueSize, err := serializer.Serialize(uint8(len(value)))
				if err != nil {
					return [32]byte{}, err
				}
				bs := bitsequence.New()
				bs.AppendBits([]bool{true, false})
				bs.Concat(bitsequence.FromBytes(serializedEmbeddedValueSize).SubsequenceFrom(2))
				bs.Concat(bitsequence.FromBytes(key[:]).SubsequenceTo(248))
				bs.Concat(bitsequence.FromBytes(value))
				for bs.Len() < 32*8 {
					bs.AppendBit(false)
				}
				return bs.To32ByteArray(), nil
			} else {
				return [32]byte{}, nil
			}
		}
	}

	return [32]byte{}, nil
}
