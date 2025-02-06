package merklizer

import "github.com/ascrivener/jam/serializer"

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
			} else {
				return [32]byte{}, nil
			}
		}
	}
}
