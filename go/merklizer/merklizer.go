package merklizer

import (
	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
)

type StateKV struct {
	OriginalKey [31]byte
	Value       []byte
}

func MerklizeStateRecurser(bitSeqKeyMap map[bitsequence.BitSeqKey]StateKV) [32]byte {
	if len(bitSeqKeyMap) == 0 {
		return [32]byte{}
	}
	if len(bitSeqKeyMap) == 1 {
		bs := bitsequence.New()
		for _, stateKV := range bitSeqKeyMap {
			if len(stateKV.Value) <= 32 {
				serializedEmbeddedValueSize := serializer.Serialize(uint8(len(stateKV.Value)))
				bs.AppendBits([]bool{true, false})
				bs.Concat(bitsequence.FromBytes(serializedEmbeddedValueSize).SubsequenceFrom(2))
				bs.Concat(bitsequence.FromBytes(stateKV.OriginalKey[:]).SubsequenceTo(248))
				bs.Concat(bitsequence.FromBytes(stateKV.Value))
				for bs.Len() < 64*8 {
					bs.AppendBit(false)
				}
			} else {
				valueHash := blake2b.Sum256(stateKV.Value)
				bs.AppendBits([]bool{true, true, false, false, false, false, false, false})
				bs.Concat(bitsequence.FromBytes(stateKV.OriginalKey[:]).SubsequenceTo(248))
				bs.Concat(bitsequence.FromBytes(valueHash[:]))
			}
			break
		}
		return blake2b.Sum256(bs.Bytes())
	}

	leftMap := make(map[bitsequence.BitSeqKey]StateKV)
	rightMap := make(map[bitsequence.BitSeqKey]StateKV)

	// Process each key-value pair in the original map.
	for k, stateKV := range bitSeqKeyMap {
		// Convert the key to a BitSequence.
		bs := k.ToBitSequence()

		// Get the first bit.
		firstBit := bs.BitAt(0)

		// Get a new BitSequence containing all bits after the first one.
		newKeyBS := bs.SubsequenceFrom(1)

		// Insert into the appropriate map.
		if firstBit == false {
			leftMap[newKeyBS.Key()] = stateKV
		} else {
			rightMap[newKeyBS.Key()] = stateKV
		}
	}

	leftSubtrieHash := MerklizeStateRecurser(leftMap)
	rightSubtrieHash := MerklizeStateRecurser(rightMap)
	bs := bitsequence.New()
	bs.AppendBit(false)
	bs.Concat(bitsequence.FromBytes(leftSubtrieHash[:]).SubsequenceFrom(1))
	bs.Concat(bitsequence.FromBytes(rightSubtrieHash[:]))

	return blake2b.Sum256(bs.Bytes())
}
