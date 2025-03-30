package merklizer

import (
	"golang.org/x/crypto/blake2b"

	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/serializer"
)

func MerklizeStateRecurser(bitSeqKeyMap map[bitsequence.BitSeqKey][]byte) [32]byte {
	if len(bitSeqKeyMap) == 0 {
		return [32]byte{}
	}
	if len(bitSeqKeyMap) == 1 {
		bs := bitsequence.New()
		for key, value := range bitSeqKeyMap {
			if len(value) <= 32 {
				serializedEmbeddedValueSize := serializer.Serialize(uint8(len(value)))
				bs.AppendBits([]bool{true, false})
				bs.Concat(bitsequence.FromBytes(serializedEmbeddedValueSize).SubsequenceFrom(2))
				bs.Concat(key.ToBitSequence().SubsequenceTo(248))
				bs.Concat(bitsequence.FromBytes(value))
				for bs.Len() < 32*8 {
					bs.AppendBit(false)
				}
			} else {
				valueHash := blake2b.Sum256(value)
				bs.AppendBits([]bool{true, true, false, false, false, false, false, false})
				bs.Concat(key.ToBitSequence().SubsequenceTo(248))
				bs.Concat(bitsequence.FromBytes(valueHash[:]))
			}
			break
		}
		return blake2b.Sum256(bs.Bytes())
	}

	leftMap := make(map[bitsequence.BitSeqKey][]byte)
	rightMap := make(map[bitsequence.BitSeqKey][]byte)

	// Process each key-value pair in the original map.
	for k, v := range bitSeqKeyMap {
		// Convert the key to a BitSequence.
		bs := k.ToBitSequence()

		// Get the first bit.
		firstBit := bs.BitAt(0)

		// Get a new BitSequence containing all bits after the first one.
		newKeyBS := bs.SubsequenceFrom(1)

		// Insert into the appropriate map.
		if firstBit == false {
			leftMap[newKeyBS.Key()] = v
		} else {
			rightMap[newKeyBS.Key()] = v
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
