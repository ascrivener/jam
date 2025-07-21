package extrinsics

import "jam/pkg/types"

type Preimages []Preimage

type Preimage struct {
	ServiceIndex types.ServiceIndex
	Data         []byte
}

func (p Preimages) TotalDataSize() int {
	sum := 0
	for _, preimage := range p {
		sum += len(preimage.Data)
	}
	return sum
}
