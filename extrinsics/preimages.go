package extrinsics

type Preimages []Preimage

type Preimage struct {
	ServiceIndex uint64
	Data         []byte
}
