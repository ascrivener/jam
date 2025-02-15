package bandersnatch

/*
#cgo LDFLAGS: -L../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#include <stdlib.h>

// Declaration of the Rust functions.
int bandersnatch_ring_vrf_proof_output(const unsigned char *input_ptr, unsigned char *out_ptr);
int kzg_commitment(const unsigned char *hashes_ptr, size_t num_hashes, unsigned char *out_ptr);
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/ascrivener/jam/types"
)

func BandersnatchRingVRFProofOutput(proof types.BandersnatchRingVRFProof) ([32]byte, error) {
	var out [32]byte

	ret := C.bandersnatch_ring_vrf_proof_output(
		(*C.uchar)(unsafe.Pointer(&proof)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, errors.New("vrf_output failed")
	}

	return out, nil
}

// TODO: implement
func BandersnatchVRFSignatureOutput(proof types.BandersnatchVRFSignature) ([32]byte, error) {
	var out [32]byte
	return out, nil
}

func BandersnatchRingRoot(pks []types.BandersnatchPublicKey) (types.BandersnatchRingRoot, error) {
	var out [144]byte

	// There must be at least one public key.
	if len(pks) == 0 {
		return out, errors.New("no public keys provided")
	}

	// Flatten the slice of [32]byte into a contiguous []byte.
	total := len(pks) * 32
	input := make([]byte, total)
	for i, pk := range pks {
		copy(input[i*32:(i+1)*32], pk[:])
	}

	// Call the exported C function.
	ret := C.kzg_commitment(
		(*C.uchar)(unsafe.Pointer(&input[0])),
		C.size_t(len(pks)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, errors.New("compute_O failed")
	}

	return out, nil
}
