package bandersnatch

/*
#cgo LDFLAGS: -L${SRCDIR}/../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#cgo darwin LDFLAGS: -framework Security

// Declaration of the Rust functions.
int ietf_vrf_output(const unsigned char *input_ptr, unsigned char *out_ptr);
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
	return out, nil
}

// TODO: implement
func BandersnatchVRFSignatureOutput(proof types.BandersnatchVRFSignature) ([32]byte, error) {
	var out [32]byte

	ret := C.ietf_vrf_output(
		(*C.uchar)(unsafe.Pointer(&proof)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		return out, errors.New("vrf_output failed")
	}

	return out, nil
}

func BandersnatchRingRoot(pks []types.BandersnatchPublicKey) types.BandersnatchRingRoot {
	var out [144]byte

	// There must be at least one public key.
	if len(pks) == 0 {
		panic(errors.New("no public keys provided"))
	}

	// Since pks is a slice of [32]byte, its elements are stored contiguously.
	// We can pass a pointer to the first element.
	ret := C.kzg_commitment(
		(*C.uchar)(unsafe.Pointer(&pks[0])),
		C.size_t(len(pks)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	)
	if ret != 0 {
		panic(errors.New("compute_O failed"))
	}

	return out
}
