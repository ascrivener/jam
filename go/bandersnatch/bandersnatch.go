package bandersnatch

/*
#cgo LDFLAGS: -L${SRCDIR}/../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#cgo darwin LDFLAGS: -framework Security

// Declaration of the Rust functions.
int ietf_vrf_output(const unsigned char *input_ptr, size_t input_len, unsigned char *out_ptr);
int kzg_commitment(const unsigned char *hashes_ptr, size_t num_hashes, unsigned char *out_ptr);
int initialize_pcs_params();
*/
import "C"
import (
	"errors"
	"log"
	"unsafe"

	"github.com/ascrivener/jam/types"
)

// init is called when the package is imported
func init() {
	// Initialize the PCS parameters on package import
	ret := C.initialize_pcs_params()
	if ret != 0 {
		log.Fatalf("Failed to initialize PCS parameters: %d", ret)
	}
}

func BandersnatchRingVRFProofOutput(proof types.BandersnatchRingVRFProof) ([32]byte, error) {
	var out [32]byte

	ret := C.ietf_vrf_output(
		(*C.uchar)(unsafe.Pointer(&proof)),
		C.size_t(len(proof)),
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

	ret := C.ietf_vrf_output(
		(*C.uchar)(unsafe.Pointer(&proof)),
		C.size_t(len(proof)),
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
