package bandersnatch

/*
#cgo LDFLAGS: -L${SRCDIR}/../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#cgo darwin LDFLAGS: -framework Security
#cgo linux,amd64 LDFLAGS: -L/tmp/jam_crossbuild/lib -lbandersnatch_ffi -static
// Declaration of the Rust functions.
int ietf_vrf_output(const unsigned char *input_ptr, size_t input_len, unsigned char *out_ptr);
int kzg_commitment(const unsigned char *hashes_ptr, size_t num_hashes, unsigned char *out_ptr);
int initialize_pcs_params();
int verify_signature(const unsigned char *public_key_ptr, size_t public_key_len,
                     const unsigned char *message_ptr, size_t message_len,
                     const unsigned char *context_ptr, size_t context_len,
                     const unsigned char *proof_ptr, size_t proof_len);
int verify_ring_signature(const unsigned char *commitment_ptr, size_t commitment_len,
                         size_t ring_size,
                         const unsigned char *message_ptr, size_t message_len,
                         const unsigned char *context_ptr, size_t context_len,
                         const unsigned char *proof_ptr, size_t proof_len);
*/
import "C"
import (
	"errors"
	"log"
	"unsafe"

	"github.com/ascrivener/jam/constants"
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

// VerifySignature verifies a Bandersnatch VRF signature
// Returns:
//   - true if the signature is valid
//   - false if the signature is invalid
//   - error if there was a problem processing the inputs
func VerifySignature(
	publicKey types.BandersnatchPublicKey,
	message []byte,
	context []byte,
	signature types.BandersnatchVRFSignature,
) (bool, error) {
	// Call the Rust FFI function
	var contextPtr *C.uchar
	var contextLen C.size_t

	if len(context) > 0 {
		contextPtr = (*C.uchar)(unsafe.Pointer(&context[0]))
		contextLen = C.size_t(len(context))
	}

	ret := C.verify_signature(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		C.size_t(len(publicKey)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		contextPtr,
		contextLen,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
	)

	switch ret {
	case 1:
		return true, nil // Signature valid
	case 0:
		return false, nil // Signature invalid
	default:
		return false, errors.New("error processing signature verification")
	}
}

// VerifyRingSignature verifies a Bandersnatch ring VRF signature
// Returns:
//   - true if the signature is valid
//   - false if the signature is invalid
//   - error if there was a problem processing the inputs
func VerifyRingSignature(
	ringCommitment types.BandersnatchRingRoot,
	message []byte,
	context []byte,
	signature types.BandersnatchRingVRFProof,
) (bool, error) {
	// Call the Rust FFI function
	var contextPtr *C.uchar
	var contextLen C.size_t

	if len(context) > 0 {
		contextPtr = (*C.uchar)(unsafe.Pointer(&context[0]))
		contextLen = C.size_t(len(context))
	}

	ret := C.verify_ring_signature(
		(*C.uchar)(unsafe.Pointer(&ringCommitment[0])),
		C.size_t(len(ringCommitment)),
		C.size_t(constants.NumValidators),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		contextPtr,
		contextLen,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
	)

	switch ret {
	case 1:
		return true, nil // Signature valid
	case 0:
		return false, nil // Signature invalid
	default:
		return false, errors.New("error processing ring signature verification")
	}
}
