package bandersnatch

/*
#cgo LDFLAGS: -L../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#include <stdlib.h>

// Declaration of the Rust function.
int vrf_output(const unsigned char *bytes_ptr, size_t bytes_len, unsigned char *out_ptr, size_t out_len);
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/ascrivener/jam/types"
)

func VRFOutput(bytes []byte) ([32]byte, error) {
	var out [32]byte
	if len(bytes) < 32 {
		return out, errors.New("vrfOutput must be at least 32 bytes long")
	}

	ret := C.vrf_output(
		(*C.uchar)(unsafe.Pointer(&bytes[0])),
		C.size_t(len(bytes)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
	)
	if ret != 0 {
		return out, errors.New("vrf_output failed")
	}

	return out, nil
}

// TODO: implement
func BandersnatchRingRoot(pks []types.BandersnatchPublicKey) (types.BandersnatchRingRoot, error) {
	return [144]byte{}, nil
}

// func ComputeO(pks [][32]byte) (types.BandersnatchRingRoot, error) {
// 	var out [144]byte

// 	// There must be at least one public key.
// 	if len(pks) == 0 {
// 		return out, errors.New("no public keys provided")
// 	}

// 	// Flatten the slice of [32]byte into a contiguous []byte.
// 	total := len(pks) * 32
// 	input := make([]byte, total)
// 	for i, pk := range pks {
// 		copy(input[i*32:(i+1)*32], pk[:])
// 	}

// 	// Call the exported C function.
// 	ret := C.compute_O(
// 		(*C.uchar)(unsafe.Pointer(&input[0])),
// 		C.size_t(len(pks)),
// 		(*C.uchar)(unsafe.Pointer(&out[0])),
// 		C.size_t(len(out)),
// 	)
// 	if ret != 0 {
// 		return out, errors.New("compute_O failed")
// 	}

// 	return out, nil
// }
