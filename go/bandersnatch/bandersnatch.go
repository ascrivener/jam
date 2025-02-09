package bandersnatch

/*
#cgo LDFLAGS: -L../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#include <stdlib.h>

// Declaration of the Rust function.
int compute_y(const unsigned char *vrf_output_ptr, size_t vrf_output_len, unsigned char *out_ptr, size_t out_len);
*/
import "C"
import (
	"errors"
	"unsafe"
)

func VRFOutput(bytes []byte) ([32]byte, error) {
	var out [32]byte
	if len(bytes) < 32 {
		return out, errors.New("vrfOutput must be at least 32 bytes long")
	}

	ret := C.compute_y(
		(*C.uchar)(unsafe.Pointer(&bytes[0])),
		C.size_t(len(bytes)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
	)
	if ret != 0 {
		return out, errors.New("compute_y failed")
	}

	return out, nil
}
