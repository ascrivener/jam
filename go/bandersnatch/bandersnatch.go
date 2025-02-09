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
