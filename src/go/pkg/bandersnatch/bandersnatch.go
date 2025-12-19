package bandersnatch

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../bandersnatch_ffi/target/release -lbandersnatch_ffi
#cgo darwin LDFLAGS: -framework Security
// Declaration of the Rust functions.
int ietf_vrf_output(const unsigned char *input_ptr, size_t input_len, unsigned char *out_ptr);
int kzg_commitment(const unsigned char *hashes_ptr, size_t num_hashes, unsigned char *out_ptr);
int initialize_ring_params(size_t ring_size);
int verify_signature(const unsigned char *public_key_ptr, size_t public_key_len,
                     const unsigned char *message_ptr, size_t message_len,
                     const unsigned char *context_ptr, size_t context_len,
                     const unsigned char *proof_ptr, size_t proof_len);
int verify_ring_signature(const unsigned char *commitment_ptr, size_t commitment_len,
                         const unsigned char *message_ptr, size_t message_len,
                         const unsigned char *context_ptr, size_t context_len,
                         const unsigned char *proof_ptr, size_t proof_len);
*/
import "C"
import (
	"crypto/sha256"
	"errors"
	"log"
	"sync"
	"unsafe"

	"jam/pkg/constants"
	"jam/pkg/types"
)

// init is called when the package is imported
func init() {
	// Initialize the ring parameters with the fixed ring size
	ret := C.initialize_ring_params(C.size_t(constants.NumValidators))
	if ret != 0 {
		log.Fatalf("Failed to initialize ring parameters: %d", ret)
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

// Cache for BandersnatchRingRoot results
type ringRootCache struct {
	mu    sync.RWMutex
	cache map[[32]byte]types.BandersnatchRingRoot
}

var ringCache = &ringRootCache{
	cache: make(map[[32]byte]types.BandersnatchRingRoot),
}

// hashPublicKeys creates a hash of the public keys slice for cache key
func hashPublicKeys(pks []types.BandersnatchPublicKey) [32]byte {
	hasher := sha256.New()
	for _, pk := range pks {
		hasher.Write(pk[:])
	}
	return sha256.Sum256(hasher.Sum(nil))
}

func BandersnatchRingRoot(pks []types.BandersnatchPublicKey) types.BandersnatchRingRoot {
	// Create cache key from hash of public keys
	cacheKey := hashPublicKeys(pks)

	// Check cache first
	ringCache.mu.RLock()
	if cached, exists := ringCache.cache[cacheKey]; exists {
		ringCache.mu.RUnlock()
		return cached
	}
	ringCache.mu.RUnlock()

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
		panic(errors.New("kzg_commitment failed"))
	}

	result := types.BandersnatchRingRoot(out)

	// Store in cache
	ringCache.mu.Lock()
	// Simple cache size limit to prevent unbounded growth
	if len(ringCache.cache) >= 1000 {
		// Clear cache when it gets too large (simple eviction)
		ringCache.cache = make(map[[32]byte]types.BandersnatchRingRoot)
	}
	ringCache.cache[cacheKey] = result
	ringCache.mu.Unlock()

	return result
}

// Cache for ring signature verification results
type ringSignatureCache struct {
	mu    sync.RWMutex
	cache map[string]bool
}

var globalRingSignatureCache = &ringSignatureCache{
	cache: make(map[string]bool),
}

// generateCacheKey creates a unique key for the signature verification inputs
func generateRingSignatureCacheKey(
	ringCommitment types.BandersnatchRingRoot,
	message []byte,
	context []byte,
	signature types.BandersnatchRingVRFProof,
) string {
	hasher := sha256.New()
	hasher.Write(ringCommitment[:])
	hasher.Write(message)
	hasher.Write(context)
	hasher.Write(signature[:])
	return string(hasher.Sum(nil))
}

// VerifyRingSignature verifies a ring signature with caching
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
	// Generate cache key
	cacheKey := generateRingSignatureCacheKey(ringCommitment, message, context, signature)

	// Check cache first
	globalRingSignatureCache.mu.RLock()
	if result, exists := globalRingSignatureCache.cache[cacheKey]; exists {
		globalRingSignatureCache.mu.RUnlock()
		return result, nil
	}
	globalRingSignatureCache.mu.RUnlock()

	// Not in cache - perform actual verification
	var contextPtr *C.uchar
	var contextLen C.size_t

	if len(context) > 0 {
		contextPtr = (*C.uchar)(unsafe.Pointer(&context[0]))
		contextLen = C.size_t(len(context))
	}

	ret := C.verify_ring_signature(
		(*C.uchar)(unsafe.Pointer(&ringCommitment[0])),
		C.size_t(len(ringCommitment)),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		contextPtr,
		contextLen,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
	)

	result := ret == 1

	// Cache the result
	globalRingSignatureCache.mu.Lock()
	globalRingSignatureCache.cache[cacheKey] = result
	globalRingSignatureCache.mu.Unlock()

	return result, nil
}

// Cache for signature verification results
type signatureCache struct {
	mu    sync.RWMutex
	cache map[string]bool
}

var globalSignatureCache = &signatureCache{
	cache: make(map[string]bool),
}

// generateSignatureCacheKey creates a unique key for the signature verification inputs
func generateSignatureCacheKey(
	publicKey types.BandersnatchPublicKey,
	message []byte,
	context []byte,
	signature types.BandersnatchVRFSignature,
) string {
	hasher := sha256.New()
	hasher.Write(publicKey[:])
	hasher.Write(message)
	hasher.Write(context)
	hasher.Write(signature[:])
	return string(hasher.Sum(nil))
}

// VerifySignature verifies a Bandersnatch VRF signature with caching
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
	// Generate cache key
	cacheKey := generateSignatureCacheKey(publicKey, message, context, signature)

	// Check cache first
	globalSignatureCache.mu.RLock()
	if result, exists := globalSignatureCache.cache[cacheKey]; exists {
		globalSignatureCache.mu.RUnlock()
		return result, nil
	}
	globalSignatureCache.mu.RUnlock()

	// Not in cache - perform actual verification
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
		result := true
		// Cache the result
		globalSignatureCache.mu.Lock()
		globalSignatureCache.cache[cacheKey] = result
		globalSignatureCache.mu.Unlock()
		return result, nil // Signature valid
	case 0:
		result := false
		// Cache the result
		globalSignatureCache.mu.Lock()
		globalSignatureCache.cache[cacheKey] = result
		globalSignatureCache.mu.Unlock()
		return result, nil // Signature invalid
	default:
		return false, errors.New("error processing signature verification")
	}
}
