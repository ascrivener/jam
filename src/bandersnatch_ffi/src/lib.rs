use ark_vrf::ietf::{Prover, Verifier};
use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::ring;
use ark_vrf::ring::RingSuite;
use ark_vrf::suites::bandersnatch::{
    BandersnatchSha512Ell2, PcsParams, RingCommitment, RingProof, RingProofParams,
};
use ark_vrf::Suite;
use ark_vrf::{codec, ietf, Error, Input, Output, Public, Secret};
use once_cell::sync::OnceCell;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn verify_signature_ffi<S: Suite>(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    proof: &[u8],
) -> Result<bool, Error> {
    // 1. Decode the public key into a curve point
    let pk_point = codec::point_decode::<S>(public_key).map_err(|_| Error::InvalidData)?;
    let public = Public(pk_point);

    // 2. Create input from message by hashing to a point first
    let input = Input::new(message).ok_or(Error::InvalidData)?;

    // 3. Extract the gamma/output from the proof (first 32 bytes)
    if proof.len() < 32 {
        return Err(Error::InvalidData);
    }
    let gamma_bytes = &proof[..32];
    let pt = codec::point_decode::<S>(gamma_bytes).map_err(|_| Error::InvalidData)?;
    let output = Output(pt);

    // 4. Decode proof components (c and s) - skip the gamma/output part
    let deserialized_proof = ietf::Proof::<S>::deserialize_compressed_unchecked(&mut &proof[32..])
        .map_err(|_| Error::InvalidData)?;

    // 5. Verify the proof
    match public.verify(input, output, context, &deserialized_proof) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailure) => Ok(false),
        Err(e) => Err(e),
    }
}

#[no_mangle]
pub extern "C" fn verify_signature(
    public_key_ptr: *const u8,
    public_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
) -> i32 {
    // Input validation
    if public_key_ptr.is_null() || message_ptr.is_null() || proof_ptr.is_null() {
        return -1; // Invalid input pointers
    }

    // Convert raw pointers to slices
    let public_key = unsafe { slice::from_raw_parts(public_key_ptr, public_key_len) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len) };
    let context = if context_ptr.is_null() {
        &[] // Empty context if null
    } else {
        unsafe { slice::from_raw_parts(context_ptr, context_len) }
    };
    let proof = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };

    // Call the internal verification function
    match verify_signature_ffi::<BandersnatchSha512Ell2>(public_key, message, context, proof) {
        Ok(true) => 1,  // Signature valid
        Ok(false) => 0, // Signature invalid
        Err(_) => -2,   // Error processing inputs
    }
}

pub fn ietf_vrf_output_ffi<S: Suite>(proof: &[u8]) -> Result<[u8; 32], Error> {
    // For Bandersnatch IETF proof, the format is:
    // - gamma (32 bytes)
    // - c (32 bytes)
    // - s (32 bytes)

    // Extract gamma from the first 32 bytes
    let gamma_bytes = &proof[..32];

    // Convert gamma bytes to a curve point
    // This uses the Suite's point decoding mechanism
    let pt: <S as Suite>::Affine =
        codec::point_decode::<S>(gamma_bytes).map_err(|_| Error::InvalidData)?;

    // Hash the point to get the VRF output
    let output = <S>::point_to_hash(&pt);

    let truncated: [u8; 32] = output.as_slice()[..32]
        .try_into()
        .map_err(|_| Error::InvalidData)?;

    Ok(truncated)
}

#[no_mangle]
pub extern "C" fn ietf_vrf_output(input_ptr: *const u8, input_len: usize, out_ptr: *mut u8) -> i32 {
    if input_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let input_slice = unsafe { slice::from_raw_parts(input_ptr, input_len) };

    match ietf_vrf_output_ffi::<BandersnatchSha512Ell2>(input_slice) {
        Ok(result_array) => {
            unsafe {
                std::ptr::copy_nonoverlapping(result_array.as_ptr(), out_ptr, 32);
            }
            0
        }
        Err(_) => -3,
    }
}

/// Compute VRF output from a seed and message without full signature.
pub fn vrf_output_from_seed_ffi(
    secret_key: &[u8],
    message: &[u8],
) -> Result<[u8; 32], Error> {
    if secret_key.len() != 32 {
        return Err(Error::InvalidData);
    }
    let secret = Secret::<BandersnatchSha512Ell2>::from_seed(secret_key);

    let input = Input::new(message).ok_or(Error::InvalidData)?;
    let output = secret.output(input);
    let vrf_hash = <BandersnatchSha512Ell2>::point_to_hash(&output.0);
    let vrf_output: [u8; 32] = vrf_hash.as_slice()[..32]
        .try_into()
        .map_err(|_| Error::InvalidData)?;

    Ok(vrf_output)
}

/// FFI wrapper for vrf_output_from_seed_ffi.
#[no_mangle]
pub extern "C" fn vrf_output_from_seed(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    vrf_output_ptr: *mut u8,
) -> i32 {
    if secret_key_ptr.is_null() || message_ptr.is_null() || vrf_output_ptr.is_null() {
        return -1;
    }

    let secret_key = unsafe { slice::from_raw_parts(secret_key_ptr, secret_key_len) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len) };

    match vrf_output_from_seed_ffi(secret_key, message) {
        Ok(vrf_output) => {
            unsafe {
                std::ptr::copy_nonoverlapping(vrf_output.as_ptr(), vrf_output_ptr, 32);
            }
            0
        }
        Err(_) => -2,
    }
}

/// Sign a message using Bandersnatch VRF. Returns 96-byte signature.
pub fn vrf_sign_ffi(
    secret_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; 96], Error> {
    if secret_key.len() != 32 {
        return Err(Error::InvalidData);
    }
    let secret = Secret::<BandersnatchSha512Ell2>::from_seed(secret_key);
    let input = Input::new(message).ok_or(Error::InvalidData)?;
    let output = secret.output(input);
    let proof = secret.prove(input, output, context);

    // Serialize: gamma (32 bytes) || proof (64 bytes)
    let mut signature = [0u8; 96];
    let mut gamma_bytes = Vec::new();
    output.0.serialize_compressed(&mut gamma_bytes)
        .map_err(|_| Error::InvalidData)?;
    if gamma_bytes.len() != 32 {
        return Err(Error::InvalidData);
    }
    signature[..32].copy_from_slice(&gamma_bytes);

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|_| Error::InvalidData)?;
    if proof_bytes.len() != 64 {
        return Err(Error::InvalidData);
    }
    signature[32..96].copy_from_slice(&proof_bytes);

    Ok(signature)
}

/// FFI wrapper for vrf_sign_ffi.
#[no_mangle]
pub extern "C" fn vrf_sign(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    signature_out_ptr: *mut u8,
) -> i32 {
    if secret_key_ptr.is_null() || message_ptr.is_null() || signature_out_ptr.is_null() {
        return -1;
    }
    let secret_key = unsafe { slice::from_raw_parts(secret_key_ptr, secret_key_len) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len) };
    let context = if context_ptr.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(context_ptr, context_len) }
    };

    match vrf_sign_ffi(secret_key, message, context) {
        Ok(signature) => {
            unsafe {
                std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_out_ptr, 96);
            }
            0
        }
        Err(_) => -2,
    }
}

/// Derive public key from secret key seed.
#[no_mangle]
pub extern "C" fn derive_public_key(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    public_key_out_ptr: *mut u8,
) -> i32 {
    if secret_key_ptr.is_null() || public_key_out_ptr.is_null() {
        return -1;
    }

    let secret_key = unsafe { slice::from_raw_parts(secret_key_ptr, secret_key_len) };
    
    if secret_key.len() != 32 {
        return -2;
    }

    // Create secret from seed
    let secret = Secret::<BandersnatchSha512Ell2>::from_seed(secret_key);

    // Derive public key
    let public = secret.public();

    // Serialize public key
    let mut pk_bytes = Vec::new();
    if public.0.serialize_compressed(&mut pk_bytes).is_err() {
        return -2;
    }

    if pk_bytes.len() != 32 {
        return -2;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(pk_bytes.as_ptr(), public_key_out_ptr, 32);
    }

    0
}

// Embed the SRS data directly in the binary
pub const PCS_SRS_DATA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
));

// Cache ring params
static RING_PARAMS: OnceCell<Result<RingProofParams, Error>> = OnceCell::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the ring parameters with a fixed ring size.
/// Returns 0 on success, -1 on failure.
/// Safe to call multiple times - will only initialize once.
#[no_mangle]
pub extern "C" fn initialize_ring_params(ring_size: usize) -> i32 {
    if INITIALIZED.load(Ordering::Relaxed) {
        return 0; // Already initialized
    }

    let result = || -> Result<RingProofParams, Error> {
        // Deserialize PCS params temporarily
        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &PCS_SRS_DATA[..])
            .map_err(|_| Error::InvalidData)?;

        // Create ring params and discard PCS params
        RingProofParams::from_pcs_params(ring_size, pcs_params).map_err(|_| Error::InvalidData)
    }();

    if RING_PARAMS.set(result).is_err() {
        return -1; // Error setting the value (should never happen)
    }

    INITIALIZED.store(true, Ordering::Relaxed);
    0
}

// Helper function to get the initialized ring parameters
fn get_ring_params() -> Result<&'static RingProofParams, Error> {
    match RING_PARAMS.get() {
        Some(Ok(params)) => Ok(params),
        Some(Err(_)) => Err(Error::InvalidData),
        None => Err(Error::InvalidData), // Must be initialized first
    }
}

pub fn kzg_commitment_ffi(hashes: &[[u8; 32]]) -> Result<RingCommitment, Error> {
    // Get the initialized ring parameters
    let ring_proof_params = get_ring_params()?;

    let mut ring_pks = Vec::with_capacity(hashes.len());
    for (_i, hash) in hashes.iter().enumerate() {
        // Per spec: if point decoding fails, use the padding point instead
        let point = codec::point_decode::<BandersnatchSha512Ell2>(&hash[..])
            .unwrap_or(<BandersnatchSha512Ell2 as RingSuite>::PADDING);
        ring_pks.push(point);
    }

    let verifier_key = ring_proof_params.verifier_key(&ring_pks);
    let commitment = verifier_key.commitment();

    Ok(commitment)
}

#[no_mangle]
pub extern "C" fn kzg_commitment(
    hashes_ptr: *const u8,
    num_hashes: usize,
    out_ptr: *mut u8,
) -> i32 {
    if hashes_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    let total_bytes = match num_hashes.checked_mul(32) {
        Some(n) => n,
        None => {
            return -2;
        }
    };

    let hashes_slice = unsafe { slice::from_raw_parts(hashes_ptr, total_bytes) };

    let mut hashes_vec = Vec::with_capacity(num_hashes);
    for (_i, chunk) in hashes_slice.chunks(32).enumerate() {
        if chunk.len() != 32 {
            return -3;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);

        hashes_vec.push(arr);
    }

    let commitment = match crate::kzg_commitment_ffi(&hashes_vec) {
        Ok(c) => c,
        Err(_) => {
            return -4;
        }
    };

    let mut out_bytes = Vec::new();
    if let Err(_) = commitment.serialize_compressed(&mut out_bytes) {
        return -5;
    }

    if out_bytes.len() != 144 {
        return -6;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, 144);
    }

    0
}

pub fn verify_ring_signature_ffi(
    ring_commitment: &[u8],
    message: &[u8],
    context: &[u8],
    proof: &[u8],
) -> Result<bool, Error> {
    // Get the initialized ring parameters
    let ring_proof_params = get_ring_params()?;

    // 2. Decode the ring commitment
    let commitment =
        CanonicalDeserialize::deserialize_compressed_unchecked(&mut &ring_commitment[..])
            .map_err(|_| Error::InvalidData)?;

    // 3. Create input from message by hashing to a point first
    let input = Input::new(message).ok_or(Error::InvalidData)?;

    // 4. Extract the gamma/output from the proof (first 32 bytes)
    if proof.len() < 32 {
        return Err(Error::InvalidData);
    }
    let gamma_bytes = &proof[..32];
    let pt = codec::point_decode::<BandersnatchSha512Ell2>(gamma_bytes)
        .map_err(|_| Error::InvalidData)?;
    let output = Output(pt);

    // 5. Decode proof components - skip the gamma/output part
    let deserialized_proof = RingProof::deserialize_compressed_unchecked(&mut &proof[32..])
        .map_err(|_| Error::InvalidData)?;

    // 6. Create a verifier for the commitment
    let verifier_key = ring_proof_params.verifier_key_from_commitment(commitment);
    let verifier = ring_proof_params.verifier(verifier_key);

    // 7. Verify the proof
    match <Public<BandersnatchSha512Ell2> as ring::Verifier<BandersnatchSha512Ell2>>::verify(
        input,
        output,
        context,
        &deserialized_proof,
        &verifier,
    ) {
        Ok(()) => Ok(true),
        Err(Error::VerificationFailure) => Ok(false),
        Err(e) => Err(e),
    }
}

#[no_mangle]
pub extern "C" fn verify_ring_signature(
    commitment_ptr: *const u8,
    commitment_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    context_ptr: *const u8,
    context_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
) -> i32 {
    // Input validation
    if commitment_ptr.is_null() || message_ptr.is_null() || proof_ptr.is_null() {
        return -1; // Invalid input pointers or ring size
    }

    // Convert raw pointers to slices
    let commitment = unsafe { slice::from_raw_parts(commitment_ptr, commitment_len) };
    let message = unsafe { slice::from_raw_parts(message_ptr, message_len) };
    let context = if context_ptr.is_null() {
        &[] // Empty context if null
    } else {
        unsafe { slice::from_raw_parts(context_ptr, context_len) }
    };
    let proof = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };

    // Call the internal verification function
    match verify_ring_signature_ffi(commitment, message, context, proof) {
        Ok(true) => 1,  // Signature valid
        Ok(false) => 0, // Signature invalid
        Err(_) => -2,   // Error processing inputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kzg_commitment_with_vector() {
        let ring_pks_hex = "7b32d917d5aa771d493c47b0e096886827cd056c82dbdba19e60baa8b2c60313d3b1bdb321123449c6e89d310bc6b7f654315eb471c84778353ce08b951ad471561fdb0dcfb8bd443718b942f82fe717238cbcf8d12b8d22861c8a09a984a3c5a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b4fd11f89c2a1aaefe856bb1c5d4a1fad73f4de5e41804ca2c17ba26d6e10050c86d06ee2c70da6cf2da2a828d8a9d8ef755ad6e580e838359a10accb086ae437ad6fdeda0dde0a57c51d3226b87e3795e6474393772da46101fd597fbd456c1b3f9dc0c4f67f207974123830c2d66988fb3fb44becbbba5a64143f376edc51d9";

        let expected_commitment_hex = "afd34e92148ec643fbb578f0e14a1ca9369d3e96b821fcc811c745c320fe2264172545ca9b6b1d8a196734bc864e171484f45ba5b95d9be39f03214b59520af3137ea80e302730a5df8e4155003414f6dcf0523d15c6ef5089806e1e8e5782be92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf";

        let ring_pks_bytes = hex::decode(ring_pks_hex).expect("Failed to decode hex string");

        assert_eq!(ring_pks_bytes.len(), 256);

        let mut hashes = Vec::new();
        for chunk in ring_pks_bytes.chunks(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            hashes.push(arr);
        }

        let result = kzg_commitment_ffi(&hashes).expect("Failed to compute commitment");

        let expected_bytes =
            hex::decode(expected_commitment_hex).expect("Failed to decode hex string");
        let expected_commitment =
            RingCommitment::deserialize_compressed_unchecked(&mut &expected_bytes[..])
                .expect("Failed to deserialize expected commitment");

        let mut result_bytes = Vec::new();
        result
            .serialize_compressed(&mut result_bytes)
            .expect("Failed to serialize result");

        assert_eq!(expected_commitment, result, "Commitments don't match");
        assert_eq!(
            expected_bytes, result_bytes,
            "Serialized commitment bytes don't match"
        );
    }
}
