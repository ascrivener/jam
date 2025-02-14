use sha2::{Digest, Sha512};

extern crate ark_ec_vrfs;

/// In your suite, these two functions are defined to convert between 32-byte
/// representations and field elements. Here we give dummy implementations for
/// illustration. In your real code, use the implementations from your codec.
#[derive(Clone, Copy)]
pub struct FieldElement([u8; 32]);

/// Decodes a 32-byte little-endian string into a field element.
fn string_to_int(bytes: &[u8]) -> FieldElement {
    let mut arr = [0u8; 32];
    // Assume bytes has at least 32 bytes.
    arr.copy_from_slice(&bytes[0..32]);
    FieldElement(arr)
}

/// Encodes a field element into its canonical 32-byte little-endian representation.
fn int_to_string(fe: &FieldElement) -> [u8; 32] {
    fe.0
}

/// Computes the final VRF output \( Y(s) \in H \) from the VRF evaluation \( s \)
/// (represented by its encoding \( x \)). The process is as follows:
///
/// 1. Ensure the encoded VRF evaluation (point \( x \)) is at least 32 bytes long.
/// 2. Extract the first 32 bytes and decode them into a field element (using `string_to_int`).
/// 3. Re-encode the field element canonically (using `int_to_string`).
/// 4. Hash the canonical 32-byte representation with SHA-512.
/// 5. Truncate the 64-byte hash to the first 32 bytes.  
///
/// This 32-byte result is the final output \( Y(s) \).
///
/// # Parameters
/// - `bytes_ptr`: pointer to the VRF evaluation encoding \( x \).
/// - `bytes_len`: length of that encoding.
/// - `out_ptr`: pointer to an output buffer (must be at least 32 bytes).
/// - `out_len`: length of the output buffer.
///
/// # Returns
/// - 0 on success,
/// - -1 if the output buffer is too small,
/// - -2 if the input is too short.
#[no_mangle]
pub extern "C" fn vrf_output(
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    // We require that the final output buffer be at least 32 bytes.
    if out_len < 32 {
        return -1; // output buffer too small
    }
    // Safety: the caller must ensure that bytes_ptr is valid for bytes_len bytes.
    let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, bytes_len) };
    if bytes.len() < 32 {
        return -2; // VRF output too short
    }

    // Step 1: Extract the first 32 bytes.
    let encoded_part = &bytes[..32];

    // Step 2: Decode the first 32 bytes into a field element.
    let fe = string_to_int(encoded_part);

    // Step 3: Convert the field element back to its canonical 32-byte representation.
    let canonical_bytes = int_to_string(&fe);

    // Step 4: Hash the canonical representation using SHA-512.
    let hash_digest = Sha512::digest(&canonical_bytes);

    // Step 5: Truncate the SHA-512 digest to 32 bytes.
    let final_output = &hash_digest[..32];

    // Safety: the caller must ensure that out_ptr is valid for out_len bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(final_output.as_ptr(), out_ptr, 32);
    }

    0 // success
}

use ark_ec_vrfs::prelude::ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Validate,
};
use ark_ec_vrfs::suites::bandersnatch::edwards::{
    AffinePoint, BandersnatchSha512Ell2, RingCommitment, RingContext,
};
use ark_ec_vrfs::Error;
use ark_ec_vrfs::Suite;
use std::fs::File;
use std::io::Read;
use std::slice;

pub const PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/zcash-bls12-381-srs-2-11-uncompressed.bin"
);

pub fn compute_kzg_commitment(hashes: &[[u8; 32]]) -> Result<RingCommitment, Error> {
    let mut file = File::open(PCS_SRS_FILE).map_err(|_| Error::InvalidData)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| Error::InvalidData)?;

    let ring_ctx = RingContext::deserialize_with_mode(&mut &buf[..], Compress::No, Validate::Yes)
        .map_err(|_| Error::InvalidData)?;

    let ring_pks: Vec<AffinePoint> = hashes
        .iter()
        .map(|bytes| BandersnatchSha512Ell2::data_to_point(bytes).ok_or(Error::InvalidData))
        .collect::<Result<_, _>>()?;

    let verifier_key = ring_ctx.verifier_key(&ring_pks);

    Ok(verifier_key.commitment())
}

#[no_mangle]
pub extern "C" fn compute_O(hashes_ptr: *const u8, num_hashes: usize, out_ptr: *mut u8) -> i32 {
    // Check that the input pointers are non-null.
    if hashes_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }

    // Calculate the total number of bytes expected for the input.
    let total_bytes = match num_hashes.checked_mul(32) {
        Some(n) => n,
        None => return -2,
    };

    // Create a slice from the raw pointer.
    let hashes_slice = unsafe { slice::from_raw_parts(hashes_ptr, total_bytes) };

    // Convert the slice into a Vec<[u8; 32]>.
    let mut hashes_vec = Vec::with_capacity(num_hashes);
    for chunk in hashes_slice.chunks(32) {
        if chunk.len() != 32 {
            return -3;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        hashes_vec.push(arr);
    }

    // Compute the ring commitment using your helper function.
    // Note: this function is generic; here we specialize to BandersnatchSha512Ell2.
    let commitment = match crate::compute_kzg_commitment(&hashes_vec) {
        Ok(c) => c,
        Err(_) => return -4,
    };

    // Serialize the commitment in compressed form.
    let mut out_bytes = Vec::new();
    if commitment.serialize_compressed(&mut out_bytes).is_err() {
        return -5;
    }
    // Verify that the serialized commitment is 144 bytes.
    if out_bytes.len() != 144 {
        return -6;
    }

    // Copy the serialized bytes into the output buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, 144);
    }
    0
}
