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

// use ark_ec_vrfs::suites::bandersnatch::weierstrass::BandersnatchSha512Tai;
// use ark_ec_vrfs::ring::RingContext;
// use ark_ec_vrfs::prelude::ark_std::rand::SeedableRng;
// use ark_ec_vrfs::prelude::ark_std::rand::rngs::StdRng;
// use ark_ec_vrfs::codec;
// use core::slice;
// #[no_mangle]
// pub extern "C" fn compute_O(
//     pks_ptr: *const u8,
//     count: usize,
//     out_ptr: *mut u8,
//     out_len: usize,
// ) -> i32 {
//     // Define the expected size of the serialized commitment.
//     const COMMITMENT_SIZE: usize = 144;
//     // Define the size of each public key.
//     const PK_SIZE: usize = 32;

//     // Check if the output buffer is large enough.
//     if out_len < COMMITMENT_SIZE {
//         return -1; // Output buffer too small.
//     }

//     // Calculate the total number of bytes expected for the public keys.
//     let total_bytes = match count.checked_mul(PK_SIZE) {
//         Some(size) if size > 0 => size,
//         _ => return -2, // Invalid count or no keys provided.
//     };

//     // Create a slice from the provided pointer.
//     let input_slice = unsafe { slice::from_raw_parts(pks_ptr, total_bytes) };

//     // Deserialize each 32-byte block into an AffinePoint.
//     let mut pks = Vec::with_capacity(count);
//     for chunk in input_slice.chunks_exact(PK_SIZE) {
//         match codec::point_decode::<BandersnatchSha512Tai>(chunk) {
//             Ok(pk) => pks.push(pk),
//             Err(_) => return -3, // Deserialization error.
//         };
//     }

//     // Ensure that the number of deserialized public keys matches the count.
//     if pks.len() != count {
//         return -4; // Mismatch between count and actual number of public keys.
//     }

//     // Initialize a random number generator.
//     let mut rng = StdRng::from_seed([0u8; 32]);
//     let ring_ctx = RingContext::<BandersnatchSha512Tai>::from_rand(pks.len(), &mut rng);

//     // Compute the verifier key, which internally computes the commitment O.
//     let vk = ring_ctx.verifier_key(&pks);
//     let commitment = vk.commitment();

//     // Serialize the commitment to compressed form.
//     let serialized = codec::point_encode::<BandersnatchSha512Tai>(&commitment);
//     if serialized.len() > out_len {
//         return -5; // Serialized length exceeds provided buffer.
//     }

//     // Copy the serialized commitment to the output buffer.
//     unsafe {
//         core::ptr::copy_nonoverlapping(serialized.as_ptr(), out_ptr, serialized.len());
//     }

//     0 // Success.
// }
