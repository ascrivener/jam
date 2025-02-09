use sha2::{Digest, Sha512};

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
/// - `vrf_output_ptr`: pointer to the VRF evaluation encoding \( x \).
/// - `vrf_output_len`: length of that encoding.
/// - `out_ptr`: pointer to an output buffer (must be at least 32 bytes).
/// - `out_len`: length of the output buffer.
///
/// # Returns
/// - 0 on success,
/// - -1 if the output buffer is too small,
/// - -2 if the input is too short.
#[no_mangle]
pub extern "C" fn compute_y(
    vrf_output_ptr: *const u8,
    vrf_output_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    // We require that the final output buffer be at least 32 bytes.
    if out_len < 32 {
        return -1; // output buffer too small
    }
    // Safety: the caller must ensure that vrf_output_ptr is valid for vrf_output_len bytes.
    let vrf_output = unsafe { std::slice::from_raw_parts(vrf_output_ptr, vrf_output_len) };
    if vrf_output.len() < 32 {
        return -2; // VRF output too short
    }

    // Step 1: Extract the first 32 bytes.
    let encoded_part = &vrf_output[..32];

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
