use ark_ec_vrfs::prelude::ark_ec::AffineRepr;
use ark_ec_vrfs::prelude::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ec_vrfs::suites::bandersnatch::edwards::{
    AffinePoint, BandersnatchSha512Ell2, PcsParams, RingCommitment, RingContext,
};
use ark_ec_vrfs::Suite;
use ark_ec_vrfs::{codec, Error, Output};
use std::fs::File;
use std::io::Read;
use std::slice;

// https://datatracker.ietf.org/doc/rfc9381/ 5.2 and 5.4.4 and 5.5
pub fn vrf_output_ffi<S: Suite>(hash: &[u8; 784]) -> Result<[u8; 32], Error> {
    // Decode the first 32 bytes into an affine point.
    let gamma = codec::point_decode::<S>(&hash[..32]).map_err(|_| Error::InvalidData)?;
    // Multiply by the cofactor and wrap the result in an Output.
    let output = Output::<S>::from(gamma.mul_by_cofactor());
    // Hash the output and truncate the result to 32 bytes.
    let truncated: [u8; 32] = output.hash().as_slice()[..32]
        .try_into()
        .map_err(|_| Error::InvalidData)?;
    Ok(truncated)
}

#[no_mangle]
pub extern "C" fn bandersnatch_ring_vrf_proof_output(
    input_ptr: *const u8,
    out_ptr: *mut u8,
) -> i32 {
    // Check that the pointers are non-null.
    if input_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    // Safety: caller must guarantee that input_ptr is valid for 784 bytes.
    let input_slice = unsafe { slice::from_raw_parts(input_ptr, 784) };
    // Try to convert the slice to a fixed-size array.
    let input_array: &[u8; 784] = match input_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return -2,
    };

    match vrf_output_ffi::<BandersnatchSha512Ell2>(input_array) {
        Ok(result_array) => {
            // Safety: caller must guarantee that out_ptr is valid for 32 bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(result_array.as_ptr(), out_ptr, 32);
            }
            0
        }
        Err(_) => -3,
    }
}

pub const PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/zcash-bls12-381-srs-2-11-uncompressed.bin"
);

pub fn kzg_commitment_ffi(hashes: &[[u8; 32]]) -> Result<RingCommitment, Error> {
    let mut file = File::open(PCS_SRS_FILE).map_err(|_| Error::InvalidData)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| Error::InvalidData)?;

    let pcs_params =
        <PcsParams as CanonicalDeserialize>::deserialize_uncompressed(&mut &buf[..]).unwrap();
    const RING_SIZE: usize = 2048;
    let ring_ctx = RingContext::from_srs(RING_SIZE, pcs_params).map_err(|_| Error::InvalidData)?;

    let ring_pks: Vec<AffinePoint> = hashes
        .iter()
        .map(|bytes| BandersnatchSha512Ell2::data_to_point(bytes).ok_or(Error::InvalidData))
        .collect::<Result<_, _>>()?;

    let verifier_key = ring_ctx.verifier_key(&ring_pks);

    Ok(verifier_key.commitment())
}

#[no_mangle]
pub extern "C" fn kzg_commitment(
    hashes_ptr: *const u8,
    num_hashes: usize,
    out_ptr: *mut u8,
) -> i32 {
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
    let commitment = match crate::kzg_commitment_ffi(&hashes_vec) {
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
