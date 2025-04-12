use ark_vrf::suites::bandersnatch::{
    AffinePoint, BandersnatchSha512Ell2, PcsParams, RingCommitment, RingProofParams,
};
use ark_vrf::reexports::ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_vrf::reexports::ark_ec::AffineRepr;
use ark_vrf::Suite;
use ark_vrf::{codec, Error, Output};
use std::fs::File;
use std::io::Read;
use std::slice;
use std::io::Write;

// Function to log debug info to a file
fn log_debug(message: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/bandersnatch_debug.log") {
        let _ = writeln!(file, "{}", message);
    }
}

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
    "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
);

pub fn kzg_commitment_ffi(hashes: &[[u8; 32]]) -> Result<RingCommitment, Error> {
    log_debug(&format!("Starting kzg_commitment_ffi with {} hashes", hashes.len()));
    
    // Log the first hash to see what's being passed
    if !hashes.is_empty() {
        let first_hash = hashes[0];
        log_debug(&format!("First hash: {:?}", first_hash));
        let all_zeros = first_hash.iter().all(|&b| b == 0);
        log_debug(&format!("First hash is all zeros: {}", all_zeros));
    }
    
    let mut file = match File::open(PCS_SRS_FILE) {
        Ok(f) => f,
        Err(e) => {
            log_debug(&format!("Failed to open SRS file: {}", e));
            return Err(Error::InvalidData);
        }
    };
    
    let mut buf = Vec::new();
    if let Err(e) = file.read_to_end(&mut buf) {
        log_debug(&format!("Failed to read SRS file: {}", e));
        return Err(Error::InvalidData);
    }
    log_debug(&format!("Read {} bytes from SRS file", buf.len()));

    let pcs_params = match PcsParams::deserialize_uncompressed(&mut &buf[..]) {
        Ok(p) => p,
        Err(e) => {
            log_debug(&format!("Failed to deserialize PCS params: {:?}", e));
            return Err(Error::InvalidData);
        }
    };
    log_debug("Successfully deserialized PCS params");
    
    // Use a ring size we know works for production
    const RING_SIZE: usize = 8;
    log_debug(&format!("Using ring size: {}", RING_SIZE));
    
    let ring_proof_params = match RingProofParams::from_pcs_params(RING_SIZE, pcs_params) {
        Ok(p) => p,
        Err(e) => {
            log_debug(&format!("Failed to create ring proof params: {:?}", e));
            return Err(Error::InvalidData);
        }
    };
    log_debug("Successfully created ring proof params");

    // Convert each hash to a point, but log failures
    let mut ring_pks = Vec::with_capacity(hashes.len());
    for (i, hash) in hashes.iter().enumerate() {
        match BandersnatchSha512Ell2::data_to_point(hash) {
            Some(point) => {
                ring_pks.push(point);
                if i == 0 {
                    log_debug("Successfully converted first hash to point");
                }
            },
            None => {
                log_debug(&format!("Failed to convert hash at index {} to point", i));
                return Err(Error::InvalidData);
            }
        }
    }
    log_debug(&format!("Successfully converted {} hashes to points", ring_pks.len()));

    let verifier_key = ring_proof_params.verifier_key(&ring_pks);
    log_debug("Successfully created verifier key");

    let commitment = verifier_key.commitment();
    log_debug("Successfully created commitment");
    
    Ok(commitment)
}

#[no_mangle]
pub extern "C" fn kzg_commitment(
    hashes_ptr: *const u8,
    num_hashes: usize,
    out_ptr: *mut u8,
) -> i32 {
    log_debug(&format!("kzg_commitment called with {} hashes", num_hashes));
    
    // Check that the input pointers are non-null.
    if hashes_ptr.is_null() || out_ptr.is_null() {
        log_debug("Null pointer error");
        return -1;
    }

    // Calculate the total number of bytes expected for the input.
    let total_bytes = match num_hashes.checked_mul(32) {
        Some(n) => n,
        None => {
            log_debug("Integer overflow in size calculation");
            return -2;
        }
    };
    log_debug(&format!("Total bytes: {}", total_bytes));

    // Create a slice from the raw pointer.
    let hashes_slice = unsafe { slice::from_raw_parts(hashes_ptr, total_bytes) };

    // Convert the slice into a Vec<[u8; 32]>.
    let mut hashes_vec = Vec::with_capacity(num_hashes);
    for (i, chunk) in hashes_slice.chunks(32).enumerate() {
        if chunk.len() != 32 {
            log_debug(&format!("Chunk {} has invalid length: {}", i, chunk.len()));
            return -3;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        
        // Log first and last hash details
        if i == 0 || i == num_hashes - 1 {
            let all_zeros = arr.iter().all(|&b| b == 0);
            log_debug(&format!("Hash {} is all zeros: {}", i, all_zeros));
        }
        
        hashes_vec.push(arr);
    }
    log_debug(&format!("Created Vec with {} hashes", hashes_vec.len()));

    // Compute the ring commitment using your helper function.
    let commitment = match crate::kzg_commitment_ffi(&hashes_vec) {
        Ok(c) => c,
        Err(e) => {
            log_debug(&format!("kzg_commitment_ffi failed with error: {:?}", e));
            return -4;
        }
    };
    log_debug("kzg_commitment_ffi succeeded");

    // Serialize the commitment in compressed form.
    let mut out_bytes = Vec::new();
    if let Err(e) = commitment.serialize_compressed(&mut out_bytes) {
        log_debug(&format!("Failed to serialize commitment: {:?}", e));
        return -5;
    }
    // Verify that the serialized commitment is 144 bytes.
    if out_bytes.len() != 144 {
        log_debug(&format!("Serialized commitment has wrong length: {}", out_bytes.len()));
        return -6;
    }
    log_debug("Successfully serialized commitment");

    // Copy the serialized bytes into the output buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, 144);
    }
    log_debug("Successfully copied commitment to output buffer");
    
    0
}
