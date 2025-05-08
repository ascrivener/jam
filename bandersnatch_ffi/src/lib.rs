use ark_vrf::ietf::IetfSuite;
use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{
    BandersnatchSha512Ell2, PcsParams, RingCommitment, RingProofParams,
};
use ark_vrf::Suite;
use ark_vrf::{codec, Error};
use std::fs::File;
use std::io::Read;
use std::slice;

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

pub const PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
);

pub fn kzg_commitment_ffi(hashes: &[[u8; 32]]) -> Result<RingCommitment, Error> {
    let mut file = match File::open(PCS_SRS_FILE) {
        Ok(f) => f,
        Err(_) => {
            return Err(Error::InvalidData);
        }
    };

    let mut buf = Vec::new();
    if let Err(_) = file.read_to_end(&mut buf) {
        return Err(Error::InvalidData);
    }

    let pcs_params = match PcsParams::deserialize_uncompressed(&mut &buf[..]) {
        Ok(p) => p,
        Err(_) => {
            return Err(Error::InvalidData);
        }
    };

    let ring_size: usize = hashes.len();

    let ring_proof_params = match RingProofParams::from_pcs_params(ring_size, pcs_params) {
        Ok(p) => p,
        Err(_) => {
            return Err(Error::InvalidData);
        }
    };

    let mut ring_pks = Vec::with_capacity(hashes.len());
    for (_i, hash) in hashes.iter().enumerate() {
        match codec::point_decode::<BandersnatchSha512Ell2>(&hash[..]) {
            Ok(point) => {
                ring_pks.push(point);
            }
            Err(_) => {
                return Err(Error::InvalidData);
            }
        }
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
        let expected_commitment = RingCommitment::deserialize_compressed(&mut &expected_bytes[..])
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
