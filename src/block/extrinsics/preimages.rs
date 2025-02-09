// src/extrinsics/preimages.rs

#[derive(Debug, Clone)]
pub struct Preimage {
    /// In your Go code, ServiceIndex is a uint64.
    /// You can either use u64 here or a types alias (if you choose to change types::ServiceIndex).
    pub service_index: u64,
    pub data: Vec<u8>,
}

pub type Preimages = Vec<Preimage>;
