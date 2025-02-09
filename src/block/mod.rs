// src/block/mod.rs

// Declare the submodules.
pub mod extrinsics;
pub mod header;

// Bring the types into scope for convenience.
use crate::block::extrinsics::Extrinsics;
use crate::block::header::Header;

/// The Block struct combines a header and extrinsics.
/// This mirrors your Go Block type.
#[derive(Debug, Clone)]
pub struct Block {
    pub header: Header,
    pub extrinsics: Extrinsics,
}
