// src/extrinsics/assurances.rs

use crate::bitsequence::BitSequence;
use crate::types::{Ed25519Signature, ValidatorIndex}; // assuming you have a BitSequence type

#[derive(Debug, Clone)]
pub struct Assurance {
    /// Must be equal to the ParentHash field of the header.
    pub parent_hash: [u8; 32],
    pub core_availability_contributions: BitSequence,
    pub validator_index: ValidatorIndex,
    pub signature: Ed25519Signature,
}

pub type Assurances = Vec<Assurance>;
