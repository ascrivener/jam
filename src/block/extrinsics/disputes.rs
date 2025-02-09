// src/extrinsics/disputes.rs

use crate::constants;
use crate::types::{Ed25519PublicKey, Ed25519Signature, ValidatorIndex};

#[derive(Debug, Clone)]
pub struct Judgement {
    pub valid: bool,
    pub validator_index: ValidatorIndex,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub work_report_hash: [u8; 32],
    pub epoch_index: u64, // Note: In your comment, you mention this must be an epoch index of the prior state.
    // We assume that constants::NUM_VALIDATOR_SAFETY_THRESHOLD is defined as a usize.
    pub judgements: [Judgement; constants::NUM_VALIDATOR_SAFETY_THRESHOLD],
}

#[derive(Debug, Clone)]
pub struct Culprit {
    pub invalid_work_report_hash: [u8; 32],
    pub validator_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone)]
pub struct Fault {
    pub work_report_hash: [u8; 32],
    pub incorrect_validity: bool,
    pub validator_key: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone)]
pub struct Disputes {
    pub verdicts: Vec<Verdict>,
    pub culprits: Vec<Culprit>,
    pub faults: Vec<Fault>,
}
