// src/extrinsics/guarantees.rs

use crate::types::{Ed25519Signature, Timeslot, ValidatorIndex};
use crate::workreport::WorkReport;

#[derive(Debug, Clone)]
pub struct Credential {
    pub validator_index: ValidatorIndex,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone)]
pub struct Guarantee {
    pub work_report: WorkReport,
    pub timeslot: Timeslot,
    /// In Go this slice is meant to contain only 2 or 3 credentials.
    pub credentials: Vec<Credential>,
}

pub type Guarantees = Vec<Guarantee>;
