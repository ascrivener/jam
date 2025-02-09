// src/types.rs

use crate::constants;

/// A 32-byte Ed25519 public key.
pub type Ed25519PublicKey = [u8; 32];

/// A 32-byte Bandersnatch public key.
pub type BandersnatchPublicKey = [u8; 32];

/// A 64-byte Bandersnatch signature.
pub type BandersnatchSignature = [u8; 64];

/// A 784-byte Bandersnatch ring VRF proof.
pub type BandersnatchRingVRFProof = [u8; 784];

/// A 144-byte Bandersnatch ring root.
pub type BandersnatchRingRoot = [u8; 144];

/// A 64-byte Ed25519 signature.
pub type Ed25519Signature = [u8; 64];

/// A timeslot, represented as a 32-bit unsigned integer.
pub type Timeslot = u32;

/// ValidatorIndex wraps a `u16` and checks that the value is less than constants::NUM_VALIDATORS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorIndex(u16);

impl ValidatorIndex {
    pub fn new(value: u16) -> Result<Self, String> {
        if (value as u32) < constants::NUM_VALIDATORS {
            Ok(ValidatorIndex(value))
        } else {
            Err(format!(
                "invalid validator index value: must be less than {}",
                constants::NUM_VALIDATORS
            ))
        }
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// TicketEntryIndex wraps a `u8` and checks that the value is less than NUM_TICKET_ENTRIES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketEntryIndex(u8);

impl TicketEntryIndex {
    pub fn new(value: u8) -> Result<Self, String> {
        if (value as u32) < constants::NUM_TICKET_ENTRIES {
            Ok(TicketEntryIndex(value))
        } else {
            Err(format!(
                "invalid ticket entry index value: must be less than {}",
                constants::NUM_TICKET_ENTRIES
            ))
        }
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

/// BlobLength is defined as a 32-bit unsigned integer.
pub type BlobLength = u32;

/// CoreIndex wraps a `u16` and checks that the value is less than NUM_CORES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreIndex(u16);

impl CoreIndex {
    pub fn new(value: u16) -> Result<Self, String> {
        if (value as u32) < constants::NUM_CORES {
            Ok(CoreIndex(value))
        } else {
            Err(format!(
                "invalid core index value: must be less than {}",
                constants::NUM_CORES
            ))
        }
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// ServiceIndex is defined as a 32-bit unsigned integer.
pub type ServiceIndex = u32;

/// GasValue is defined as a 64-bit signed integer.
pub type GasValue = i64;

/// ValidatorKeyset is a 336-byte array.
pub type ValidatorKeyset = [u8; 336];

/// Balance is defined as a 64-bit unsigned integer.
pub type Balance = u64;
