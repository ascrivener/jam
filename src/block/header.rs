use crate::constants;
use crate::types::{
    BandersnatchPublicKey, BandersnatchSignature, Ed25519PublicKey, TicketEntryIndex, Timeslot,
    ValidatorIndex,
};

/// The Header struct corresponds to the Go Header type.
///
/// - Fixed-size arrays such as `[u8; 32]` represent your hash fields.
/// - Pointer fields in Go (which can be nil) are represented as `Option<T>`.
/// - Slices (dynamic arrays) are represented as `Vec<T>`.
#[derive(Debug, Clone)]
pub struct Header {
    pub parent_hash: [u8; 32],
    pub prior_state_root: [u8; 32],
    pub extrinsic_hash: [u8; 32],
    pub time_slot: Timeslot,
    /// In Go, this was a pointer, so we use `Option` here.
    pub epoch_marker: Option<EpochMarker>,
    /// This is an optional pointer to a fixed-size array of Tickets.
    /// We box the array to allocate it on the heap.
    pub winning_tickets_marker: Option<Box<[Ticket; constants::NUM_TIMESLOTS_PER_EPOCH]>>,
    /// A slice of Ed25519PublicKey in Go is represented as a Vec.
    pub offenders_marker: Vec<Ed25519PublicKey>,
    pub bandersnatch_block_author_index: ValidatorIndex,
    pub vrf_signature: BandersnatchSignature,
    pub block_seal: BandersnatchSignature,
}

/// The EpochMarker struct.
#[derive(Debug, Clone)]
pub struct EpochMarker {
    pub current_epoch_randomness: [u8; 32],
    pub next_epoch_randomness: [u8; 32],
    /// In Go, this is a fixed-size array with length constants.NumValidators.
    pub validator_keys: [BandersnatchPublicKey; constants::NUM_VALIDATORS],
}

/// The Ticket struct.
#[derive(Debug, Clone)]
pub struct Ticket {
    pub verifiably_random_identifier: [u8; 32],
    pub entry_index: TicketEntryIndex,
}
