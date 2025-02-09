// src/extrinsics/tickets.rs

use crate::types::{BandersnatchRingVRFProof, TicketEntryIndex};

#[derive(Debug, Clone)]
pub struct Ticket {
    pub entry_index: TicketEntryIndex,
    pub validity_proof: BandersnatchRingVRFProof,
}

pub type Tickets = Vec<Ticket>;
