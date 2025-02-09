// src/extrinsics/mod.rs

pub mod assurances;
pub mod disputes;
pub mod guarantees;
pub mod preimages;
pub mod tickets;

use crate::block::extrinsics::assurances::Assurances;
use crate::block::extrinsics::disputes::Disputes;
use crate::block::extrinsics::guarantees::Guarantees;
use crate::block::extrinsics::preimages::Preimages;
use crate::block::extrinsics::tickets::Tickets;

#[derive(Debug, Clone)]
pub struct Extrinsics {
    pub tickets: Tickets, // Corresponds to 6.29 in your comment.
    pub disputes: Disputes,
    pub preimages: Preimages,
    pub assurances: Assurances,
    pub guarantees: Guarantees,
}
