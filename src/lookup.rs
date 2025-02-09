use dashmap::DashMap;
use hex;
use std::fmt;

use crate::types::{ServiceIndex, Timeslot};

/// PreimageKey is a composite key consisting of a service index and a 32-byte hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PreimageKey {
    pub service: ServiceIndex,
    pub hash: [u8; 32],
}

/// Implements Display to provide a string representation of the key.
impl fmt::Display for PreimageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Convert the 32-byte hash to a hexadecimal string.
        write!(f, "{}:{}", self.service, hex::encode(&self.hash))
    }
}

/// PreimageData holds the preimage and its availability information.
/// The availability vector may contain up to 3 Timeslot elements.
#[derive(Clone, Debug)]
pub struct PreimageData {
    pub preimage: Vec<u8>,
    pub availability: Vec<Timeslot>,
}

/// PreimageLookup provides a thread-safe mapping from a composite key to PreimageData.
/// Internally, we use DashMap to allow concurrent access.
#[derive(Debug)]
pub struct PreimageLookup {
    store: DashMap<PreimageKey, PreimageData>,
}

impl PreimageLookup {
    /// Creates a new PreimageLookup instance.
    pub fn new() -> Self {
        PreimageLookup {
            store: DashMap::new(),
        }
    }

    /// Stores the given PreimageData under the specified composite key.
    pub fn set_preimage(&self, key: PreimageKey, data: PreimageData) {
        self.store.insert(key, data);
    }

    /// Retrieves the PreimageData for the specified composite key.
    /// Returns `Some(PreimageData)` if found, or `None` otherwise.
    pub fn get_preimage(&self, key: &PreimageKey) -> Option<PreimageData> {
        self.store.get(key).map(|entry| entry.value().clone())
    }
}
