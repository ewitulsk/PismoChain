use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};

/// Flexible blockchain enum that can be extended for different blockchain integrations
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Blockchain {
    /// Sui blockchain integration with address and locker box object ID
    Sui {
        /// The Sui address that should own the locker box
        sui_address: String,
        /// The object ID of the LockerBox shared object
        locker_box_address: String,
        /// The checkpoint sequence number to query the object at
        checkpoint: u64,
    },
} 