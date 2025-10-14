//! Event infrastructure for storing and querying blockchain events
//! 
//! This module provides the core infrastructure for emitting, storing, and querying
//! events from transactions. Events are stored in a separate RocksDB column family
//! with version-based keys for efficient range queries.

use borsh::{BorshSerialize, BorshDeserialize};
use crate::database::rocks_db::{RocksDBStore, CF_EVENTS, CF_TRANSACTIONS};
use crate::pismo_app_jmt::PismoTransaction;

/// Generic event container for any serializable event data
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub struct Event {
    /// The JMT version when this event was emitted
    pub version: u64,
    /// Index of this event within the version (for multiple events per version)
    pub event_index: u32,
    /// Type identifier for the event (e.g., "Transfer", "Mint")
    pub event_type: String,
    /// Borsh-serialized event data
    pub event_data: Vec<u8>,
}

/// Helper to create event key for storage
/// Format: __event__{version:u64_be}_{event_index:u32_be}
fn make_event_key(version: u64, event_index: u32) -> Vec<u8> {
    let mut key = b"__event__".to_vec();
    key.extend_from_slice(&version.to_be_bytes()); // Big-endian for lexicographic ordering
    key.push(b'_');
    key.extend_from_slice(&event_index.to_be_bytes());
    key
}

/// Helper to create transaction key for storage
/// Format: __tx__{version:u64_be}
fn make_transaction_key(version: u64) -> Vec<u8> {
    let mut key = b"__tx__".to_vec();
    key.extend_from_slice(&version.to_be_bytes()); // Big-endian for lexicographic ordering
    key
}

/// Store events for a specific version
pub fn store_events(kv_store: &RocksDBStore, version: u64, events: Vec<(String, Vec<u8>)>) -> anyhow::Result<()> {
    for (event_index, (event_type, event_data)) in events.into_iter().enumerate() {
        let event = Event {
            version,
            event_index: event_index as u32,
            event_type,
            event_data,
        };
        
        let key = make_event_key(version, event_index as u32);
        let value = event.try_to_vec()?;
        kv_store.write_cf(CF_EVENTS, &key, &value)?;
    }
    Ok(())
}

/// Store a transaction for a specific version
pub fn store_transaction(kv_store: &RocksDBStore, version: u64, tx: &PismoTransaction) -> anyhow::Result<()> {
    let key = make_transaction_key(version);
    let value = tx.try_to_vec()?;
    kv_store.write_cf(CF_TRANSACTIONS, &key, &value)?;
    Ok(())
}

/// Get all events in a version range (inclusive)
pub fn get_events_range(kv_store: &RocksDBStore, start_version: u64, end_version: u64) -> anyhow::Result<Vec<Event>> {
    // Create range keys
    let start_key = make_event_key(start_version, 0);
    let end_key = make_event_key(end_version, u32::MAX);
    
    let raw_events = kv_store.scan_range_cf(CF_EVENTS, &start_key, &end_key)?;
    
    let mut events = Vec::new();
    for (_key, value) in raw_events {
        let event = Event::try_from_slice(&value)?;
        events.push(event);
    }
    
    Ok(events)
}

/// Get all transactions in a version range (inclusive)
pub fn get_transactions_range(kv_store: &RocksDBStore, start_version: u64, end_version: u64) -> anyhow::Result<Vec<(u64, PismoTransaction)>> {
    // Create range keys
    let start_key = make_transaction_key(start_version);
    let end_key = make_transaction_key(end_version);
    
    let raw_txs = kv_store.scan_range_cf(CF_TRANSACTIONS, &start_key, &end_key)?;
    
    let mut transactions = Vec::new();
    for (key, value) in raw_txs {
        // Extract version from key
        if key.len() >= 17 { // "__tx__" (6 bytes) + u64 (8 bytes) + some margin
            let version_bytes: [u8; 8] = key[6..14].try_into()?;
            let version = u64::from_be_bytes(version_bytes);
            let tx = PismoTransaction::try_from_slice(&value)?;
            transactions.push((version, tx));
        }
    }
    
    Ok(transactions)
}

