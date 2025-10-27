//! Event infrastructure for storing and querying blockchain events
//! 
//! This module provides the core infrastructure for emitting, storing, and querying
//! events from transactions. Events are stored in a separate RocksDB column family
//! with version-based keys for efficient range queries.

use borsh::{BorshSerialize, BorshDeserialize};
use crate::database::rocks_db::{RocksDBStore, CF_EVENTS, CF_TRANSACTIONS};
use crate::pismo_app_jmt::PismoTransaction;
use hotstuff_rs::block_tree::pluggables::KVGet;

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

/// Represents a batch of events that were committed in a block
/// Used for distributing newly committed events to event stream subscribers
#[derive(Clone, Debug)]
pub struct CommittedEvents {
    /// The version at which these events were committed
    pub version: u64,
    /// The events that were committed
    pub events: Vec<Event>,
}

/// Transfer event emitted for mint and transfer operations
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TransferEvent {
    pub from_coinstore: [u8; 32],
    pub to_coinstore: [u8; 32],
    pub coin_address: [u8; 32],
    pub amount: u128,
}

/// Offramp event emitted when tokens are burned for bridge withdrawal
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, serde::Serialize)]
pub struct OfframpEvent {
    pub amount: u64,
    pub coin_address: [u8; 32],
    pub recipient_address: [u8; 32],
    pub destination_chain: u16,
}

/// Response containing an offramp event with its cryptographic inclusion proof
/// This allows external chains to verify that the offramp transaction occurred
#[derive(Clone, Debug, serde::Serialize)]
pub struct OfframpProofResponse {
    /// The offramp event data
    pub event: OfframpEvent,
    /// The JMT version when this event was committed
    pub version: u64,
    /// Index of this event within the version
    pub event_index: u32,
    /// JMT sparse merkle proof for inclusion verification
    #[serde(serialize_with = "serialize_proof")]
    pub proof: jmt::proof::SparseMerkleProof<sha2::Sha256>,
    /// The state root at this version
    pub state_root: [u8; 32],
}

/// Custom serializer for SparseMerkleProof to convert to hex-encoded JSON
fn serialize_proof<S>(proof: &jmt::proof::SparseMerkleProof<sha2::Sha256>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // Serialize the proof as bytes then hex encode it
    let proof_bytes = bincode::serialize(proof).map_err(serde::ser::Error::custom)?;
    let hex_string = hex::encode(proof_bytes);
    serializer.serialize_str(&hex_string)
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
    if events.is_empty() {
        return Ok(());
    }
    
    for (event_index, (event_type, event_data)) in events.into_iter().enumerate() {
        let event = Event {
            version,
            event_index: event_index as u32,
            event_type: event_type.clone(),
            event_data: event_data.clone(),
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
    for (_key, value) in raw_txs {
        // Extract version from key
        if _key.len() >= 17 { // "__tx__" (6 bytes) + u64 (8 bytes) + some margin
            let version_bytes: [u8; 8] = _key[6..14].try_into()?;
            let version = u64::from_be_bytes(version_bytes);
            let tx = PismoTransaction::try_from_slice(&value)?;
            transactions.push((version, tx));
        }
    }
    
    Ok(transactions)
}

/// Get an offramp event with its cryptographic inclusion proof
/// This allows external chains to verify that the offramp transaction occurred
pub fn get_offramp_proof(
    kv_store: &RocksDBStore,
    version: u64,
    event_index: u32,
) -> anyhow::Result<OfframpProofResponse> {
    use crate::jmt_state::{DirectJMTReader, make_offramp_event_key_hash};
    use jmt::JellyfishMerkleTree;
    
    // Step 1: Verify the event exists and is an offramp event
    let event_key = make_event_key(version, event_index);
    let event_bytes = kv_store
        .get_cf(CF_EVENTS, &event_key)
        .ok_or_else(|| anyhow::anyhow!("Event not found at version {} index {}", version, event_index))?;
    
    let event = Event::try_from_slice(&event_bytes)?;
    
    // Verify it's an offramp event
    if event.event_type != "Offramp" {
        return Err(anyhow::anyhow!("Event at version {} index {} is not an offramp event (type: {})", 
            version, event_index, event.event_type));
    }
    
    // Deserialize the offramp event data
    let offramp_event = OfframpEvent::try_from_slice(&event.event_data)?;
    
    // Step 2: Get the JMT state root for this version
    let state_root = get_jmt_root_from_kv(kv_store, version)?
        .ok_or_else(|| anyhow::anyhow!("State root not found for version {}", version))?;
    
    // Step 3: Generate the JMT inclusion proof
    let key_hash = make_offramp_event_key_hash(version, event_index);
    let reader = DirectJMTReader::new(kv_store);
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    
    let (_value, proof) = tree.get_with_proof(key_hash, version)?;
    
    Ok(OfframpProofResponse {
        event: offramp_event,
        version,
        event_index,
        proof,
        state_root: state_root.0,
    })
}

/// Helper to get JMT root from KVStore (for RPC queries)
fn get_jmt_root_from_kv(kv_store: &RocksDBStore, version: u64) -> anyhow::Result<Option<jmt::RootHash>> {
    use crate::jmt_state::COMMITTED_APP_STATE;
    
    let mut root_key = Vec::new();
    root_key.push(COMMITTED_APP_STATE);
    root_key.extend_from_slice(b"__jmt_root__");
    root_key.extend_from_slice(&version.to_le_bytes());
    
    if let Some(bytes) = kv_store.get(&root_key) {
        if bytes.len() >= 32 {
            let mut root = [0u8; 32];
            root.copy_from_slice(&bytes[..32]);
            Ok(Some(jmt::RootHash(root)))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

