//! JMT-enhanced PismoApp with authenticated state management
//! 
//! This module provides the main application logic with Jellyfish Merkle Tree
//! integration for verifiable state transitions and inclusion proofs.
//! JMT is built on top of HotStuff's KVStore, not as a separate layer.

use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
    collections::HashMap,
};

use borsh::{BorshDeserialize, BorshSerialize};
use hotstuff_rs::{
    app::{
        App, ProduceBlockRequest, ProduceBlockResponse, ValidateBlockRequest, ValidateBlockResponse,
    },
    block_tree::accessors::app::AppBlockTreeView,
    types::{
        crypto_primitives::{CryptoHasher, Digest},
        data_types::{CryptoHash, Data, Datum},
        update_sets::AppStateUpdates,
    },
};

// No direct use of Sui PublicKey needed for verification path now

use crate::transactions::Transaction;
use crate::transactions::onramp;
use crate::config::Config;
use crate::jmt_state::{make_state_key, make_key_hash_from_parts, get_jmt_root, get_jmt_value, compute_jmt_updates, get_with_proof};
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, RootHash, OwnedValue, proof::SparseMerkleProof};
use crate::standards::accounts::{Chain, AccountAddr};
use crate::transactions::accounts::{build_create_account_updates, build_link_account_updates};
 

/// Counter-specific transaction operations that can be performed
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub enum PismoOperation {
    /// Process an onramp transaction with VAA verification
    Onramp(String, u64), // vaa string, guardian_set index
    /// Create a new account from an external wallet link
    CreateAccount {
        chain: Chain,
        created_at_ms: u64,
    },
    /// Link a new external wallet to an existing account
    LinkAccount {
        account_addr: AccountAddr,
        chain: Chain,
        added_at_ms: u64,
    },
}

/// Type alias for counter transactions
pub type PismoTransaction = Transaction<PismoOperation>;

/// Token information stored for each locked token
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct Token {
    /// The token contract address (e.g., "0x2::sui::SUI")
    pub address: String,
    /// Last unlock checkpoint (0 if never unlocked)
    pub last_unlock: u64,
    /// User's token holdings
    pub amount: u128,
}

/// User information containing their locked tokens across chains
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct User {
    /// Map of token_hash -> Token info
    /// token_hash = hash(token_address + chain_id)
    pub tokens: HashMap<String, Token>,
}

/// Enhanced block payload that includes state root for JMT verification
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub struct BlockPayload {
    /// List of transactions in this block
    pub transactions: Vec<PismoTransaction>,
    /// JMT state root after applying all transactions
    pub state_root: [u8; 32], // Keep as [u8; 32] for serialization compatibility
    /// Final JMT version after applying all transactions in this block
    pub final_version: u64,
}

impl BlockPayload {
    pub fn new(transactions: Vec<PismoTransaction>, state_root: RootHash, final_version: u64) -> Self {
        Self {
            transactions,
            state_root: state_root.into(), // Convert RootHash to [u8; 32]
            final_version,
        }
    }
    
    /// Get the state root as a RootHash
    pub fn state_root(&self) -> RootHash {
        RootHash(self.state_root)
    }

    /// Compute the hash of this block payload
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("Failed to serialize block payload");
        let mut hasher = CryptoHasher::new();
        hasher.update(&serialized);
        hasher.finalize().into()
    }
}

// State key constants for different data types
const COUNTER_ADDR: [u8; 32] = [0u8; 32]; // Global counter address
const COUNTER_TAG: &[u8] = b"counter";

pub struct PismoAppJMT {
    tx_queue: Arc<Mutex<Vec<PismoTransaction>>>,
    config: Config,
    next_version: u64, // JMT version counter - increments with each transaction
}

impl PismoAppJMT {
    /// Create a new JMT-enhanced counter app
    pub fn new(tx_queue: Arc<Mutex<Vec<PismoTransaction>>>, config: Config) -> Self {
        Self {
            tx_queue,
            config,
            next_version: 1, // Start at version 1, initialization handled by HotStuff
        }
    }

    /// Return an `AppStateUpdates` that when applied on an empty app state will produce a good "initial"
    /// app state for a counter app: one containing the counter value 0.
    pub fn initial_app_state() -> AppStateUpdates {
        let mut state = AppStateUpdates::new();
        let counter_key = make_state_key(COUNTER_ADDR, COUNTER_TAG);
        state.insert(counter_key.to_vec(), 0i64.to_le_bytes().to_vec());
        state
    }

    /// Get counter value from the committed HotStuff state (not JMT directly)
    pub fn get_counter_from_committed_state<K: hotstuff_rs::block_tree::pluggables::KVStore>(
        block_tree: &hotstuff_rs::block_tree::accessors::app::AppBlockTreeView<K>,
        version: u64
    ) -> anyhow::Result<i64> {
        let counter_key_hash = make_key_hash_from_parts(COUNTER_ADDR, COUNTER_TAG);
        let counter_bytes = get_jmt_value(block_tree, counter_key_hash, version)?
            .unwrap_or_else(|| 0i64.to_le_bytes().to_vec());
        
        let counter = i64::from_le_bytes(
            counter_bytes.as_slice().try_into()
                .map_err(|_| anyhow::anyhow!("Invalid counter bytes"))?
        );
        Ok(counter)
    }

    /// Get the current state root for a specific version
    pub fn get_state_root<K: hotstuff_rs::block_tree::pluggables::KVStore>(
        block_tree: &hotstuff_rs::block_tree::accessors::app::AppBlockTreeView<K>,
        version: u64
    ) -> Option<RootHash> {
        get_jmt_root(block_tree, version)
    }

    /// Get proof for a key at a specific version
    pub fn get_proof<K: hotstuff_rs::block_tree::pluggables::KVStore>(
        block_tree: &hotstuff_rs::block_tree::accessors::app::AppBlockTreeView<K>,
        key_hash: KeyHash,
        version: u64,
    ) -> anyhow::Result<(Option<OwnedValue>, SparseMerkleProof<sha2::Sha256>)> {
        get_with_proof(block_tree, key_hash, version)
    }
}

impl<K: KVStore> App<K> for PismoAppJMT {
    fn produce_block(&mut self, request: ProduceBlockRequest<K>) -> ProduceBlockResponse {
        // Reduced sleep time for faster consensus
        thread::sleep(Duration::from_millis(100));

        // Cache the starting version before we dequeue transactions
        let start_version = self.next_version;
        
        let transactions_clone = {
            let mut tx_queue = self.tx_queue.lock().unwrap();
            // Clone transactions to avoid borrowing conflicts
            let transactions_clone = tx_queue.clone();
            tx_queue.clear();
            transactions_clone
        };
        
        // If no transactions, return early with no state changes
        if transactions_clone.is_empty() {
            let block_tree = request.block_tree();
            let previous_root = get_jmt_root(block_tree, start_version.saturating_sub(1))
                .unwrap_or_else(|| RootHash([0u8; 32]));
            let block_payload = BlockPayload::new(transactions_clone, previous_root, start_version.saturating_sub(1));
            let serialized_payload = block_payload.try_to_vec().unwrap();
            
            let data = Data::new(vec![Datum::new(serialized_payload)]);
            let data_hash = {
                let mut hasher = CryptoHasher::new();
                hasher.update(&data.vec()[0].bytes());
                let bytes = hasher.finalize().into();
                CryptoHash::new(bytes)
            };

            return ProduceBlockResponse {
                data_hash,
                data,
                app_state_updates: None,
                validator_set_updates: None,
            };
        }
        
        // Calculate the final version - this will be the version of the last transaction
        let final_version = start_version + transactions_clone.len() as u64 - 1;
        let block_tree = request.block_tree();
        
        // Execute transactions and get new state root using the final version
        let (app_state_updates, state_root) = self.execute(
            &transactions_clone, 
            &block_tree, 
            final_version
        );
        
        // Advance the next_version counter for future blocks
        self.next_version = final_version + 1;
        
        // Create enhanced block payload with state root and final version
        let block_payload = BlockPayload::new(transactions_clone, state_root, final_version);
        let serialized_payload = block_payload.try_to_vec().unwrap();
        
        let data = Data::new(vec![Datum::new(serialized_payload)]);
        let data_hash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        ProduceBlockResponse {
            data_hash,
            data,
            app_state_updates,
            validator_set_updates: None,
        }
    }

    fn validate_block(&mut self, request: ValidateBlockRequest<K>) -> ValidateBlockResponse {
        // Reduced sleep time for faster consensus
        thread::sleep(Duration::from_millis(10));

        self.validate_block_for_sync(request)
    }

    fn validate_block_for_sync(
        &mut self,
        request: ValidateBlockRequest<K>,
    ) -> ValidateBlockResponse {
        let data = &request.proposed_block().data;
        let data_hash: CryptoHash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        if request.proposed_block().data_hash != data_hash {
            return ValidateBlockResponse::Invalid;
        }

        let initial_block_tree = request.block_tree();

        // Deserialize the enhanced block payload
        if let Ok(block_payload) = BlockPayload::deserialize(
            &mut &*request.proposed_block().data.vec()[0].bytes().as_slice(),
        ) {
            // Use the actual final version from the block payload
            let block_version = block_payload.final_version;

            // Validate all transactions in the block (signature, chain id, nonce)
            for transaction in &block_payload.transactions {
                if !transaction.is_signed() {
                    println!("❌ Transaction validation failed: Transaction not signed");
                    return ValidateBlockResponse::Invalid;
                }
                match transaction.verify_with_state(self.config.chain_id, &initial_block_tree, block_version) {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("❌ Transaction validation failed: signature/chain/nonce check failed for public_key {}", transaction.public_key);
                        return ValidateBlockResponse::Invalid;
                    }
                    Err(e) => {
                        println!("❌ Transaction validation failed: Verification error: {}", e);
                        return ValidateBlockResponse::Invalid;
                    }
                }
            }

            // Execute transactions with JMT and verify state root
            let (app_state_updates, computed_state_root) = self.execute(&block_payload.transactions, &initial_block_tree, block_version);
            
            // Verify that the computed state root matches the proposed one
            let expected_state_root = block_payload.state_root();
            if computed_state_root != expected_state_root {
                println!("❌ Block validation failed: State root mismatch");
                println!("   Expected: {:?}", expected_state_root);
                println!("   Computed: {:?}", computed_state_root);
                return ValidateBlockResponse::Invalid;
            }

            println!("✅ Block validated successfully with state root: {:?}", computed_state_root);
            ValidateBlockResponse::Valid {
                app_state_updates,
                validator_set_updates: None,
            }
        } else {
            println!("❌ Block validation failed: Could not deserialize block payload");
            ValidateBlockResponse::Invalid
        }
    }
}

impl PismoAppJMT {
    /// Execute transactions using JMT read-only view, return AppStateUpdates
    /// This follows the proper pattern: no persistence, only AppStateUpdates construction
    fn execute<K: KVStore>(
        &self,
        transactions: &[PismoTransaction],
        block_tree: &AppBlockTreeView<'_, K>,
        version: u64,
    ) -> (Option<AppStateUpdates>, RootHash) {
        let user_modifications_in_block: HashMap<String, User> = HashMap::new();
        let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
        let mut app_mirror_inserts: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        // Process transactions (business logic)
        for transaction in transactions {
            // Chain id + signature + nonce checks using stateful verifier
            match transaction.verify_with_state(self.config.chain_id, block_tree, version) {
                Ok(true) => {}
                Ok(false) => {
                    println!("❌ Tx rejected by verification (chain_id/signature/nonce)");
                    continue;
                }
                Err(e) => {
                    println!("❌ Tx verification error: {}", e);
                    continue;
                }
            }

            let signing_pub_key = transaction.public_key.clone();

            match &transaction.payload {
                // Remove counter-only transactions per new requirements
                PismoOperation::Onramp(vaa, guardian_set_index) => {
                    // Verify VAA and extract onramp message
                    match onramp::verify_vaa_and_extract_message(vaa, *guardian_set_index) {
                        Ok(onramp_message) => {
                            println!("🚀 Successfully processed Onramp transaction!");
                            println!("OnrampMessage: {:#?}", onramp_message);
                            
                            // TODO: Update user balances based on onramp_message
                            // For now, we'll just log the success
                        }
                        Err(e) => {
                            println!("❌ Failed to process Onramp transaction: {}", e);
                            // For now, we continue processing other transactions
                            // In a real system, you might want to reject the entire block
                        }
                    }
                }
                PismoOperation::CreateAccount { chain, created_at_ms } => {
                    let (writes, mirrors) = build_create_account_updates(*chain, signing_pub_key.clone(), *created_at_ms, block_tree, version);
                    jmt_writes.extend(writes);
                    app_mirror_inserts.extend(mirrors);
                }
                PismoOperation::LinkAccount { account_addr, chain, added_at_ms } => {
                    let (writes, mirrors) = build_link_account_updates(*account_addr, *chain, signing_pub_key.clone(), *added_at_ms, block_tree, version);
                    jmt_writes.extend(writes);
                    app_mirror_inserts.extend(mirrors);
                }
            }
        }

        // Prepare JMT writes using proper KeyHash and OwnedValue types
        // No-op for counter state now

        // Use JMT to compute the new state root and AppStateUpdates
        // This follows the correct pattern: read from committed state, compute changes, return updates
        let has_jmt_changes = !jmt_writes.is_empty();
        let (state_root, mut jmt_updates) = if has_jmt_changes {
            match compute_jmt_updates(block_tree, version, jmt_writes) {
                Ok((root, updates)) => {
                    println!("🌳 Computed JMT root at version {}: {:?}", version, hex::encode(&root.0[..8]));
                    (root, updates)
                }
                Err(e) => {
                    eprintln!("❌ JMT computation failed: {}", e);
                    (RootHash([0u8; 32]), AppStateUpdates::new())
                }
            }
        } else {
            // No state changes, return previous root
            let prev_root = get_jmt_root(block_tree, version)
                .unwrap_or_else(|| RootHash([0u8; 32]));
            (prev_root, AppStateUpdates::new())
        };

        // The JMT updates already contain all the internal JMT operations
        let mut has_updates = has_jmt_changes;

        // Also add the application-level counter state for HotStuff compatibility
        // No-op mirror for counter now

        // Write user modifications to AppStateUpdates as well
        for (sui_address, updated_user) in user_modifications_in_block {
            let sui_address_as_bytes = sui_address.as_bytes();
            let serialized_user = updated_user.try_to_vec().unwrap();
            jmt_updates.insert(sui_address_as_bytes.to_vec(), serialized_user);
            has_updates = true;
        }

        // Apply any app-level mirror inserts
        if !app_mirror_inserts.is_empty() {
            for (k, v) in app_mirror_inserts {
                jmt_updates.insert(k, v);
            }
            has_updates = true;
        }

        let app_state_updates = if has_updates { Some(jmt_updates) } else { None };
        
        (app_state_updates, state_root)
    }
}