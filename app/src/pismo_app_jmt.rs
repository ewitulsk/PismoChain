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

use crate::{standards::book_executor::BookExecutor, transactions::Transaction};
use crate::config::Config;
use crate::jmt_state::{get_jmt_root, compute_jmt_updates, get_with_proof, PendingBlockState, LATEST_VERSION_KEY};
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, RootHash, OwnedValue, proof::SparseMerkleProof};

use crate::transactions::book_executor::build_executor_updates;
use crate::execution::execute_transaction;
 

/// Counter-specific transaction operations that can be performed
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub enum PismoOperation {
    /// Process an onramp transaction with VAA verification
    Onramp(String, u64), // vaa string, guardian_set index
    /// Create a new account from an external wallet link
    CreateAccount,
    /// Link a new external wallet to an existing account
    LinkAccount {
        external_wallet: String,
    },
    /// No-operation transaction that only increments the account nonce
    NoOp,
    /// Create a new token
    NewCoin {
        name: String,
        project_uri: String,
        logo_uri: String,
        total_supply: u128,
        max_supply: Option<u128>,
        canonical_chain_id: u64,
    },
    /// Mint tokens to an account's coin store
    Mint {
        coin_addr: [u8; 32],
        account_addr: [u8; 32],
        amount: u128,
    },
    /// Transfer tokens between accounts
    Transfer {
        coin_addr: [u8; 32],
        receiver_addr: [u8; 32],
        amount: u128,
    },
    /// Create a new spot orderbook for a trading pair
    CreateOrderbook {
        buy_asset: String,
        sell_asset: String,
    },
    /// Place a new limit order in an orderbook
    NewLimitOrder {
        orderbook_address: [u8; 32],
        is_buy: bool,
        amount: u128,
        tick_price: u64,
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
    pub start_version: u64,
    /// Final JMT version after applying all transactions in this block
    pub final_version: u64
}

impl BlockPayload {
    pub fn new(transactions: Vec<PismoTransaction>, state_root: RootHash, start_version: u64, final_version: u64) -> Self {
        Self {
            transactions,
            state_root: state_root.into(), // Convert RootHash to [u8; 32]
            start_version,
            final_version
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
    book_executor: BookExecutor, // Orderbook tracking
}

impl PismoAppJMT {
    /// Create a new JMT-enhanced counter app
    pub fn new(tx_queue: Arc<Mutex<Vec<PismoTransaction>>>, config: Config, book_executor: BookExecutor, initial_version: u64) -> Self {
        Self {
            tx_queue,
            config,
            next_version: initial_version,
            book_executor,
        }
    }

    /// Read the latest JMT version from app state
    pub fn read_latest_version<K: KVStore>(block_tree_camera: &hotstuff_rs::block_tree::accessors::public::BlockTreeCamera<K>) -> u64 {
        let snapshot = block_tree_camera.snapshot();
        if let Some(version_bytes) = snapshot.committed_app_state(LATEST_VERSION_KEY) {
            if version_bytes.len() >= 8 {
                // Return stored version + 1 for next version
                return u64::from_le_bytes(version_bytes[..8].try_into().unwrap()) + 1;
            }
        }
        // Default to 1 if not found
        1
    }

    /// Return an `AppStateUpdates` that when applied on an empty app state will produce a good "initial"
    /// app state for a counter app: one containing the counter value 0.
    pub fn initial_app_state() -> AppStateUpdates {
        let mut state = AppStateUpdates::new();
        // Store initial version as 0
        state.insert(LATEST_VERSION_KEY.to_vec(), 0u64.to_le_bytes().to_vec());
        state
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
        let last_version = start_version.saturating_sub(1);
        
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
            let previous_root = get_jmt_root(block_tree, last_version)
                .unwrap_or_else(|| RootHash([0u8; 32]));
            let block_payload = BlockPayload::new(transactions_clone, previous_root, last_version, last_version);
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

        let block_tree = request.block_tree();
        
        // Execute transactions and get new state root using the final version
        let (app_state_updates, state_root, final_version) = self.execute(
            &transactions_clone, 
            &block_tree, 
            start_version
        );
        
        // Advance the next_version counter for future blocks
        self.next_version = final_version + 1; //I REALLY don't like tracking 3 different version types.
        
        // Create enhanced block payload with state root and final version
        let block_payload = BlockPayload::new(transactions_clone, state_root, start_version, final_version);
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
            let block_final_version = block_payload.final_version;
            let block_start_version = block_payload.start_version;

            // Validate all transactions in the block (signature, chain id, nonce)
            for transaction in &block_payload.transactions {
                if !transaction.is_signed() {
                    println!("❌ Transaction validation failed: Transaction not signed");
                    return ValidateBlockResponse::Invalid;
                }
                match transaction.verify_with_state(self.config.chain_id, &initial_block_tree, block_start_version) {
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
            let (app_state_updates, computed_state_root, _final_version) = self.execute(&block_payload.transactions, &initial_block_tree, block_start_version);
            
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
    ) -> (Option<AppStateUpdates>, RootHash, u64) {

        // Create pending state overlay for intra-block transaction visibility
        let mut pending_state = PendingBlockState::new(block_tree, version);

        // Process transactions (business logic)
        for transaction in transactions {
            // Execute the transaction using the execution module (includes verification)
            execute_transaction(transaction, &self.config, block_tree, &mut pending_state, &self.book_executor);
        }

        // Process orderbook execution after all transactions have been processed
        let (executor_writes, executor_mirrors) = build_executor_updates(&self.book_executor, &pending_state, version);
        if !executor_writes.is_empty() {
            pending_state.version += 1; //Count the orderbook executor as a transaction
        }; 
        pending_state.apply_jmt_writes(executor_writes);
        pending_state.apply_mirror_inserts(executor_mirrors);
        
        // Extract accumulated changes from pending state
        let jmt_writes = pending_state.jmt_overlay.into_iter().collect::<Vec<_>>();
        let app_mirror_inserts = pending_state.mirror_overlay.into_iter().collect::<Vec<_>>();

        let new_version = pending_state.version;

        // Use JMT to compute the new state root and AppStateUpdates
        // This follows the correct pattern: read from committed state, compute changes, return updates
        let has_jmt_changes = !jmt_writes.is_empty();
        let (state_root, mut jmt_updates) = if has_jmt_changes {
            match compute_jmt_updates(block_tree, new_version, jmt_writes) {
                Ok((root, updates)) => {
                    println!("🌳 Computed JMT root at version {}: {:?}", new_version, hex::encode(&root.0[..8]));
                    (root, updates)
                }
                Err(e) => {
                    eprintln!("❌ JMT computation failed: {}", e);
                    (RootHash([0u8; 32]), AppStateUpdates::new())
                }
            }
        } else {
            // No state changes, return previous root
            let prev_root = get_jmt_root(block_tree, new_version)
                .unwrap_or_else(|| RootHash([0u8; 32]));
            (prev_root, AppStateUpdates::new())
        };

        // The JMT updates already contain all the internal JMT operations
        let mut has_updates = has_jmt_changes;

        // Apply any app-level mirror inserts
        if !app_mirror_inserts.is_empty() {
            for (k, v) in app_mirror_inserts {
                jmt_updates.insert(k, v);
            }
            has_updates = true;
        }

        let app_state_updates = if has_updates { Some(jmt_updates) } else { None };
        
        (app_state_updates, state_root, new_version)
    }
}