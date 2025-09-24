//! Fullnode application implementation
//! 
//! This provides a minimal App implementation for fullnodes that validates blocks
//! without participating in consensus.

use std::{
    thread,
    time::Duration,
};

use borsh::BorshDeserialize;
use sha2::{Digest, Sha256};
use hotstuff_rs::{
    app::{App, ProduceBlockRequest, ProduceBlockResponse, ValidateBlockRequest, ValidateBlockResponse},
    block_tree::accessors::app::AppBlockTreeView,
    block_tree::pluggables::KVStore,
    types::{
        data_types::{CryptoHash, Data},
        update_sets::AppStateUpdates,
    },
};

use crate::{
    config::Config,
    pismo_app_jmt::{BlockPayload, PismoTransaction},
    jmt_state::{get_latest_jmt_root_before, compute_jmt_updates, PendingBlockState, LATEST_VERSION_KEY},
    standards::book_executor::BookExecutor,
    execution::execute_transaction,
    transactions::book_executor::build_executor_updates,
};
use jmt::RootHash;

/// Fullnode application that validates blocks without consensus participation
pub struct FullnodeApp {
    config: Config,
    next_version: u64, // JMT version counter
    book_executor: BookExecutor, // Orderbook tracking
}

impl FullnodeApp {
    /// Create a new fullnode app
    pub fn new(config: Config, book_executor: BookExecutor, initial_version: u64) -> Self {
        Self {
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

    /// Return initial app state for fullnode
    pub fn initial_app_state() -> AppStateUpdates {
        let mut state = AppStateUpdates::new();
        // Store initial version as 0
        state.insert(LATEST_VERSION_KEY.to_vec(), 0u64.to_le_bytes().to_vec());
        state
    }

    /// Safely compute hash for block data, handling empty blocks
    fn compute_block_data_hash(data: &Data) -> CryptoHash {
        let mut hasher = Sha256::new();
        
        if data.vec().is_empty() {
            // Hash empty data consistently
            hasher.update(b"EMPTY_BLOCK");
        } else {
            // Hash the first datum as before
            hasher.update(&data.vec()[0].bytes());
        }
        
        let result = hasher.finalize();
        CryptoHash::new(result.into())
    }

    /// Execute transactions using JMT read-only view, return AppStateUpdates
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
        let has_jmt_changes = !jmt_writes.is_empty();
        let (state_root, mut jmt_updates) = if has_jmt_changes {
            match compute_jmt_updates(block_tree, new_version, jmt_writes) {
                Ok((root, updates)) => {
                    println!("🌳 Fullnode computed JMT root at version {}: {:?}", new_version, hex::encode(&root.0[..8]));
                    (root, updates)
                }
                Err(e) => {
                    eprintln!("❌ Fullnode JMT computation failed: {}", e);
                    (RootHash([0u8; 32]), AppStateUpdates::new())
                }
            }
        } else {
            // No state changes, return previous root
            let prev_version = new_version.saturating_sub(1);
            let prev_root = get_latest_jmt_root_before(block_tree, prev_version)
                .unwrap_or_else(|| RootHash([0u8; 32]));
            println!("📋 Fullnode: No JMT changes, using latest root at/before version {}: {:?}", prev_version, hex::encode(&prev_root.0[..8]));
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

impl<K: KVStore> App<K> for FullnodeApp {
    fn produce_block(&mut self, _request: ProduceBlockRequest<K>) -> ProduceBlockResponse {
        // Fullnodes never produce blocks
        panic!("Fullnodes should never be asked to produce blocks");
    }

    fn validate_block(&mut self, request: ValidateBlockRequest<K>) -> ValidateBlockResponse {
        // Reduced sleep time for faster validation
        thread::sleep(Duration::from_millis(10));

        self.validate_block_for_sync(request)
    }

    fn validate_block_for_sync(
        &mut self,
        request: ValidateBlockRequest<K>,
    ) -> ValidateBlockResponse {
        let data = &request.proposed_block().data;
        
        // Compute data hash (handles empty blocks safely)
        let data_hash = Self::compute_block_data_hash(data);

        if request.proposed_block().data_hash != data_hash {
            println!("❌ Fullnode: Block validation failed - data hash mismatch");
            return ValidateBlockResponse::Invalid;
        }

        let initial_block_tree = request.block_tree();

        // Handle empty blocks during sync
        if data.vec().is_empty() {
            println!("🔍 Fullnode: Validating empty sync block with consistent hash");
            
            return ValidateBlockResponse::Valid {
                app_state_updates: None,
                validator_set_updates: None,
            };
        }

        // Deserialize the enhanced block payload
        if let Ok(block_payload) = BlockPayload::deserialize(
            &mut &*request.proposed_block().data.vec()[0].bytes().as_slice(),
        ) {
            let block_final_version = block_payload.final_version;
            let block_start_version = block_payload.start_version;
            
            println!("🔍 Fullnode: Validating block: start_version={}, final_version={}, tx_count={}", 
                block_start_version, block_final_version, block_payload.transactions.len());

            // Validate all transactions in the block
            for transaction in &block_payload.transactions {
                if !transaction.is_signed() {
                    println!("❌ Fullnode: Transaction validation failed - not signed");
                    return ValidateBlockResponse::Invalid;
                }
                match transaction.verify_with_state(self.config.chain_id, &initial_block_tree, block_start_version) {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("❌ Fullnode: Transaction validation failed for public_key {}", transaction.public_key);
                        return ValidateBlockResponse::Invalid;
                    }
                    Err(e) => {
                        println!("❌ Fullnode: Transaction verification error: {}", e);
                        return ValidateBlockResponse::Invalid;
                    }
                }
            }

            // Special handling for empty blocks
            if block_payload.transactions.is_empty() {
                let expected_state_root = block_payload.state_root();
                println!("✅ Fullnode: Empty block validated with state root: {:?}", expected_state_root);
                
                return ValidateBlockResponse::Valid {
                    app_state_updates: None,
                    validator_set_updates: None,
                };
            }

            // Execute transactions with JMT and verify state root
            let (app_state_updates, computed_state_root, final_version) = self.execute(
                &block_payload.transactions, 
                &initial_block_tree, 
                block_start_version
            );
            
            // Update next version for consistency
            self.next_version = final_version + 1;
            
            // Verify that the computed state root matches the proposed one
            let expected_state_root = block_payload.state_root();
            if computed_state_root != expected_state_root {
                println!("❌ Fullnode: Block validation failed - state root mismatch");
                println!("   Expected: {:?}", expected_state_root);
                println!("   Computed: {:?}", computed_state_root);
                return ValidateBlockResponse::Invalid;
            }

            println!("✅ Fullnode: Block validated successfully with state root: {:?}", computed_state_root);
            ValidateBlockResponse::Valid {
                app_state_updates,
                validator_set_updates: None,
            }
        } else {
            println!("❌ Fullnode: Block validation failed - could not deserialize block payload");
            ValidateBlockResponse::Invalid
        }
    }
}
