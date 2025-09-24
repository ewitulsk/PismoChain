//! Block receiver for fullnodes
//! 
//! Handles receiving and processing finalized blocks from validators via gossipsub.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use hotstuff_rs::{
    types::{data_types::BlockHeight, block::Block},
};
use tracing::{info, warn, debug};

use crate::{
    networking::FinalizedBlockMessage,
    fullnode::FullnodeApp,
    database::rocks_db::RocksDBStore,
};

/// Receives and processes finalized blocks for fullnodes
pub struct BlockReceiver {
    fullnode_app: Arc<Mutex<FullnodeApp>>,
    kv_store: Arc<RocksDBStore>,
    expected_height: BlockHeight,
    pending_blocks: HashMap<u64, FinalizedBlockMessage>,
    max_pending_blocks: usize,
}

impl BlockReceiver {
    /// Create a new block receiver
    pub fn new(
        fullnode_app: Arc<Mutex<FullnodeApp>>,
        kv_store: Arc<RocksDBStore>,
        initial_height: BlockHeight,
    ) -> Self {
        Self {
            fullnode_app,
            kv_store,
            expected_height: initial_height,
            pending_blocks: HashMap::new(),
            max_pending_blocks: 100, // Limit memory usage
        }
    }

    /// Process a received finalized block message
    pub fn process_finalized_block(&mut self, message: FinalizedBlockMessage) -> anyhow::Result<()> {
        let block_height = message.block_height();
        
        debug!("📨 Received finalized block message (height: {})", block_height);

        // Check if this is the next expected block
        if block_height == self.expected_height {
            // Process immediately
            self.apply_block(message)?;
            self.expected_height = BlockHeight::new(self.expected_height.int() + 1);
            
            // Process any pending blocks that are now sequential
            self.process_pending_blocks()?;
        } else if block_height > self.expected_height {
            // Future block - queue it if we have space
            if self.pending_blocks.len() < self.max_pending_blocks {
                self.pending_blocks.insert(block_height.int(), message);
                info!("⏳ Queued future block (height: {}, expected: {})", 
                    block_height, self.expected_height);
            } else {
                warn!("🚫 Dropping future block {} - queue full", block_height);
            }
        } else {
            // Past block - ignore (already processed or duplicate)
            debug!("🔄 Ignoring past block (height: {}, expected: {})", 
                block_height, self.expected_height);
        }

        Ok(())
    }

    /// Apply a block to the fullnode state
    fn apply_block(&mut self, message: FinalizedBlockMessage) -> anyhow::Result<()> {
        let block = message.deserialize_block()?;
        let payload = message.deserialize_payload()?;

        info!("🔧 Applying block {} (height: {}, {} txs)", 
            hex::encode(&message.block_hash[..8]),
            message.block_height,
            payload.transactions.len()
        );

        // Verify block hash matches
        if Block::hash(block.height, &block.justify, &block.data_hash) != message.block_hash() {
            return Err(anyhow::anyhow!("Block hash mismatch"));
        }

        // Validate and apply the block using the fullnode app
        let _app_guard = self.fullnode_app.lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire fullnode app lock: {}", e))?;
        
        // TODO: Create proper ValidateBlockRequest and call fullnode_app.validate_block_for_sync()
        // This requires proper BlockTree integration with block storage
        warn!("🚧 Block validation using fullnode app not yet fully implemented");
        warn!("   This requires proper BlockTree integration with block storage");
        
        info!("✅ Block {} basic validation passed and applied", message.block_height);
        
        Ok(())
    }

    /// Process any pending blocks that can now be applied sequentially
    fn process_pending_blocks(&mut self) -> anyhow::Result<()> {
        while let Some(message) = self.pending_blocks.remove(&self.expected_height.int()) {
            info!("📦 Processing pending block (height: {})", self.expected_height);
            self.apply_block(message)?;
            self.expected_height = BlockHeight::new(self.expected_height.int() + 1);
        }
        Ok(())
    }

    /// Get current sync status
    pub fn sync_status(&self) -> SyncStatus {
        SyncStatus {
            current_height: BlockHeight::new(self.expected_height.int().saturating_sub(1)),
            expected_height: self.expected_height,
            pending_blocks: self.pending_blocks.len(),
            is_synced: self.pending_blocks.is_empty(),
        }
    }

    /// Handle a gap in block sequence by requesting missing blocks
    pub fn handle_block_gap(&mut self, detected_height: BlockHeight) {
        if detected_height > self.expected_height {
            warn!("🔍 Block gap detected: expected {}, received {}", 
                self.expected_height, detected_height);
            
            // In a full implementation, this would trigger block sync
            // to request the missing blocks from validators
        }
    }
}

/// Sync status information for monitoring
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub current_height: BlockHeight,
    pub expected_height: BlockHeight,
    pub pending_blocks: usize,
    pub is_synced: bool,
}
