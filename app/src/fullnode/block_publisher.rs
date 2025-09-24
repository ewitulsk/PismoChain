//! Block publisher for validators
//! 
//! Handles publishing finalized blocks to the gossipsub network for fullnodes to consume.

use std::sync::{Arc, Mutex};
use hotstuff_rs::{
    events::CommitBlockEvent,
    types::data_types::CryptoHash,
};
use tracing::{info, error, warn};

use crate::{
    networking::{LibP2PNetwork, FinalizedBlockMessage},
    pismo_app_jmt::BlockPayload,
    database::rocks_db::RocksDBStore,
};

/// Publishes finalized blocks to the gossipsub network
pub struct BlockPublisher {
    network: Arc<Mutex<LibP2PNetwork>>,
    kv_store: RocksDBStore,
}

impl BlockPublisher {
    /// Create a new block publisher
    pub fn new(
        network: Arc<Mutex<LibP2PNetwork>>,
        kv_store: RocksDBStore,
    ) -> Self {
        Self {
            network,
            kv_store,
        }
    }

    /// Publish a committed block to the network
    pub fn publish_committed_block(&self, event: &CommitBlockEvent) {
        let block_hash = event.block;
        
        // Attempt to retrieve and publish the block
        if let Err(e) = self.try_publish_block(block_hash) {
            error!("❌ Failed to publish committed block {}: {}", 
                hex::encode(&block_hash.bytes()[..8]), e);
        }
    }

    /// Internal method to retrieve and publish a block
    fn try_publish_block(&self, block_hash: CryptoHash) -> anyhow::Result<()> {
        // Retrieve block from storage
        let block = self.get_block_from_storage(block_hash)?;
        
        // Extract payload from block data
        let payload = self.extract_payload_from_block(&block)?;
        
        // Create finalized block message
        let message = FinalizedBlockMessage::new(&block, &payload)?;
        
        // Publish to gossipsub
        let network = self.network.lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire network lock: {}", e))?;
        
        network.publish_finalized_block(message)
            .map_err(|e| anyhow::anyhow!("Failed to publish via gossipsub: {}", e))?;
        
        info!("📡 Published finalized block {} (height: {})", 
            hex::encode(&block_hash.bytes()[..8]), block.height);
        
        Ok(())
    }

    /// Retrieve a block from storage by hash
    fn get_block_from_storage(&self, block_hash: CryptoHash) -> anyhow::Result<hotstuff_rs::types::block::Block> {
        use hotstuff_rs::block_tree::accessors::public::BlockTreeCamera;
        
        // Create a block tree camera to access storage
        let block_tree_camera = BlockTreeCamera::new(self.kv_store.clone());
        let snapshot = block_tree_camera.snapshot();
        
        // Try to get the block by hash
        match snapshot.block(&block_hash) {
            Ok(Some(block)) => {
                info!("📦 Retrieved block {} from storage", hex::encode(&block_hash.bytes()[..8]));
                Ok(block)
            }
            Ok(None) => {
                warn!("❌ Block {} not found in storage", hex::encode(&block_hash.bytes()[..8]));
                Err(anyhow::anyhow!("Block not found in storage"))
            }
            Err(e) => {
                warn!("❌ Failed to retrieve block {} from storage: {:?}", 
                    hex::encode(&block_hash.bytes()[..8]), e);
                Err(anyhow::anyhow!("Block retrieval error: {:?}", e))
            }
        }
    }

    /// Extract payload from block data
    fn extract_payload_from_block(&self, block: &hotstuff_rs::types::block::Block) -> anyhow::Result<BlockPayload> {
        if block.data.vec().is_empty() {
            return Err(anyhow::anyhow!("Block has no data"));
        }

        let payload_bytes = block.data.vec()[0].bytes();
        <BlockPayload as borsh::BorshDeserialize>::try_from_slice(payload_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize block payload: {}", e))
    }
}

/// Create a commit event handler closure for the replica
pub fn create_commit_event_handler(
    network: Arc<Mutex<LibP2PNetwork>>,
    kv_store: RocksDBStore,
) -> impl Fn(&CommitBlockEvent) + Send + Sync + 'static {
    let publisher = BlockPublisher::new(network, kv_store);
    
    move |event: &CommitBlockEvent| {
        publisher.publish_committed_block(event);
    }
}
