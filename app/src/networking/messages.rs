//! Network messages for fullnode synchronization
//! 
//! Defines messages used to broadcast finalized blocks from validators to fullnodes.

use serde::{Deserialize, Serialize};
use hotstuff_rs::types::{
    block::Block,
    data_types::{BlockHeight, CryptoHash},
};
use crate::pismo_app_jmt::BlockPayload;

/// Message broadcast by validators when a block is finalized/committed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedBlockMessage {
    /// Height of the finalized block (as u64 for serde compatibility)
    pub block_height: u64,
    /// Hash of the finalized block (as bytes for serde compatibility)
    pub block_hash: [u8; 32],
    /// Serialized Block data
    pub block_data: Vec<u8>,
    /// Serialized BlockPayload containing transactions and state root
    pub payload_data: Vec<u8>,
}

impl FinalizedBlockMessage {
    /// Create a new finalized block message
    pub fn new(
        block: &Block,
        payload: &BlockPayload,
    ) -> anyhow::Result<Self> {
        let block_data = borsh::to_vec(block)
            .map_err(|e| anyhow::anyhow!("Failed to serialize block: {}", e))?;
        
        let payload_data = borsh::to_vec(payload)
            .map_err(|e| anyhow::anyhow!("Failed to serialize payload: {}", e))?;

        Ok(Self {
            block_height: block.height.int(),
            block_hash: Block::hash(block.height, &block.justify, &block.data_hash).bytes(),
            block_data,
            payload_data,
        })
    }

    /// Deserialize the block from this message
    pub fn deserialize_block(&self) -> anyhow::Result<Block> {
        <Block as borsh::BorshDeserialize>::try_from_slice(&self.block_data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize block: {}", e))
    }

    /// Deserialize the payload from this message
    pub fn deserialize_payload(&self) -> anyhow::Result<BlockPayload> {
        <BlockPayload as borsh::BorshDeserialize>::try_from_slice(&self.payload_data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize payload: {}", e))
    }

    /// Get block height as BlockHeight type
    pub fn block_height(&self) -> BlockHeight {
        BlockHeight::new(self.block_height)
    }

    /// Get block hash as CryptoHash type  
    pub fn block_hash(&self) -> CryptoHash {
        CryptoHash::new(self.block_hash)
    }

    /// Get the size of this message in bytes
    pub fn size(&self) -> usize {
        self.block_data.len() + self.payload_data.len() + 64 // Approximate overhead
    }
}
