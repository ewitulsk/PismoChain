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

/// Request for specific blocks from validators (sent by fullnodes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    /// Starting block height to request
    pub start_height: u64,
    /// Ending block height to request (inclusive)
    pub end_height: u64,
    /// Maximum number of blocks to return
    pub max_blocks: u32,
    /// Request ID for tracking responses
    pub request_id: u64,
}

impl BlockRequest {
    pub fn new(start_height: u64, end_height: u64, max_blocks: u32) -> Self {
        Self {
            start_height,
            end_height,
            max_blocks,
            request_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        }
    }

    pub fn single_block(height: u64) -> Self {
        Self::new(height, height, 1)
    }

    pub fn block_range(start: u64, end: u64) -> Self {
        let count = (end - start + 1).min(50) as u32; // Limit to 50 blocks per request
        Self::new(start, end, count)
    }
}

/// Response to block requests (sent by validators)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    /// Request ID this response corresponds to
    pub request_id: u64,
    /// List of finalized block messages
    pub blocks: Vec<FinalizedBlockMessage>,
    /// Whether this is the final response for the request
    pub is_final: bool,
    /// Error message if the request failed
    pub error: Option<String>,
}

impl BlockResponse {
    pub fn success(request_id: u64, blocks: Vec<FinalizedBlockMessage>, is_final: bool) -> Self {
        Self {
            request_id,
            blocks,
            is_final,
            error: None,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            blocks: Vec::new(),
            is_final: true,
            error: Some(error),
        }
    }

    pub fn size(&self) -> usize {
        self.blocks.iter().map(|b| b.size()).sum::<usize>() + 64 // Approximate overhead
    }
}

/// Request for available snapshots (sent by fullnodes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotListRequest {
    /// Request ID for tracking responses
    pub request_id: u64,
    /// Minimum block height to consider
    pub min_height: Option<u64>,
}

impl SnapshotListRequest {
    pub fn new(min_height: Option<u64>) -> Self {
        Self {
            request_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            min_height,
        }
    }
}

/// Response with available snapshots (sent by validators)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotListResponse {
    /// Request ID this response corresponds to
    pub request_id: u64,
    /// List of available snapshot metadata
    pub snapshots: Vec<crate::fullnode::SnapshotMetadata>,
    /// Error message if the request failed
    pub error: Option<String>,
}

impl SnapshotListResponse {
    pub fn success(request_id: u64, snapshots: Vec<crate::fullnode::SnapshotMetadata>) -> Self {
        Self {
            request_id,
            snapshots,
            error: None,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            snapshots: Vec::new(),
            error: Some(error),
        }
    }
}

/// Request for a specific snapshot (sent by fullnodes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Block height of the desired snapshot
    pub block_height: u64,
    /// Request ID for tracking responses
    pub request_id: u64,
}

impl SnapshotRequest {
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            request_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        }
    }
}

/// Response with snapshot data (sent by validators)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResponse {
    /// Request ID this response corresponds to
    pub request_id: u64,
    /// Snapshot metadata
    pub metadata: Option<crate::fullnode::SnapshotMetadata>,
    /// Compressed snapshot data (base64 encoded)
    pub data: Option<String>,
    /// Error message if the request failed
    pub error: Option<String>,
}

impl SnapshotResponse {
    pub fn success(
        request_id: u64, 
        metadata: crate::fullnode::SnapshotMetadata, 
        data: Vec<u8>
    ) -> Self {
        use base64::Engine;
        let encoded_data = base64::engine::general_purpose::STANDARD.encode(&data);
        
        Self {
            request_id,
            metadata: Some(metadata),
            data: Some(encoded_data),
            error: None,
        }
    }

    pub fn error(request_id: u64, error: String) -> Self {
        Self {
            request_id,
            metadata: None,
            data: None,
            error: Some(error),
        }
    }

    pub fn decode_data(&self) -> anyhow::Result<Vec<u8>> {
        use base64::Engine;
        
        match &self.data {
            Some(encoded) => {
                base64::engine::general_purpose::STANDARD.decode(encoded)
                    .map_err(|e| anyhow::anyhow!("Failed to decode snapshot data: {}", e))
            }
            None => Err(anyhow::anyhow!("No snapshot data in response")),
        }
    }
}
