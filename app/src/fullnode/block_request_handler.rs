//! Block request handler for validators
//! 
//! Handles incoming block requests from fullnodes and responds with requested blocks.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{info, warn, debug, error};
use hotstuff_rs::types::data_types::BlockHeight;

use crate::{
    networking::{BlockRequest, BlockResponse, FinalizedBlockMessage, LibP2PNetwork},
    fullnode::block_publisher::BlockPublisher,
    database::rocks_db::RocksDBStore,
};

/// Handles block requests from fullnodes (validator-side)
pub struct BlockRequestHandler {
    network: Arc<Mutex<LibP2PNetwork>>,
    kv_store: RocksDBStore,
    /// Track request processing to avoid spam
    request_rate_limit: HashMap<u64, Instant>, // request_id -> last_processed
    /// Maximum requests to process per minute
    max_requests_per_minute: u32,
}

impl BlockRequestHandler {
    /// Create a new block request handler
    pub fn new(
        network: Arc<Mutex<LibP2PNetwork>>,
        kv_store: RocksDBStore,
    ) -> Self {
        Self {
            network,
            kv_store,
            request_rate_limit: HashMap::new(),
            max_requests_per_minute: 60, // Reasonable limit
        }
    }

    /// Process a block request from a fullnode
    pub fn process_block_request(&mut self, request: BlockRequest) -> anyhow::Result<()> {
        // Rate limiting check
        if !self.check_rate_limit(&request) {
            warn!("⚠️ Rate limit exceeded for block request");
            return self.send_error_response(request.request_id, "Rate limit exceeded".to_string());
        }

        info!("📤 Processing block request: {} to {} (request_id: {})", 
            request.start_height, request.end_height, request.request_id);

        // Validate request parameters
        if request.start_height > request.end_height {
            return self.send_error_response(request.request_id, "Invalid range: start_height > end_height".to_string());
        }

        if request.max_blocks == 0 || request.max_blocks > 50 {
            return self.send_error_response(request.request_id, "Invalid max_blocks: must be 1-50".to_string());
        }

        // Collect requested blocks
        let mut blocks = Vec::new();
        let mut current_height = request.start_height;
        let end_height = request.end_height.min(request.start_height + request.max_blocks as u64 - 1);

        while current_height <= end_height && blocks.len() < request.max_blocks as usize {
            // Try to get block at this height - this is simplified
            // In a real implementation, you'd need to map height to block hash
            // and use the block publisher's storage access
            match self.get_block_at_height(current_height) {
                Ok(Some(finalized_block)) => {
                    blocks.push(finalized_block);
                }
                Ok(None) => {
                    warn!("Block at height {} not found", current_height);
                    break; // Stop at first missing block
                }
                Err(e) => {
                    error!("Error retrieving block at height {}: {}", current_height, e);
                    return self.send_error_response(request.request_id, format!("Storage error: {}", e));
                }
            }
            current_height += 1;
        }

        // Send response
        let response = BlockResponse::success(request.request_id, blocks, true);
        self.send_block_response(response)
    }

    /// Check rate limiting for requests
    fn check_rate_limit(&mut self, request: &BlockRequest) -> bool {
        let now = Instant::now();
        
        // Clean up old entries (older than 1 minute)
        self.request_rate_limit.retain(|_, timestamp| {
            now.duration_since(*timestamp) < Duration::from_secs(60)
        });

        // Check if we're within rate limits
        if self.request_rate_limit.len() >= self.max_requests_per_minute as usize {
            return false;
        }

        // Record this request
        self.request_rate_limit.insert(request.request_id, now);
        true
    }

    /// Get block at specific height (simplified implementation)
    fn get_block_at_height(&self, height: u64) -> anyhow::Result<Option<FinalizedBlockMessage>> {
        // TODO: This is a simplified implementation
        // In practice, you'd need to:
        // 1. Map block height to block hash using committed chain
        // 2. Retrieve block by hash using BlockPublisher::get_block_from_storage
        // 3. Convert to FinalizedBlockMessage
        
        warn!("🚧 Block retrieval by height not yet implemented for height: {}", height);
        Ok(None)
    }

    /// Send an error response
    fn send_error_response(&self, request_id: u64, error: String) -> anyhow::Result<()> {
        let response = BlockResponse::error(request_id, error);
        self.send_block_response(response)
    }

    /// Send a block response
    fn send_block_response(&self, response: BlockResponse) -> anyhow::Result<()> {
        if let Ok(network) = self.network.lock() {
            network.respond_to_block_request(response)
                .map_err(|e| anyhow::anyhow!("Failed to send block response: {}", e))?;
        } else {
            return Err(anyhow::anyhow!("Failed to acquire network lock"));
        }
        Ok(())
    }
}
