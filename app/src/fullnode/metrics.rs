//! Basic metrics collection for fullnode monitoring
//! 
//! Provides simple metrics tracking for fullnode performance and sync status.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
    collections::VecDeque,
};
use serde::{Deserialize, Serialize};
use hotstuff_rs::types::data_types::BlockHeight;

/// Metrics tracking for fullnode operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullnodeMetrics {
    /// Sync-related metrics
    pub sync: SyncMetrics,
    /// Network-related metrics
    pub network: NetworkMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// Sync status and progress metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMetrics {
    /// Current block height processed
    pub current_height: u64,
    /// Highest known block height from network
    pub highest_known_height: u64,
    /// Number of blocks behind the latest
    pub blocks_behind: u64,
    /// Whether the node is considered synced
    pub is_synced: bool,
    /// Number of pending blocks in queue
    pub pending_blocks: usize,
    /// Sync progress percentage (0-100)
    pub sync_progress: f32,
}

/// Network connection and communication metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Number of connected peers
    pub connected_peers: usize,
    /// Number of gossipsub messages received
    pub gossip_messages_received: u64,
    /// Number of block requests sent
    pub block_requests_sent: u64,
    /// Number of block responses received
    pub block_responses_received: u64,
    /// Average response time for block requests
    pub avg_response_time_ms: f32,
}

/// Performance and processing metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Blocks processed per second
    pub blocks_per_second: f32,
    /// Average block processing time
    pub avg_block_processing_ms: f32,
    /// Queue depth (blocks waiting to be processed)
    pub queue_depth: usize,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Internal metrics state with mutable collections
#[derive(Debug)]
struct MetricsState {
    metrics: FullnodeMetrics,
    recent_processing_times: VecDeque<Duration>,
    recent_response_times: VecDeque<Duration>,
}

/// Metrics collector that tracks and aggregates fullnode metrics
pub struct MetricsCollector {
    /// Shared metrics state
    state: Arc<Mutex<MetricsState>>,
    /// Start time for uptime calculation
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        let metrics = FullnodeMetrics {
            sync: SyncMetrics {
                current_height: 0,
                highest_known_height: 0,
                blocks_behind: 0,
                is_synced: false,
                pending_blocks: 0,
                sync_progress: 0.0,
            },
            network: NetworkMetrics {
                connected_peers: 0,
                gossip_messages_received: 0,
                block_requests_sent: 0,
                block_responses_received: 0,
                avg_response_time_ms: 0.0,
            },
            performance: PerformanceMetrics {
                blocks_per_second: 0.0,
                avg_block_processing_ms: 0.0,
                queue_depth: 0,
                uptime_seconds: 0,
            },
        };

        let state = MetricsState {
            metrics,
            recent_processing_times: VecDeque::with_capacity(100),
            recent_response_times: VecDeque::with_capacity(100),
        };

        Self {
            state: Arc::new(Mutex::new(state)),
            start_time: Instant::now(),
        }
    }

    /// Get a snapshot of current metrics
    pub fn get_metrics(&self) -> FullnodeMetrics {
        if let Ok(state) = self.state.lock() {
            state.metrics.clone()
        } else {
            FullnodeMetrics {
                sync: SyncMetrics {
                    current_height: 0,
                    highest_known_height: 0,
                    blocks_behind: 0,
                    is_synced: false,
                    pending_blocks: 0,
                    sync_progress: 0.0,
                },
                network: NetworkMetrics {
                    connected_peers: 0,
                    gossip_messages_received: 0,
                    block_requests_sent: 0,
                    block_responses_received: 0,
                    avg_response_time_ms: 0.0,
                },
                performance: PerformanceMetrics {
                    blocks_per_second: 0.0,
                    avg_block_processing_ms: 0.0,
                    queue_depth: 0,
                    uptime_seconds: 0,
                },
            }
        }
    }

    /// Update sync metrics
    pub fn update_sync_metrics(&self, current_height: BlockHeight, pending_blocks: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.sync.current_height = current_height.int();
            state.metrics.sync.pending_blocks = pending_blocks;
            
            // Update blocks behind calculation
            if state.metrics.sync.highest_known_height > state.metrics.sync.current_height {
                state.metrics.sync.blocks_behind = state.metrics.sync.highest_known_height - state.metrics.sync.current_height;
                state.metrics.sync.sync_progress = if state.metrics.sync.highest_known_height > 0 {
                    (state.metrics.sync.current_height as f32 / state.metrics.sync.highest_known_height as f32) * 100.0
                } else {
                    100.0
                };
            } else {
                state.metrics.sync.blocks_behind = 0;
                state.metrics.sync.sync_progress = 100.0;
            }
            
            state.metrics.sync.is_synced = state.metrics.sync.blocks_behind <= 1;
        }
    }

    /// Record a new highest known block height
    pub fn update_highest_known_height(&self, height: BlockHeight) {
        if let Ok(mut state) = self.state.lock() {
            if height.int() > state.metrics.sync.highest_known_height {
                state.metrics.sync.highest_known_height = height.int();
            }
        }
    }

    /// Record a gossipsub message received
    pub fn record_gossip_message(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.network.gossip_messages_received += 1;
        }
    }

    /// Record a block request sent
    pub fn record_block_request(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.network.block_requests_sent += 1;
        }
    }

    /// Record a block response received
    pub fn record_block_response(&self, response_time: Duration) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.network.block_responses_received += 1;
            
            // Update average response time
            state.recent_response_times.push_back(response_time);
            if state.recent_response_times.len() > 100 {
                state.recent_response_times.pop_front();
            }
            
            let avg_ms = state.recent_response_times.iter()
                .map(|d| d.as_millis() as f32)
                .sum::<f32>() / state.recent_response_times.len() as f32;
            state.metrics.network.avg_response_time_ms = avg_ms;
        }
    }

    /// Record block processing time
    pub fn record_block_processing(&self, processing_time: Duration) {
        if let Ok(mut state) = self.state.lock() {
            state.recent_processing_times.push_back(processing_time);
            if state.recent_processing_times.len() > 100 {
                state.recent_processing_times.pop_front();
            }
            
            // Update average processing time
            let avg_ms = state.recent_processing_times.iter()
                .map(|d| d.as_millis() as f32)
                .sum::<f32>() / state.recent_processing_times.len() as f32;
            state.metrics.performance.avg_block_processing_ms = avg_ms;
            
            // Calculate blocks per second
            if !state.recent_processing_times.is_empty() {
                let total_time_secs = state.recent_processing_times.iter()
                    .sum::<Duration>().as_secs_f32();
                state.metrics.performance.blocks_per_second = if total_time_secs > 0.0 {
                    state.recent_processing_times.len() as f32 / total_time_secs
                } else {
                    0.0
                };
            }
            
            // Update uptime
            state.metrics.performance.uptime_seconds = self.start_time.elapsed().as_secs();
        }
    }

    /// Update queue depth
    pub fn update_queue_depth(&self, depth: usize) {
        if let Ok(mut state) = self.state.lock() {
            state.metrics.performance.queue_depth = depth;
        }
    }

    /// Get shared metrics reference for RPC endpoints
    pub fn metrics_ref(&self) -> Arc<Mutex<MetricsState>> {
        self.state.clone()
    }
}
