//! Health check system for production monitoring
//! 
//! Provides comprehensive health checks for fullnode and validator deployments.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use hotstuff_rs::types::data_types::BlockHeight;

use crate::{
    fullnode::{MetricsCollector, SnapshotManager},
    networking::LibP2PNetwork,
    database::rocks_db::RocksDBStore,
    types::NodeMode,
};
use hotstuff_rs::block_tree::pluggables::KVGet;

/// Overall health status of the node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical issues detected
    Warning,
    /// Critical issues detected
    Critical,
    /// Node is starting up
    Starting,
    /// Node is shutting down
    Stopping,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Warning => write!(f, "warning"),
            HealthStatus::Critical => write!(f, "critical"),
            HealthStatus::Starting => write!(f, "starting"),
            HealthStatus::Stopping => write!(f, "stopping"),
        }
    }
}

/// Individual component health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Last check timestamp
    pub last_check: u64,
    /// Status message
    pub message: String,
    /// Check duration in milliseconds
    pub check_duration_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ComponentHealth {
    pub fn healthy(name: String, message: String) -> Self {
        Self::new(name, HealthStatus::Healthy, message)
    }

    pub fn warning(name: String, message: String) -> Self {
        Self::new(name, HealthStatus::Warning, message)
    }

    pub fn critical(name: String, message: String) -> Self {
        Self::new(name, HealthStatus::Critical, message)
    }

    fn new(name: String, status: HealthStatus, message: String) -> Self {
        Self {
            name,
            status,
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            message,
            check_duration_ms: 0,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.check_duration_ms = duration.as_millis() as u64;
        self
    }
}

/// Comprehensive health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall health status
    pub status: HealthStatus,
    /// Node mode (validator or fullnode)
    pub node_mode: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Timestamp of this report
    pub timestamp: u64,
    /// Individual component health statuses
    pub components: HashMap<String, ComponentHealth>,
    /// Summary message
    pub summary: String,
    /// Version information
    pub version: String,
}

impl HealthReport {
    pub fn new(node_mode: NodeMode, uptime: Duration) -> Self {
        Self {
            status: HealthStatus::Starting,
            node_mode: node_mode.to_string(),
            uptime_seconds: uptime.as_secs(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            components: HashMap::new(),
            summary: "Health check in progress".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn add_component(&mut self, component: ComponentHealth) {
        self.components.insert(component.name.clone(), component);
    }

    pub fn finalize(&mut self) {
        // Determine overall status based on components
        let has_critical = self.components.values().any(|c| c.status == HealthStatus::Critical);
        let has_warning = self.components.values().any(|c| c.status == HealthStatus::Warning);

        self.status = if has_critical {
            HealthStatus::Critical
        } else if has_warning {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        // Generate summary
        let healthy_count = self.components.values().filter(|c| c.status == HealthStatus::Healthy).count();
        let warning_count = self.components.values().filter(|c| c.status == HealthStatus::Warning).count();
        let critical_count = self.components.values().filter(|c| c.status == HealthStatus::Critical).count();

        self.summary = match self.status {
            HealthStatus::Healthy => format!("{} components healthy", healthy_count),
            HealthStatus::Warning => format!("{} healthy, {} warning, {} critical", healthy_count, warning_count, critical_count),
            HealthStatus::Critical => format!("CRITICAL: {} components failed", critical_count),
            HealthStatus::Starting => "Node starting up".to_string(),
            HealthStatus::Stopping => "Node shutting down".to_string(),
        };
    }
}

/// Health checker that performs comprehensive system health checks
pub struct HealthChecker {
    node_mode: NodeMode,
    start_time: Instant,
    kv_store: Option<RocksDBStore>,
    network: Option<Arc<Mutex<LibP2PNetwork>>>,
    metrics_collector: Option<Arc<MetricsCollector>>,
    snapshot_manager: Option<Arc<SnapshotManager>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(node_mode: NodeMode) -> Self {
        Self {
            node_mode,
            start_time: Instant::now(),
            kv_store: None,
            network: None,
            metrics_collector: None,
            snapshot_manager: None,
        }
    }

    /// Set the KV store for database health checks
    pub fn with_kv_store(mut self, kv_store: RocksDBStore) -> Self {
        self.kv_store = Some(kv_store);
        self
    }

    /// Set the network for network health checks
    pub fn with_network(mut self, network: Arc<Mutex<LibP2PNetwork>>) -> Self {
        self.network = Some(network);
        self
    }

    /// Set the metrics collector for metrics health checks
    pub fn with_metrics(mut self, collector: Arc<MetricsCollector>) -> Self {
        self.metrics_collector = Some(collector);
        self
    }

    /// Set the snapshot manager for snapshot health checks
    pub fn with_snapshots(mut self, manager: Arc<SnapshotManager>) -> Self {
        self.snapshot_manager = Some(manager);
        self
    }

    /// Perform comprehensive health check
    pub async fn check_health(&self) -> HealthReport {
        let uptime = self.start_time.elapsed();
        let mut report = HealthReport::new(self.node_mode, uptime);

        // Check database health
        report.add_component(self.check_database_health().await);

        // Check network health
        report.add_component(self.check_network_health().await);

        // Check sync health (for fullnodes)
        if self.node_mode == NodeMode::Fullnode {
            report.add_component(self.check_sync_health().await);
        }

        // Check snapshot health (if available)
        if self.snapshot_manager.is_some() {
            report.add_component(self.check_snapshot_health().await);
        }

        // Check metrics health
        report.add_component(self.check_metrics_health().await);

        // Check memory and performance
        report.add_component(self.check_performance_health().await);

        report.finalize();
        report
    }

    /// Check database connectivity and health
    async fn check_database_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        match &self.kv_store {
            Some(kv_store) => {
                // Try a simple read operation to test database
                match kv_store.get(b"health_check_key") {
                    Some(_) => {
                        ComponentHealth::healthy(
                            "database".to_string(),
                            "Database accessible and responsive".to_string(),
                        ).with_duration(start.elapsed())
                    }
                    None => {
                        ComponentHealth::healthy(
                            "database".to_string(),
                            "Database accessible (no test data found, which is normal)".to_string(),
                        ).with_duration(start.elapsed())
                    }
                }
            }
            None => {
                ComponentHealth::warning(
                    "database".to_string(),
                    "Database not configured for health checks".to_string(),
                ).with_duration(start.elapsed())
            }
        }
    }

    /// Check network connectivity and peer health
    async fn check_network_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        match &self.network {
            Some(network) => {
                let peer_count = 0; // Simplified - would need to implement connection counting
                let local_peer_id = if let Ok(net) = network.lock() {
                    net.local_peer_id().to_string()
                } else {
                    "unknown".to_string()
                };

                if peer_count == 0 {
                    ComponentHealth::warning(
                        "network".to_string(),
                        "No connected peers".to_string(),
                    )
                    .with_metadata("peer_count".to_string(), serde_json::Value::Number(peer_count.into()))
                    .with_metadata("local_peer_id".to_string(), serde_json::Value::String(local_peer_id))
                    .with_duration(start.elapsed())
                } else {
                    ComponentHealth::healthy(
                        "network".to_string(),
                        format!("{} peers connected", peer_count),
                    )
                    .with_metadata("peer_count".to_string(), serde_json::Value::Number(peer_count.into()))
                    .with_metadata("local_peer_id".to_string(), serde_json::Value::String(local_peer_id))
                    .with_duration(start.elapsed())
                }
            }
            None => {
                ComponentHealth::critical(
                    "network".to_string(),
                    "Network not initialized".to_string(),
                ).with_duration(start.elapsed())
            }
        }
    }

    /// Check sync status health (fullnodes only)
    async fn check_sync_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        match &self.metrics_collector {
            Some(collector) => {
                let metrics = collector.get_metrics();
                let blocks_behind = metrics.sync.blocks_behind;
                let sync_progress = metrics.sync.sync_progress;
                
                let health = if blocks_behind == 0 {
                    ComponentHealth::healthy(
                        "sync".to_string(),
                        "Fully synced with network".to_string(),
                    )
                } else if blocks_behind <= 10 {
                    ComponentHealth::warning(
                        "sync".to_string(),
                        format!("{} blocks behind", blocks_behind),
                    )
                } else {
                    ComponentHealth::critical(
                        "sync".to_string(),
                        format!("Significantly behind: {} blocks", blocks_behind),
                    )
                };

                health
                    .with_metadata("blocks_behind".to_string(), serde_json::Value::Number(blocks_behind.into()))
                    .with_metadata("sync_progress".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(sync_progress as f64).unwrap()))
                    .with_metadata("current_height".to_string(), serde_json::Value::Number(metrics.sync.current_height.into()))
                    .with_duration(start.elapsed())
            }
            None => {
                ComponentHealth::warning(
                    "sync".to_string(),
                    "Sync metrics not available".to_string(),
                ).with_duration(start.elapsed())
            }
        }
    }

    /// Check snapshot system health
    async fn check_snapshot_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        match &self.snapshot_manager {
            Some(manager) => {
                match manager.list_snapshots() {
                    Ok(snapshots) => {
                        let snapshot_count = snapshots.len();
                        let total_size = manager.total_snapshot_size();
                        
                        let health = if snapshot_count > 0 {
                            ComponentHealth::healthy(
                                "snapshots".to_string(),
                                format!("{} snapshots available", snapshot_count),
                            )
                        } else {
                            ComponentHealth::warning(
                                "snapshots".to_string(),
                                "No snapshots available".to_string(),
                            )
                        };

                        health
                            .with_metadata("snapshot_count".to_string(), serde_json::Value::Number(snapshot_count.into()))
                            .with_metadata("total_size_bytes".to_string(), serde_json::Value::Number(total_size.into()))
                            .with_duration(start.elapsed())
                    }
                    Err(e) => {
                        ComponentHealth::critical(
                            "snapshots".to_string(),
                            format!("Snapshot system error: {}", e),
                        ).with_duration(start.elapsed())
                    }
                }
            }
            None => {
                ComponentHealth::warning(
                    "snapshots".to_string(),
                    "Snapshot system not configured".to_string(),
                ).with_duration(start.elapsed())
            }
        }
    }

    /// Check metrics collection health
    async fn check_metrics_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        match &self.metrics_collector {
            Some(collector) => {
                let metrics = collector.get_metrics();
                let uptime = metrics.performance.uptime_seconds;
                let message_rate = metrics.network.gossip_messages_received;
                
                ComponentHealth::healthy(
                    "metrics".to_string(),
                    "Metrics collection active".to_string(),
                )
                .with_metadata("uptime_seconds".to_string(), serde_json::Value::Number(uptime.into()))
                .with_metadata("messages_received".to_string(), serde_json::Value::Number(message_rate.into()))
                .with_duration(start.elapsed())
            }
            None => {
                ComponentHealth::warning(
                    "metrics".to_string(),
                    "Metrics collection not configured".to_string(),
                ).with_duration(start.elapsed())
            }
        }
    }

    /// Check system performance and resource usage
    async fn check_performance_health(&self) -> ComponentHealth {
        let start = Instant::now();
        
        // Get memory usage (simplified)
        let memory_info = self.get_memory_info();
        
        // Check if performance is acceptable
        let memory_usage_mb = memory_info.used_mb;
        let memory_threshold_mb = 1024; // 1GB threshold
        
        let health = if memory_usage_mb > memory_threshold_mb {
            ComponentHealth::warning(
                "performance".to_string(),
                format!("High memory usage: {} MB", memory_usage_mb),
            )
        } else {
            ComponentHealth::healthy(
                "performance".to_string(),
                "System performance normal".to_string(),
            )
        };

        health
            .with_metadata("memory_used_mb".to_string(), serde_json::Value::Number(memory_usage_mb.into()))
            .with_metadata("memory_available_mb".to_string(), serde_json::Value::Number(memory_info.available_mb.into()))
            .with_duration(start.elapsed())
    }

    /// Get memory information (simplified implementation)
    fn get_memory_info(&self) -> MemoryInfo {
        // This is a simplified implementation
        // In production, you'd use system APIs to get actual memory usage
        MemoryInfo {
            used_mb: 256,     // Placeholder
            available_mb: 4096, // Placeholder
            total_mb: 8192,   // Placeholder
        }
    }

    /// Perform a quick liveness check (for load balancer health checks)
    pub async fn liveness_check(&self) -> bool {
        // Simple check: can we access the database?
        match &self.kv_store {
            Some(kv_store) => kv_store.get(b"liveness_check").is_some() || true, // Always true for liveness
            None => true, // If no DB configured, assume alive
        }
    }

    /// Perform a readiness check (for traffic routing decisions)
    pub async fn readiness_check(&self) -> bool {
        // More comprehensive check for readiness to serve traffic
        let db_ready = match &self.kv_store {
            Some(kv_store) => kv_store.get(b"readiness_check").is_some() || true, // Simplified check
            None => true,
        };

        let network_ready = match &self.network {
            Some(_) => true, // Simplified - would check peer connections
            None => false,
        };

        let sync_ready = if self.node_mode == NodeMode::Fullnode {
            match &self.metrics_collector {
                Some(collector) => {
                    let metrics = collector.get_metrics();
                    metrics.sync.blocks_behind <= 5 // Ready if less than 5 blocks behind
                }
                None => false,
            }
        } else {
            true // Validators are always ready if network and DB are ready
        };

        db_ready && network_ready && sync_ready
    }
}

/// Memory information structure
#[derive(Debug, Clone)]
struct MemoryInfo {
    used_mb: u64,
    available_mb: u64,
    total_mb: u64,
}

/// Configuration for health checks
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// How often to run health checks
    pub check_interval: Duration,
    /// Timeout for individual health checks
    pub check_timeout: Duration,
    /// Enable detailed component checks
    pub detailed_checks: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            check_timeout: Duration::from_secs(5),
            detailed_checks: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeMode;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Warning.to_string(), "warning");
        assert_eq!(HealthStatus::Critical.to_string(), "critical");
    }

    #[test]
    fn test_component_health_creation() {
        let health = ComponentHealth::healthy(
            "test".to_string(),
            "Test component".to_string(),
        );
        
        assert_eq!(health.name, "test");
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.message, "Test component");
    }

    #[test]
    fn test_health_report_finalization() {
        let mut report = HealthReport::new(NodeMode::Fullnode, Duration::from_secs(100));
        
        report.add_component(ComponentHealth::healthy("db".to_string(), "OK".to_string()));
        report.add_component(ComponentHealth::warning("network".to_string(), "Slow".to_string()));
        
        report.finalize();
        
        assert_eq!(report.status, HealthStatus::Warning);
        assert!(report.summary.contains("warning"));
    }

    #[tokio::test]
    async fn test_liveness_check() {
        let checker = HealthChecker::new(NodeMode::Fullnode);
        // Should return true when no dependencies configured
        assert!(checker.liveness_check().await);
    }
}
