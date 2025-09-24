//! State snapshot management for fast sync
//! 
//! Provides functionality to create, store, and restore state snapshots
//! for efficient fullnode bootstrapping.

use std::{
    path::{Path, PathBuf},
    fs,
    io::{self, Write, Read},
    time::{SystemTime, UNIX_EPOCH},
};
use serde::{Deserialize, Serialize};
use hotstuff_rs::{
    types::data_types::BlockHeight,
    block_tree::accessors::public::BlockTreeCamera,
    block_tree::pluggables::KVStore,
};
use jmt::RootHash;
use tracing::{info, warn, error, debug};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};

use crate::{
    database::rocks_db::RocksDBStore,
    jmt_state::{get_jmt_root, DirectJMTReader},
};

/// Metadata for a state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height at which this snapshot was taken
    pub block_height: u64,
    /// JMT version corresponding to this snapshot
    pub jmt_version: u64,
    /// State root hash at this snapshot
    pub state_root: [u8; 32],
    /// Timestamp when snapshot was created
    pub timestamp: u64,
    /// Size of the compressed snapshot data in bytes
    pub compressed_size: u64,
    /// Size of the uncompressed snapshot data in bytes
    pub uncompressed_size: u64,
    /// Checksum of the snapshot data for integrity verification
    pub checksum: [u8; 32],
}

impl SnapshotMetadata {
    pub fn new(
        block_height: u64,
        jmt_version: u64,
        state_root: RootHash,
        compressed_size: u64,
        uncompressed_size: u64,
        checksum: [u8; 32],
    ) -> Self {
        Self {
            block_height,
            jmt_version,
            state_root: state_root.0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            compressed_size,
            uncompressed_size,
            checksum,
        }
    }

    pub fn state_root(&self) -> RootHash {
        RootHash(self.state_root)
    }
}

/// Configuration for snapshot management
#[derive(Debug, Clone)]
pub struct SnapshotConfig {
    /// Directory to store snapshots
    pub snapshot_dir: PathBuf,
    /// How often to create snapshots (in blocks)
    pub snapshot_interval: u64,
    /// Maximum number of snapshots to keep
    pub max_snapshots: usize,
    /// Compression level (0-9, where 9 is max compression)
    pub compression_level: u32,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            snapshot_dir: PathBuf::from("./data/snapshots"),
            snapshot_interval: 1000, // Every 1000 blocks
            max_snapshots: 5,
            compression_level: 6, // Balanced compression
        }
    }
}

/// Manages state snapshots for fast sync
pub struct SnapshotManager {
    config: SnapshotConfig,
    kv_store: RocksDBStore,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(config: SnapshotConfig, kv_store: RocksDBStore) -> anyhow::Result<Self> {
        // Ensure snapshot directory exists
        fs::create_dir_all(&config.snapshot_dir)?;
        
        Ok(Self {
            config,
            kv_store,
        })
    }

    /// Check if a snapshot should be created at this block height
    pub fn should_create_snapshot(&self, block_height: u64) -> bool {
        block_height > 0 && block_height % self.config.snapshot_interval == 0
    }

    /// Create a snapshot of the current state
    pub fn create_snapshot(&self, block_height: u64, jmt_version: u64) -> anyhow::Result<SnapshotMetadata> {
        info!("📸 Creating state snapshot at block {} (JMT version {})", block_height, jmt_version);
        
        // Get current state root (simplified for now)
        let state_root = RootHash([0u8; 32]); // Placeholder - in practice get from block tree

        // Export state data from JMT
        let state_data = self.export_state_data(jmt_version)?;
        let uncompressed_size = state_data.len() as u64;

        // Compress the data
        let compressed_data = self.compress_data(&state_data)?;
        let compressed_size = compressed_data.len() as u64;

        // Calculate checksum
        let checksum = self.calculate_checksum(&compressed_data);

        // Write snapshot to disk
        let snapshot_path = self.get_snapshot_path(block_height);
        fs::write(&snapshot_path, &compressed_data)?;

        // Create metadata
        let metadata = SnapshotMetadata::new(
            block_height,
            jmt_version,
            state_root,
            compressed_size,
            uncompressed_size,
            checksum,
        );

        // Write metadata
        let metadata_path = self.get_metadata_path(block_height);
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(metadata_path, metadata_json)?;

        // Clean up old snapshots
        self.cleanup_old_snapshots()?;

        info!("✅ Snapshot created: {} bytes compressed ({}% ratio)", 
            compressed_size, 
            (compressed_size as f32 / uncompressed_size as f32 * 100.0) as u32
        );

        Ok(metadata)
    }

    /// Export state data from JMT at a specific version
    fn export_state_data(&self, version: u64) -> anyhow::Result<Vec<u8>> {
        // This is a simplified implementation
        // In practice, you'd need to:
        // 1. Iterate through all JMT keys at the given version
        // 2. Serialize all key-value pairs
        // 3. Include JMT internal nodes for proof verification
        
        warn!("🚧 State data export not fully implemented - using placeholder");
        
        // For now, return a placeholder that includes basic state info
        let placeholder_data = format!("SNAPSHOT_V{}_PLACEHOLDER", version);
        Ok(placeholder_data.into_bytes())
    }

    /// Compress data using gzip
    fn compress_data(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.config.compression_level));
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Decompress data using gzip
    fn decompress_data(&self, compressed_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    /// Calculate SHA256 checksum of data
    fn calculate_checksum(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Get snapshot file path for a given block height
    fn get_snapshot_path(&self, block_height: u64) -> PathBuf {
        self.config.snapshot_dir.join(format!("snapshot_{}.gz", block_height))
    }

    /// Get metadata file path for a given block height
    fn get_metadata_path(&self, block_height: u64) -> PathBuf {
        self.config.snapshot_dir.join(format!("snapshot_{}.json", block_height))
    }

    /// Load a snapshot from disk
    pub fn load_snapshot(&self, block_height: u64) -> anyhow::Result<(SnapshotMetadata, Vec<u8>)> {
        let metadata_path = self.get_metadata_path(block_height);
        let snapshot_path = self.get_snapshot_path(block_height);

        // Load metadata
        let metadata_json = fs::read_to_string(metadata_path)?;
        let metadata: SnapshotMetadata = serde_json::from_str(&metadata_json)?;

        // Load and decompress snapshot data
        let compressed_data = fs::read(snapshot_path)?;
        
        // Verify checksum
        let actual_checksum = self.calculate_checksum(&compressed_data);
        if actual_checksum != metadata.checksum {
            return Err(anyhow::anyhow!("Snapshot checksum mismatch"));
        }

        let state_data = self.decompress_data(&compressed_data)?;

        info!("📂 Loaded snapshot at block {} ({} bytes)", block_height, state_data.len());

        Ok((metadata, state_data))
    }

    /// List all available snapshots
    pub fn list_snapshots(&self) -> anyhow::Result<Vec<SnapshotMetadata>> {
        let mut snapshots = Vec::new();

        if !self.config.snapshot_dir.exists() {
            return Ok(snapshots);
        }

        for entry in fs::read_dir(&self.config.snapshot_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension() == Some(std::ffi::OsStr::new("json")) {
                if let Ok(metadata_json) = fs::read_to_string(&path) {
                    if let Ok(metadata) = serde_json::from_str::<SnapshotMetadata>(&metadata_json) {
                        snapshots.push(metadata);
                    }
                }
            }
        }

        // Sort by block height (newest first)
        snapshots.sort_by(|a, b| b.block_height.cmp(&a.block_height));

        Ok(snapshots)
    }

    /// Get the latest snapshot
    pub fn get_latest_snapshot(&self) -> anyhow::Result<Option<SnapshotMetadata>> {
        let snapshots = self.list_snapshots()?;
        Ok(snapshots.into_iter().next())
    }

    /// Clean up old snapshots, keeping only the most recent ones
    fn cleanup_old_snapshots(&self) -> anyhow::Result<()> {
        let snapshots = self.list_snapshots()?;
        
        if snapshots.len() <= self.config.max_snapshots {
            return Ok(());
        }

        // Remove oldest snapshots
        for snapshot in snapshots.iter().skip(self.config.max_snapshots) {
            let snapshot_path = self.get_snapshot_path(snapshot.block_height);
            let metadata_path = self.get_metadata_path(snapshot.block_height);
            
            if let Err(e) = fs::remove_file(&snapshot_path) {
                warn!("Failed to remove old snapshot {}: {}", snapshot_path.display(), e);
            }
            
            if let Err(e) = fs::remove_file(&metadata_path) {
                warn!("Failed to remove old metadata {}: {}", metadata_path.display(), e);
            } else {
                debug!("🗑️ Removed old snapshot at block {}", snapshot.block_height);
            }
        }

        Ok(())
    }

    /// Bootstrap from a snapshot (for new fullnodes)
    pub fn bootstrap_from_snapshot(&self, snapshot_metadata: &SnapshotMetadata) -> anyhow::Result<()> {
        info!("🚀 Bootstrapping from snapshot at block {} (JMT version {})", 
            snapshot_metadata.block_height, snapshot_metadata.jmt_version);

        // Load snapshot data
        let (_, state_data) = self.load_snapshot(snapshot_metadata.block_height)?;

        // Apply snapshot to current state
        self.apply_snapshot_data(&state_data, snapshot_metadata.jmt_version)?;

        info!("✅ Successfully bootstrapped from snapshot");
        Ok(())
    }

    /// Apply snapshot data to the current state
    fn apply_snapshot_data(&self, _state_data: &[u8], _version: u64) -> anyhow::Result<()> {
        // This is a simplified implementation
        // In practice, you'd need to:
        // 1. Parse the serialized state data
        // 2. Reconstruct the JMT at the specified version
        // 3. Update the app state to match the snapshot
        // 4. Verify state root matches snapshot metadata
        
        warn!("🚧 Snapshot data application not fully implemented");
        Ok(())
    }

    /// Get snapshot directory path
    pub fn snapshot_dir(&self) -> &Path {
        &self.config.snapshot_dir
    }

    /// Get total size of all snapshots
    pub fn total_snapshot_size(&self) -> u64 {
        let mut total_size = 0;
        
        if let Ok(snapshots) = self.list_snapshots() {
            for snapshot in snapshots {
                total_size += snapshot.compressed_size;
            }
        }
        
        total_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_snapshot_config_default() {
        let config = SnapshotConfig::default();
        assert_eq!(config.snapshot_interval, 1000);
        assert_eq!(config.max_snapshots, 5);
        assert_eq!(config.compression_level, 6);
    }

    #[test]
    fn test_should_create_snapshot() {
        let config = SnapshotConfig::default();
        let temp_dir = TempDir::new().unwrap();
        let kv_store = RocksDBStore::new(temp_dir.path().join("test_db").to_str().unwrap()).unwrap();
        let manager = SnapshotManager::new(config, kv_store).unwrap();

        assert!(!manager.should_create_snapshot(0));
        assert!(!manager.should_create_snapshot(999));
        assert!(manager.should_create_snapshot(1000));
        assert!(manager.should_create_snapshot(2000));
        assert!(!manager.should_create_snapshot(1001));
    }

    #[test]
    fn test_compression_roundtrip() {
        let config = SnapshotConfig::default();
        let temp_dir = TempDir::new().unwrap();
        let kv_store = RocksDBStore::new(temp_dir.path().join("test_db").to_str().unwrap()).unwrap();
        let manager = SnapshotManager::new(config, kv_store).unwrap();

        let test_data = b"Hello, World! This is test data for compression.";
        let compressed = manager.compress_data(test_data).unwrap();
        let decompressed = manager.decompress_data(&compressed).unwrap();

        assert_eq!(test_data, decompressed.as_slice());
        assert!(compressed.len() < test_data.len()); // Should be compressed
    }
}
