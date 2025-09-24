//! Compression utilities for network messages and storage
//! 
//! Provides efficient compression for large block data and snapshots.

use std::io::{Write, Read};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};

/// Configuration for compression
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Compression level (0-9, where 9 is max compression)
    pub level: u32,
    /// Minimum size threshold to apply compression (bytes)
    pub min_size_threshold: usize,
    /// Maximum compressed message size (bytes)
    pub max_compressed_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            level: 6, // Balanced compression
            min_size_threshold: 1024, // Only compress if > 1KB
            max_compressed_size: 16 * 1024 * 1024, // 16MB max
        }
    }
}

/// Compressed data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    /// The compressed data
    pub data: Vec<u8>,
    /// Original size before compression
    pub original_size: usize,
    /// Whether the data is actually compressed
    pub is_compressed: bool,
    /// Compression algorithm used
    pub algorithm: CompressionAlgorithm,
}

/// Supported compression algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression applied
    None,
    /// Gzip compression
    Gzip,
}

/// Compression utility
pub struct CompressionUtil {
    config: CompressionConfig,
}

impl CompressionUtil {
    /// Create a new compression utility
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// Compress data if beneficial
    pub fn compress(&self, data: &[u8]) -> anyhow::Result<CompressedData> {
        let original_size = data.len();
        
        // Skip compression for small data
        if original_size < self.config.min_size_threshold {
            return Ok(CompressedData {
                data: data.to_vec(),
                original_size,
                is_compressed: false,
                algorithm: CompressionAlgorithm::None,
            });
        }

        // Try gzip compression
        let compressed = self.compress_gzip(data)?;
        
        // Use compression only if it provides significant benefit (at least 10% reduction)
        if compressed.len() < original_size * 9 / 10 && compressed.len() <= self.config.max_compressed_size {
            Ok(CompressedData {
                data: compressed,
                original_size,
                is_compressed: true,
                algorithm: CompressionAlgorithm::Gzip,
            })
        } else {
            // Compression not beneficial or result too large
            Ok(CompressedData {
                data: data.to_vec(),
                original_size,
                is_compressed: false,
                algorithm: CompressionAlgorithm::None,
            })
        }
    }

    /// Decompress data
    pub fn decompress(&self, compressed_data: &CompressedData) -> anyhow::Result<Vec<u8>> {
        if !compressed_data.is_compressed {
            return Ok(compressed_data.data.clone());
        }

        match compressed_data.algorithm {
            CompressionAlgorithm::None => Ok(compressed_data.data.clone()),
            CompressionAlgorithm::Gzip => self.decompress_gzip(&compressed_data.data),
        }
    }

    /// Compress using gzip
    fn compress_gzip(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.config.level));
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Decompress using gzip
    fn decompress_gzip(&self, compressed_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    /// Get compression ratio as percentage
    pub fn compression_ratio(&self, compressed_data: &CompressedData) -> f32 {
        if compressed_data.original_size == 0 {
            return 0.0;
        }
        
        (compressed_data.data.len() as f32 / compressed_data.original_size as f32) * 100.0
    }

    /// Calculate potential space savings
    pub fn space_savings(&self, compressed_data: &CompressedData) -> usize {
        if compressed_data.is_compressed {
            compressed_data.original_size.saturating_sub(compressed_data.data.len())
        } else {
            0
        }
    }
}

/// Compressed block response for large block batches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedBlockResponse {
    /// Original request ID
    pub request_id: u64,
    /// Compressed block data
    pub compressed_blocks: CompressedData,
    /// Number of blocks in the response
    pub block_count: usize,
    /// Whether this is the final response
    pub is_final: bool,
    /// Error message if any
    pub error: Option<String>,
}

impl CompressedBlockResponse {
    /// Create a compressed block response
    pub fn create(
        request_id: u64,
        blocks: Vec<crate::networking::FinalizedBlockMessage>,
        is_final: bool,
        compression_util: &CompressionUtil,
    ) -> anyhow::Result<Self> {
        // Serialize blocks
        let serialized = serde_json::to_vec(&blocks)?;
        
        // Compress the serialized data
        let compressed_blocks = compression_util.compress(&serialized)?;
        
        Ok(Self {
            request_id,
            compressed_blocks,
            block_count: blocks.len(),
            is_final,
            error: None,
        })
    }

    /// Decompress and get the original blocks
    pub fn decompress_blocks(
        &self,
        compression_util: &CompressionUtil,
    ) -> anyhow::Result<Vec<crate::networking::FinalizedBlockMessage>> {
        let decompressed = compression_util.decompress(&self.compressed_blocks)?;
        let blocks = serde_json::from_slice(&decompressed)?;
        Ok(blocks)
    }

    /// Get size information
    pub fn size_info(&self) -> (usize, usize, f32) {
        let compressed_size = self.compressed_blocks.data.len();
        let original_size = self.compressed_blocks.original_size;
        let ratio = if original_size > 0 {
            (compressed_size as f32 / original_size as f32) * 100.0
        } else {
            0.0
        };
        
        (compressed_size, original_size, ratio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_util() {
        let util = CompressionUtil::new(CompressionConfig::default());
        
        // Test with small data (should not compress)
        let small_data = b"small";
        let result = util.compress(small_data).unwrap();
        assert!(!result.is_compressed);
        assert_eq!(result.data, small_data);

        // Test with large repetitive data (should compress well)
        let large_data = vec![b'A'; 10000];
        let result = util.compress(&large_data).unwrap();
        assert!(result.is_compressed);
        assert!(result.data.len() < large_data.len());

        // Test roundtrip
        let decompressed = util.decompress(&result).unwrap();
        assert_eq!(decompressed, large_data);
    }

    #[test]
    fn test_compression_ratio() {
        let util = CompressionUtil::new(CompressionConfig::default());
        let data = vec![b'X'; 5000];
        let compressed = util.compress(&data).unwrap();
        
        let ratio = util.compression_ratio(&compressed);
        assert!(ratio > 0.0 && ratio <= 100.0);
        
        let savings = util.space_savings(&compressed);
        assert!(savings > 0);
    }
}
