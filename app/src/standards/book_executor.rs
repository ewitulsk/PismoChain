use deterministic_bloom::runtime_size::BloomFilter;
use std::sync::{Arc, Mutex};

use crate::standards::orderbook::OrderbookAddr;

/// BookExecutor manages all orderbooks in the system using a deterministic bloom filter
/// This is a runtime optimization structure that doesn't need to be serialized
#[derive(Clone, Debug)]
pub struct BookExecutor {
    /// Bloom filter to track which orderbooks exist
    /// Using deterministic bloom filter for fast orderbook existence checks
    orderbook_filter: Arc<Mutex<BloomFilter>>,
    /// Vector of orderbook addresses that have changed since the last block
    /// This tracks which orderbooks need processing by the execution engine
    orderbooks: Arc<Mutex<Vec<OrderbookAddr>>>,
}

impl BookExecutor {
    /// Create a new BookExecutor with default bloom filter parameters
    pub fn new() -> Self {
        // Initialize with capacity for 10,000 orderbooks and 1% false positive rate
        Self {
            orderbook_filter: Arc::new(Mutex::new(BloomFilter::new_from_fpr(10_000, 0.01))),
            orderbooks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add an orderbook address to the executor's tracking
    pub fn add_orderbook(&self, orderbook_addr: &OrderbookAddr) {
        // Add to bloom filter for existence checks
        if let Ok(mut filter) = self.orderbook_filter.lock() {
            filter.insert(orderbook_addr);
        }
        
        // Add to orderbooks vector for processing tracking
        if let Ok(mut orderbooks) = self.orderbooks.lock() {
            if !orderbooks.contains(orderbook_addr) {
                orderbooks.push(*orderbook_addr);
            }
        }
    }

    /// Check if an orderbook might exist (bloom filter may have false positives)
    pub fn contain_orderbook(&self, orderbook_addr: &OrderbookAddr) -> bool {
        if let Ok(filter) = self.orderbook_filter.lock() {
            filter.contains(orderbook_addr)
        } else {
            false
        }
    }

    /// Clear the bloom filter (useful for testing or rebuilding)
    pub fn clear(&self) {
        if let Ok(mut filter) = self.orderbook_filter.lock() {
            *filter = BloomFilter::new_from_fpr(10_000, 0.01);
        }
        if let Ok(mut orderbooks) = self.orderbooks.lock() {
            orderbooks.clear();
        }
    }

    /// Get a copy of all tracked orderbook addresses
    pub fn get_orderbook_addresses(&self) -> Vec<OrderbookAddr> {
        if let Ok(orderbooks) = self.orderbooks.lock() {
            orderbooks.clone()
        } else {
            Vec::new()
        }
    }

    /// Mark an orderbook as changed (add to processing queue if not already present)
    pub fn mark_orderbook_changed(&self, orderbook_addr: &OrderbookAddr) {
        if let Ok(mut orderbooks) = self.orderbooks.lock() {
            if !orderbooks.contains(orderbook_addr) {
                orderbooks.push(*orderbook_addr);
            }
        }
    }

    /// Clear the changed orderbooks list (typically called after processing)
    pub fn clear_changed_orderbooks(&self) {
        if let Ok(mut orderbooks) = self.orderbooks.lock() {
            orderbooks.clear();
        }
    }

    /// Get the number of orderbooks being tracked
    pub fn orderbook_count(&self) -> usize {
        if let Ok(orderbooks) = self.orderbooks.lock() {
            orderbooks.len()
        } else {
            0
        }
    }
}


