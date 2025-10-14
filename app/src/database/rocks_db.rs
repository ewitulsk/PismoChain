//! A production-grade RocksDB implementation of [`KVStore`].

use std::sync::Arc;
use hotstuff_rs::block_tree::pluggables::{KVGet, KVStore, WriteBatch};
use rocksdb::{DB, WriteBatch as RocksWb, Snapshot, WriteOptions, Options, ColumnFamilyDescriptor, IteratorMode};

/// Column family names
pub const CF_DEFAULT: &str = "default";
pub const CF_EVENTS: &str = "events";
pub const CF_TRANSACTIONS: &str = "transactions";

/// Opens a RocksDB instance with all required column families
fn open_db(path: &str) -> anyhow::Result<DB> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    
    // Define column families
    let cf_descriptors = vec![
        ColumnFamilyDescriptor::new(CF_DEFAULT, Options::default()),
        ColumnFamilyDescriptor::new(CF_EVENTS, Options::default()),
        ColumnFamilyDescriptor::new(CF_TRANSACTIONS, Options::default()),
    ];
    
    Ok(DB::open_cf_descriptors(&opts, path, cf_descriptors)?)
}

/// A production-grade RocksDB implementation of [`KVStore`].
#[derive(Clone)]
pub struct RocksDBStore {
    inner: Arc<DB>,                    // Thread-safe handle
    cf_name: String,                   // Column family name for lookups
}

impl RocksDBStore {
    /// Open (or create) a RocksDB instance using the default column family.
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let db = open_db(path)?;
        Ok(Self { 
            inner: Arc::new(db), 
            cf_name: "default".to_string()  // Always use default CF
        })
    }
}

/// RocksDB WriteBatch wrapper
pub struct RocksWriteBatch {
    wb: RocksWb,              // real RocksDB batch
}

impl WriteBatch for RocksWriteBatch {
    fn new() -> Self {
        Self { wb: RocksWb::default() }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        self.wb.put(key, value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.wb.delete(key);
    }
}

impl KVStore for RocksDBStore {
    type WriteBatch = RocksWriteBatch;
    type Snapshot<'a> = RocksSnapshot<'a>;

    fn write(&mut self, wb: Self::WriteBatch) {
        // Durable, WAL-synced write so consensus state is crash-safe.
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.inner.write_opt(wb.wb, &opts).expect("rocksdb write");
        
        // Force a flush to ensure data is immediately available for reads
        self.inner.flush().expect("rocksdb flush");
    }

    fn clear(&mut self) {
        // Iterate through all keys in default CF and delete them
        let keys: Vec<Vec<u8>> = self
            .inner
            .iterator(rocksdb::IteratorMode::Start)
            .map(|kv| kv.unwrap().0.to_vec())
            .collect();
        let mut batch = RocksWb::default();
        for k in keys { 
            batch.delete(&k); 
        }
        self.inner.write(batch).expect("clear");
    }

    fn snapshot<'b>(&'b self) -> Self::Snapshot<'b> {
        // RocksDB snapshot lives as long as &self.
        RocksSnapshot { 
            snap: self.inner.snapshot(), 
            db: self.inner.clone()
        }
    }
}

impl KVGet for RocksDBStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key).ok().flatten()
    }
}

/// RocksDB Snapshot wrapper
pub struct RocksSnapshot<'a> {
    snap: Snapshot<'a>,
    db: Arc<DB>,
}

impl<'a> KVGet for RocksSnapshot<'a> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.snap.get(key).ok().flatten()
    }
}

// Additional methods for column family operations
impl RocksDBStore {
    /// Get a value from a specific column family
    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Option<Vec<u8>> {
        let cf = self.inner.cf_handle(cf_name)?;
        self.inner.get_cf(&cf, key).ok().flatten()
    }
    
    /// Write to a specific column family
    pub fn write_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Column family {} not found", cf_name))?;
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.inner.put_cf_opt(&cf, key, value, &opts)?;
        self.inner.flush()?;
        Ok(())
    }
    
    /// Scan a range of keys in a specific column family
    /// Returns all key-value pairs where key >= start_key and key <= end_key (inclusive)
    pub fn scan_range_cf(&self, cf_name: &str, start_key: &[u8], end_key: &[u8]) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.inner.cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Column family {} not found", cf_name))?;
        
        let mut results = Vec::new();
        let iter = self.inner.iterator_cf(&cf, IteratorMode::From(start_key, rocksdb::Direction::Forward));
        
        for item in iter {
            let (key, value) = item?;
            // Stop if we've passed the end_key
            if key.as_ref() > end_key {
                break;
            }
            results.push((key.to_vec(), value.to_vec()));
        }
        
        Ok(results)
    }
}