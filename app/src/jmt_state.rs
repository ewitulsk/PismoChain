//! Pure JMT state computation without KVStore dependencies
//! 
//! This module provides JMT operations that work with AppBlockTreeView and AppStateUpdates,
//! following the correct HotStuff integration pattern.


use anyhow::Result;
use jmt::{
    JellyfishMerkleTree, 
    KeyHash, RootHash, OwnedValue, Version,
    storage::{TreeReader, TreeWriter, Node, NodeKey, LeafNode, NodeBatch},
    proof::SparseMerkleProof,
};
use hotstuff_rs::{
    block_tree::accessors::app::AppBlockTreeView,
    types::update_sets::AppStateUpdates,
    block_tree::pluggables::KVStore,
};
use sha3::{Digest, Sha3_256};

/// Creates a 32-byte state key from owner address and struct tag
pub fn make_state_key(addr: [u8; 32], struct_tag: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha3_256 as Digest>::new();
    sha3::Digest::update(&mut hasher, addr);
    sha3::Digest::update(&mut hasher, struct_tag);
    sha3::Digest::finalize(hasher).into()
}

/// Convert a state key to JMT KeyHash
pub fn make_key_hash(state_key: [u8; 32]) -> KeyHash {
    KeyHash::with::<sha2::Sha256>(&state_key)
}

/// Helper to create KeyHash from address and struct tag
pub fn make_key_hash_from_parts(addr: [u8; 32], struct_tag: &[u8]) -> KeyHash {
    let state_key = make_state_key(addr, struct_tag);
    make_key_hash(state_key)
}

/// Key prefixes for storing JMT data in HotStuff's app state
const JMT_NODE_PREFIX: &[u8] = b"__jmt_node__";
const JMT_VALUE_PREFIX: &[u8] = b"__jmt_value__";
const JMT_ROOT_PREFIX: &[u8] = b"__jmt_root__";
/// Prefix for the secondary "latest" index
const JMT_LATEST_PREFIX: &[u8] = b"__jmt_latest__";
const COMMITTED_APP_STATE: u8 = 3;

/// Helper to create a latest-value index key for a given KeyHash
fn make_latest_key(key_hash: KeyHash) -> Vec<u8> {
    let mut k = Vec::with_capacity(JMT_LATEST_PREFIX.len() + 32);
    k.extend_from_slice(JMT_LATEST_PREFIX);
    k.extend_from_slice(&key_hash.0);
    k
}

/// Helper to create a value key for consistent key generation
fn make_value_key(version: Version, key_hash: KeyHash) -> Vec<u8> {
    let mut value_key = JMT_VALUE_PREFIX.to_vec();
    value_key.extend_from_slice(&version.to_le_bytes());
    value_key.extend_from_slice(&key_hash.0);
    value_key
}

/// In-memory JMT reader that reads from HotStuff's committed app state
pub struct AppStateJMTReader<'a, K: KVStore> {
    block_tree: &'a AppBlockTreeView<'a, K>,
}

impl<'a, K: KVStore> AppStateJMTReader<'a, K> {
    pub fn new(block_tree: &'a AppBlockTreeView<'a, K>) -> Self {
        Self { block_tree }
    }
}

impl<'a, K: KVStore> TreeReader for AppStateJMTReader<'a, K> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let mut key = JMT_NODE_PREFIX.to_vec();
        key.extend_from_slice(&bincode::serialize(node_key)?);
        
        Ok(self.block_tree.app_state(&key)
            .map(|bytes| bincode::deserialize(&bytes))
            .transpose()?)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let latest_key = make_latest_key(key_hash);
        if let Some(vbytes) = self.block_tree.app_state(&latest_key) {
            if vbytes.len() >= 8 {
                let latest = Version::from_le_bytes(vbytes[..8].try_into()?);
                
                if latest <= max_version {
                    let value_key = make_value_key(latest, key_hash);
                    return Ok(self.block_tree.app_state(&value_key));
                }
            }
        }

        // No latest-value index exists, so this key has never been written
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // This would require a more complex implementation to scan all nodes
        // For now, return None as it's mainly used for tree restoration
        Ok(None)
    }
}

impl<'a, K: KVStore> TreeWriter for AppStateJMTReader<'a, K> {
    fn write_node_batch(&self, _node_batch: &NodeBatch) -> Result<()> {
        // This should never be called in our pattern
        Err(anyhow::anyhow!("Direct writes not supported - use compute_jmt_updates"))
    }
}

/// Get the JMT root for a specific version from committed app state
pub fn get_jmt_root<K: KVStore>(
    block_tree: &AppBlockTreeView<K>,
    version: Version,
) -> Option<RootHash> {
    let mut root_key = JMT_ROOT_PREFIX.to_vec();
    root_key.extend_from_slice(&version.to_le_bytes());
    
    block_tree.app_state(&root_key)
        .map(|bytes| RootHash(bytes.as_slice().try_into().unwrap_or([0u8; 32])))
}

/// Get a JMT value for a specific version from committed app state
pub fn get_jmt_value<K: KVStore>(
    block_tree: &AppBlockTreeView<K>,
    key_hash: KeyHash,
    version: Version,
) -> Result<Option<OwnedValue>> {
    let reader = AppStateJMTReader::new(block_tree);
    reader.get_value_option(version, key_hash)
}

/// Compute JMT updates without persisting - returns AppStateUpdates
/// This follows the correct pattern: read from committed state, compute changes, return updates
pub fn compute_jmt_updates<K: KVStore>(
    block_tree: &AppBlockTreeView<K>,
    version: Version,
    writes: Vec<(KeyHash, Option<OwnedValue>)>,
) -> Result<(RootHash, AppStateUpdates)> {
    if writes.is_empty() {
        let prev_root = get_jmt_root(block_tree, version.saturating_sub(1))
            .unwrap_or_else(|| RootHash([0u8; 32]));
        return Ok((prev_root, AppStateUpdates::new()));
    }

    let reader = AppStateJMTReader::new(block_tree);
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    
    // Apply the write set using JMT - this doesn't persist, just computes the batch
    let (new_root, tree_update_batch) = tree.put_value_set(writes, version)?;
    
    let mut updates = AppStateUpdates::new();
    let node_batch = &tree_update_batch.node_batch;
    
    // Convert JMT node batch to AppStateUpdates
    
    // Store JMT internal nodes
    for (node_key, node) in node_batch.nodes() {
        let mut key = JMT_NODE_PREFIX.to_vec();
        key.extend_from_slice(&bincode::serialize(node_key)?);
        let value = bincode::serialize(node)?;
        updates.insert(key, value);
    }
    
    // Store JMT values
    for ((val_version, key_hash), value) in node_batch.values() {
        let mut key = JMT_VALUE_PREFIX.to_vec();
        key.extend_from_slice(&val_version.to_le_bytes());
        key.extend_from_slice(&key_hash.0);
        
        match value {
            Some(val) => updates.insert(key, val.clone()),
            None => updates.delete(key),
        }

        let latest_key = make_latest_key(*key_hash);
        let version_bytes = val_version.to_le_bytes().to_vec();
        updates.insert(latest_key, version_bytes);
    }
    
    // Store the new root
    let mut root_key = JMT_ROOT_PREFIX.to_vec();
    root_key.extend_from_slice(&version.to_le_bytes());
    updates.insert(root_key, new_root.0.to_vec());

    Ok((new_root, updates))
}

/// Simple JMT reader that works directly with KVStore for RPC queries
pub struct DirectJMTReader<'a, K: KVStore> {
    kv_store: &'a K,
}

impl<'a, K: KVStore> DirectJMTReader<'a, K> {
    pub fn new(kv_store: &'a K) -> Self {
        Self { kv_store }
    }
}

impl<'a, K: KVStore> TreeReader for DirectJMTReader<'a, K> {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let mut key = Vec::new();
        key.push(COMMITTED_APP_STATE);
        key.extend_from_slice(JMT_NODE_PREFIX);
        key.extend_from_slice(&bincode::serialize(node_key)?);
        
        Ok(self.kv_store.get(&key)
            .map(|bytes| bincode::deserialize(&bytes))
            .transpose()?)
    }

    fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> Result<Option<OwnedValue>> {
        // Check the latest version index for this key
        let mut latest_key = Vec::new();
        latest_key.push(COMMITTED_APP_STATE); 
        latest_key.extend_from_slice(JMT_LATEST_PREFIX);
        latest_key.extend_from_slice(&key_hash.0);
        
        if let Some(vbytes) = self.kv_store.get(&latest_key) {
            if vbytes.len() >= 8 {
                let latest = Version::from_le_bytes(vbytes[..8].try_into()?);
                
                if latest <= max_version {
                    let mut value_key = Vec::new();
                    value_key.push(COMMITTED_APP_STATE);
                    value_key.extend_from_slice(JMT_VALUE_PREFIX);
                    value_key.extend_from_slice(&latest.to_le_bytes());
                    value_key.extend_from_slice(&key_hash.0);
                    return Ok(self.kv_store.get(&value_key));
                }
            }
        }
        Ok(None)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(None) // Not needed for simple queries
    }
}

/// Get a value with cryptographic proof from committed app state
pub fn get_with_proof<K: KVStore>(
    block_tree: &AppBlockTreeView<K>,
    key_hash: KeyHash,
    version: Version,
) -> Result<(Option<OwnedValue>, SparseMerkleProof<sha2::Sha256>)> {
    let reader = AppStateJMTReader::new(block_tree);
    let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
    tree.get_with_proof(key_hash, version)
}