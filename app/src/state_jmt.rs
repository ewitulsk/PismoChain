//! Real JMT-based state management for PismoChain
//! 
//! This module provides authenticated state storage using the actual Jellyfish Merkle Tree,
//! enabling verifiable state transitions and cryptographic inclusion/exclusion proofs.

use std::collections::BTreeMap;
use anyhow::Result;
use jmt::{
    JellyfishMerkleTree, 
    KeyHash, RootHash, OwnedValue, Version,
    storage::{TreeReader, TreeWriter, Node, NodeKey, LeafNode, NodeBatch},
    proof::SparseMerkleProof,
    SimpleHasher,
};
use sha3::{Digest, Sha3_256};

/// Creates a 32-byte state key from owner address and struct tag
/// Uses SHA3-256 to ensure uniform distribution across the sparse Merkle tree
pub fn make_state_key(addr: [u8; 32], struct_tag: &[u8]) -> [u8; 32] {
    use sha3::Digest;
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

/// In-memory storage that implements JMT's TreeReader + TreeWriter traits
/// This provides a complete JMT backend using only in-memory data structures
#[derive(Default, Clone)]
pub struct JMTMemoryStorage {
    /// JMT internal nodes indexed by NodeKey
    nodes: BTreeMap<NodeKey, Node>,
    /// Values indexed by (version, key_hash)
    values: BTreeMap<(Version, KeyHash), Option<OwnedValue>>,
    /// State roots indexed by version
    roots: BTreeMap<Version, RootHash>,
}

impl JMTMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the state root for a specific version
    pub fn get_root(&self, version: Version) -> Option<RootHash> {
        self.roots.get(&version).copied()
    }

    /// Store the state root for a specific version
    pub fn set_root(&mut self, version: Version, root: RootHash) {
        self.roots.insert(version, root);
    }

    /// Clear all data (useful for testing)
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.values.clear();
        self.roots.clear();
    }
}

impl TreeReader for JMTMemoryStorage {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.nodes.get(node_key).cloned())
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        // Find the most recent value at or before max_version
        let mut result: Option<(Version, Option<OwnedValue>)> = None;
        for ((version, kh), value) in &self.values {
            if *kh == key_hash && *version <= max_version {
                if result.is_none() || *version > result.as_ref().unwrap().0 {
                    result = Some((*version, value.clone()));
                }
            }
        }
        Ok(result.map(|(_, value)| value).flatten())
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // For tree restoration - find the rightmost leaf node
        for (node_key, node) in self.nodes.iter().rev() {
            if let Node::Leaf(leaf_node) = node {
                return Ok(Some((node_key.clone(), leaf_node.clone())));
            }
        }
        Ok(None)
    }
}

impl TreeWriter for JMTMemoryStorage {
    fn write_node_batch(&self, _node_batch: &NodeBatch) -> Result<()> {
        // Note: We need mutable access, but the trait requires &self
        // This is a limitation of the JMT design - we'll handle this in the StateExecutor
        // For now, we'll implement a custom method
        Err(anyhow::anyhow!("Use write_node_batch_mut instead"))
    }
}

impl JMTMemoryStorage {
    /// Mutable version of write_node_batch that actually works
    pub fn write_node_batch_mut(&mut self, node_batch: &NodeBatch) -> Result<()> {
        // Apply all node updates
        for (node_key, node) in node_batch.nodes() {
            self.nodes.insert(node_key.clone(), node.clone());
        }
        
        // Apply all value updates
        for ((version, key_hash), value) in node_batch.values() {
            self.values.insert((*version, *key_hash), value.clone());
        }
        
        Ok(())
    }
}

/// State executor that manages real JMT operations and state transitions
pub struct StateExecutor {
    storage: JMTMemoryStorage,
}

impl StateExecutor {
    pub fn new() -> Self {
        Self {
            storage: JMTMemoryStorage::new(),
        }
    }

    /// Execute a block by applying a set of key-value writes to the JMT
    /// Returns the new state root hash
    pub fn execute_block(
        &mut self,
        version: Version,
        writes: Vec<(KeyHash, Option<OwnedValue>)>,
    ) -> Result<RootHash> {
        if writes.is_empty() {
            // Return previous root if no writes
            return Ok(self.storage.get_root(version.saturating_sub(1))
                .unwrap_or_else(|| RootHash([0u8; 32])));
        }

        // Create JMT instance
        let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&self.storage);
        
        // Apply the write set using JMT
        let (new_root, tree_update_batch) = tree.put_value_set(writes, version)?;
        
        // Apply the batch to storage
        self.storage.write_node_batch_mut(&tree_update_batch.node_batch)?;
        
        // Store the new root
        self.storage.set_root(version, new_root);
        
        Ok(new_root)
    }

    /// Get a value with cryptographic proof
    pub fn get_with_proof(
        &self,
        key_hash: KeyHash,
        version: Version,
    ) -> Result<(Option<OwnedValue>, SparseMerkleProof<sha2::Sha256>)> {
        let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&self.storage);
        tree.get_with_proof(key_hash, version)
    }

    /// Get a value without proof (faster)
    pub fn get(&self, key_hash: KeyHash, version: Version) -> Result<Option<OwnedValue>> {
        self.storage.get_value_option(version, key_hash)
    }

    /// Get the state root for a specific version
    pub fn get_root(&self, version: Version) -> Option<RootHash> {
        self.storage.get_root(version)
    }

    /// Verify a sparse merkle proof
    pub fn verify_proof(
        proof: &SparseMerkleProof<sha2::Sha256>,
        root_hash: RootHash,
        key_hash: KeyHash,
        value: Option<&[u8]>,
    ) -> Result<()> {
        match value {
            Some(v) => proof.verify(root_hash, key_hash, Some(v.to_vec())),
            None => proof.verify::<Vec<u8>>(root_hash, key_hash, None),
        }
    }

    /// Get storage statistics for debugging
    pub fn storage_stats(&self) -> (usize, usize, usize) {
        (
            self.storage.nodes.len(),
            self.storage.values.len(), 
            self.storage.roots.len(),
        )
    }
}

impl Default for StateExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for StateExecutor {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }
}

