use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use borsh::maybestd::io;
use indexmap::IndexMap;
use std::hash::Hash;

/// Wrapper for IndexMap that implements Borsh serialization
/// This maintains insertion order which is crucial for consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BorshIndexMap<K, V>(IndexMap<K, V>)
where
    K: Hash + Eq;

impl<K, V> BorshIndexMap<K, V>
where
    K: Hash + Eq,
{
    pub fn new() -> Self {
        Self(IndexMap::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(IndexMap::with_capacity(capacity))
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        K: Hash + Eq,
    {
        self.0.insert(key, value)
    }

    pub fn get(&self, key: &K) -> Option<&V>
    where
        K: Hash + Eq,
    {
        self.0.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V>
    where
        K: Hash + Eq,
    {
        self.0.get_mut(key)
    }

    pub fn shift_remove(&mut self, key: &K) -> Option<V>
    where
        K: Hash + Eq,
    {
        self.0.shift_remove(key)
    }

    pub fn entry(&mut self, key: K) -> indexmap::map::Entry<K, V>
    where
        K: Hash + Eq,
    {
        self.0.entry(key)
    }

    pub fn iter(&self) -> indexmap::map::Iter<K, V> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> indexmap::map::IterMut<K, V> {
        self.0.iter_mut()
    }

    pub fn values(&self) -> indexmap::map::Values<K, V> {
        self.0.values()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.0.retain(keep)
    }
}

impl<K, V> BorshSerialize for BorshIndexMap<K, V>
where
    K: BorshSerialize + Hash + Eq,
    V: BorshSerialize,
{
    fn serialize<W: io::Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        // Serialize length first
        let len = self.0.len() as u32;
        BorshSerialize::serialize(&len, writer)?;
        
        // Serialize key-value pairs in insertion order
        for (key, value) in self.0.iter() {
            BorshSerialize::serialize(key, writer)?;
            BorshSerialize::serialize(value, writer)?;
        }
        Ok(())
    }
}

impl<K, V> BorshDeserialize for BorshIndexMap<K, V>
where
    K: BorshDeserialize + Hash + Eq,
    V: BorshDeserialize,
{
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> Result<Self, io::Error> {
        let len = u32::deserialize_reader(reader)? as usize;
        let mut map = IndexMap::with_capacity(len);
        
        for _ in 0..len {
            let key = K::deserialize_reader(reader)?;
            let value = V::deserialize_reader(reader)?;
            map.insert(key, value);
        }
        
        Ok(Self(map))
    }
}
