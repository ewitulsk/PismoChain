use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};
use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;

use crate::standards::accounts::AccountAddr;

pub type CoinAddr = [u8; 32];
pub type CoinStoreAddr = [u8; 32];

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Coin {
    pub name: String,
    pub project_uri: String,
    pub logo_uri: String,
    pub total_supply: u128,
    pub max_supply: Option<u128>,
    pub canonical_chain_id: u64,
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct CoinStore {
    pub amount: u128,
}

/// Generate the coin address (object key) using Sha3(seed_addr || name || canonical_chain_id)
pub fn derive_coin_addr(seed_addr: &AccountAddr, name: &str, canonical_chain_id: u64) -> CoinAddr {
    let mut hasher = Sha3_256::new();
    hasher.update(seed_addr);
    hasher.update(name.as_bytes());
    hasher.update(canonical_chain_id.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Generate the bridged coin address using Sha3(token_address || emitter_chain)
pub fn derive_bridged_coin_addr(token_address: &str, emitter_chain: u16) -> CoinAddr {
    let mut hasher = Sha3_256::new();
    hasher.update(token_address.as_bytes());
    hasher.update(emitter_chain.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Create the object key for storing coin data in the app state
pub fn make_coin_object_key(coin_addr: &CoinAddr) -> Vec<u8> {
    let mut k = b"coin/".to_vec();
    k.extend_from_slice(coin_addr);
    k
}

/// Generate the coin store address (object key) using Sha3(account_address || coin_address)
pub fn derive_coin_store_addr(account_addr: &AccountAddr, coin_addr: &CoinAddr) -> CoinStoreAddr {
    let mut hasher = Sha3_256::new();
    hasher.update(account_addr);
    hasher.update(coin_addr);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Create the object key for storing coin store data in the app state
pub fn make_coin_store_object_key(coin_store_addr: &CoinStoreAddr) -> Vec<u8> {
    let mut k = b"store/".to_vec();
    k.extend_from_slice(coin_store_addr);
    k
}

/// Fetch a `Coin` by `coin_addr` from committed state using the app-level mirror
pub fn get_coin<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    coin_addr: &CoinAddr,
) -> Option<Coin> {
    let mirror_key = make_coin_object_key(coin_addr);
    if let Some(bytes) = block_tree.app_state(&mirror_key) {
        if let Ok(coin) = <Coin as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            return Some(coin);
        }
    }
    None
}

/// Fetch a `CoinStore` by `coin_store_addr` from committed state using the app-level mirror
pub fn get_coin_store<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    coin_store_addr: &CoinStoreAddr,
) -> Option<CoinStore> {
    let mirror_key = make_coin_store_object_key(coin_store_addr);
    if let Some(bytes) = block_tree.app_state(&mirror_key) {
        if let Ok(coin_store) = <CoinStore as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            return Some(coin_store);
        }
    }
    None
}
