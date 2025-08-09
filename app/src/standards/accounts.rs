use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::{BTreeMap, BTreeSet};
use sha3::{Digest, Sha3_256};

pub type Bytes = Vec<u8>;
pub type AccountAddr = [u8; 32];
pub type PubKey = Bytes;
pub type UnixMillis = u64;
pub type BlockHeight = u64;

#[repr(u8)]
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum KeyAlgo {
    Secp256k1 = 0,
    Ed25519 = 1,
    Sr25519 = 2,
}

#[derive(Clone, Copy, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Chain {
    EthereumSecp256k1,
    SolanaEd25519,
}

impl Chain {
    pub const fn internal_id(self) -> u16 {
        match self {
            Chain::EthereumSecp256k1 => 1,
            Chain::SolanaEd25519 => 2,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ExternalLink {
    pub chain: Chain,
    pub address: Bytes,
    pub algo: KeyAlgo,
    pub added_at: UnixMillis,
}

bitflags::bitflags! {
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ScopeBits: u32 {
        const TRANSFER = 1 << 0;
        const SPOT_TRADE = 1 << 1;
        const PERPS_TRADE = 1 << 2;
        const COLLATERAL_MANAGEMENT = 1 << 3;
        const ACCOUNT_ADMIN   = 1 << 4;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum SessionIssuer {
    LinkedKey { chain: Chain, address: Bytes },
    SessionKey { pubkey: PubKey },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SessionKey {
    pub algo: KeyAlgo,
    pub pubkey: PubKey,
    pub scopes: ScopeBits,
    pub issued_by: SessionIssuer,
    pub issued_at: UnixMillis,
    pub not_before: UnixMillis,
    pub expires_at: UnixMillis,
    pub last_used_height: BlockHeight,
    pub nonce: u64,
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Policy {
    pub max_session_lifetime_ms: u64,
    pub require_owner_for: ScopeBits,
    pub guardian_quorum: u8,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AccountMeta {
    pub created_at: UnixMillis,
    pub bumped: u8,
    pub frozen: bool,
    pub current_nonce: u64,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Account {
    pub account_addr: AccountAddr,
    pub links: BTreeSet<ExternalLink>,
    pub sessions: BTreeMap<[u8; 32], SessionKey>,
    pub scope_nonces: BTreeMap<u32, u64>,
    pub policy: Policy,
    pub meta: AccountMeta,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Link {
    pub account_addr: AccountAddr,
}

pub fn derive_account_addr(version: u8, chain: Chain, external_addr_bytes: &[u8]) -> AccountAddr {
    let mut hasher = Sha3_256::new();
    hasher.update(b"acct");
    hasher.update([version]);
    hasher.update(chain.internal_id().to_le_bytes());
    hasher.update(external_addr_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

pub fn make_account_object_key(account_addr: &AccountAddr) -> Vec<u8> {
    let mut k = b"acct/".to_vec();
    k.extend_from_slice(account_addr);
    k
}

pub fn make_link_object_key(chain: Chain, external_addr_bytes: &[u8]) -> Vec<u8> {
    let mut k = b"link/".to_vec();
    k.extend_from_slice(&chain.internal_id().to_le_bytes());
    k.push(b'/');
    k.extend_from_slice(external_addr_bytes);
    k
}

pub fn default_algo_for_chain(chain: Chain) -> KeyAlgo {
    match chain {
        Chain::EthereumSecp256k1 => KeyAlgo::Secp256k1,
        Chain::SolanaEd25519 => KeyAlgo::Ed25519,
    }
}

