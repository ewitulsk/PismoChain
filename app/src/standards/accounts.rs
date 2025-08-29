use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use borsh::maybestd::io;
use std::collections::{BTreeMap, BTreeSet};
use sha3::{Digest, Sha3_256};
use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::KeyHash;

use crate::transactions::{SignerType, SignatureType};

pub type Bytes = Vec<u8>;
pub type AccountAddr = [u8; 32];
pub type PubKey = Bytes;
pub type UnixMillis = u64;
pub type BlockHeight = u64;

#[repr(u8)]
#[derive(Clone, Copy, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum KeyAlgo {
    Secp256k1 = 0,
    Ed25519 = 1,
    Sr25519 = 2,
}

impl SignatureType {
    pub const fn internal_id(self) -> u16 {
        match self {
            SignatureType::PhantomSolanaEd25519 => 2,
            SignatureType::SuiDev => 3,
        }
    }


}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ExternalLink {
    pub signature_type: SignatureType,
    pub account_addr: AccountAddr, // The account address this external link points to
    pub algo: KeyAlgo,
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

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub enum SessionIssuer {
    LinkedKey { signature_type: SignatureType, address: String },
    SessionKey { pubkey: PubKey },
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
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

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Policy {
    pub max_session_lifetime_ms: u64,
    pub require_owner_for: ScopeBits,
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct AccountMeta {
    pub bumped: u8,
    pub frozen: bool
}
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Account {
    pub account_addr: AccountAddr,
    pub links: BTreeSet<ExternalLink>,
    pub sessions: BTreeMap<[u8; 32], SessionKey>,
    pub meta: AccountMeta,
    pub current_nonce: u64
}

impl Account {
    /// Increment the account's nonce by 1, using saturating arithmetic
    pub fn increment_nonce(&mut self) {
        self.current_nonce = self.current_nonce.saturating_add(1);
    }
}

pub fn derive_account_addr(version: u8, signature_type: SignatureType, external_addr_str: &str) -> AccountAddr {
    let external_addr_bytes = external_addr_str.as_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(b"acct");
    hasher.update([version]);
    hasher.update(signature_type.internal_id().to_le_bytes());
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

pub fn make_link_object_key(signature_type: SignatureType, external_addr_str: &str) -> Vec<u8> {
    let external_addr_bytes = external_addr_str.as_bytes();
    let mut k = b"link/".to_vec();
    k.extend_from_slice(&signature_type.internal_id().to_le_bytes());
    k.push(b'/');
    k.extend_from_slice(external_addr_bytes);
    k
}

/// Create a JMT KeyHash for a link object based on signature type and external address
pub fn make_link_jmt_key_hash(signature_type: SignatureType, external_addr_str: &str) -> KeyHash {
    // Create a state key similar to make_link_object_key but for JMT
    let external_addr_bytes = external_addr_str.as_bytes();
    let sig_type_bytes = signature_type.internal_id().to_le_bytes();
    
    // Create a composite address: signature_type_id + "/" + external_address
    let mut combined = Vec::new();
    combined.extend_from_slice(&sig_type_bytes);
    combined.push(b'/');
    combined.extend_from_slice(external_addr_bytes);
    
    // Pad or truncate to 32 bytes for consistent address format
    let mut address = [0u8; 32];
    if combined.len() <= 32 {
        address[..combined.len()].copy_from_slice(&combined);
    } else {
        // Hash if too long
        let mut hasher = Sha3_256::new();
        hasher.update(&combined);
        let digest = hasher.finalize();
        address.copy_from_slice(&digest[..32]);
    }
    
    // Use "link" as the struct tag
    crate::jmt_state::make_key_hash_from_parts(address, b"link")
}

pub fn default_algo_for_signature_type(signature_type: SignatureType) -> KeyAlgo {
    match signature_type {
        SignatureType::PhantomSolanaEd25519 => KeyAlgo::Ed25519,
        SignatureType::SuiDev => KeyAlgo::Ed25519,
    }
}

// Borsh support for ScopeBits (bitflags)
impl borsh::BorshSerialize for ScopeBits {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> std::result::Result<(), io::Error> {
        let bits: u32 = self.bits();
        borsh::BorshSerialize::serialize(&bits, writer)
    }
}

impl borsh::BorshDeserialize for ScopeBits {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> std::result::Result<Self, io::Error> {
        let bits = u32::deserialize_reader(reader)?;
        Ok(ScopeBits::from_bits_truncate(bits))
    }
}

/// Fetch an `Account` by `account_addr` from committed state, using mirror first then JMT fallback.
pub fn get_account<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    address: &AccountAddr,
    ) -> Option<Account> {
    // Try app-level mirror object first
    let mirror_key = make_account_object_key(address);
    if let Some(bytes) = block_tree.app_state(&mirror_key) {
        if let Ok(account) = <Account as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            return Some(account);
        }
    }

    None
}

/// Fetch an `ExternalLink` by signature_type and address from committed state
pub fn get_link_object<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    signature_type: SignatureType,
    address: &str,
) -> Option<ExternalLink> {
    let link_key = make_link_object_key(signature_type, address);
    if let Some(bytes) = block_tree.app_state(&link_key) {
        if let Ok(link) = <ExternalLink as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            return Some(link);
        }
    }
    None
}



/// Fetch an `Account` from a signer address based on signer type
pub fn get_account_from_signer<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    _signer_address: &String,
    signer_type: SignerType,
    signature_type: SignatureType,
    signing_pub_key: &str,
) -> Option<Account> {
    match signer_type {
        SignerType::NewAccount => {
            None
        }
        SignerType::Linked => {
            if let Some(link) = get_link_object(block_tree, signature_type, signing_pub_key) {
                get_account(block_tree, &link.account_addr)
            } else {
                None
            }
        }
        SignerType::Temp => {
            None
        }
    }
}

