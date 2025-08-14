use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use borsh::maybestd::io;
use std::collections::{BTreeMap, BTreeSet};
use sha3::{Digest, Sha3_256};
use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;

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

    pub const fn internal_prefix(self) -> &'static str {
        match self {
            SignatureType::PhantomSolanaEd25519 => "sol",
            SignatureType::SuiDev => "sui",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ExternalLink {
    pub signature_type: SignatureType,
    pub address: String,
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
    pub guardian_quorum: u8,
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct AccountMeta {
    pub created_at: UnixMillis,
    pub bumped: u8,
    pub frozen: bool
}
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Account {
    pub account_addr: AccountAddr,
    pub links: BTreeSet<ExternalLink>,
    pub sessions: BTreeMap<[u8; 32], SessionKey>,
    pub policy: Policy,
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

/// Derive a link address from a signer address by extracting the address part
/// Expects signer_address format: "signature_type_prefix:actual_address"
pub fn derive_link_address(signer_address: &str, signature_type: SignatureType) -> Option<String> {
    let prefix = signature_type.internal_prefix();
    let expected_prefix = format!("{}:", prefix);
    
    if signer_address.starts_with(&expected_prefix) {
        Some(signer_address[expected_prefix.len()..].to_string())
    } else {
        None
    }
}

/// Fetch an `Account` from a signer address based on signer type
pub fn get_account_from_signer<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    signer_address: &String,
    signer_type: SignerType,
    signature_type: SignatureType,
    _signing_pub_key: &str,
) -> Option<Account> {
    match signer_type {
        SignerType::NewAccount => {
            None
        }
        SignerType::Linked => {
            // Extract the actual address from the signer address and get the link object
            if let Some(link_address) = derive_link_address(signer_address, signature_type) {
                if let Some(_link) = get_link_object(block_tree, signature_type, &link_address) {
                    let account_addr = derive_account_addr(1, signature_type, &link_address);
                    get_account(block_tree, &account_addr)
                } else {
                    None
                }
            } else {
                None
            }
        }
        SignerType::Temp => {
            // Return None for temporary signers as requested
            None
        }
    }
}

