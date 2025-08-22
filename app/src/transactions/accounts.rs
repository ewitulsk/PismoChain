use std::collections::BTreeMap;

use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::make_key_hash_from_parts;
use crate::standards::accounts::{
    Account, AccountMeta, ExternalLink, Policy, ScopeBits,
    default_algo_for_signature_type, derive_account_addr, make_account_object_key, make_link_object_key,
    get_account_from_signer,
};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for creating a new account
pub fn build_create_account_updates<K: KVStore>(
    signature_type: SignatureType,
    signing_pub_key: String,
    created_at_ms: u64,
    _signer_type: SignerType,
    _block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let account_addr = derive_account_addr(1, signature_type, &signing_pub_key);
    let account_addr_hex = hex::encode(account_addr);
    println!("Creating account at address: {:?} (hex: {})", account_addr, account_addr_hex);
    let link = ExternalLink {
        signature_type,
        address: signing_pub_key.clone(),
        algo: default_algo_for_signature_type(signature_type),
        added_at: created_at_ms,
    };

    let mut links = std::collections::BTreeSet::new();
    links.insert(link.clone());

    let account = Account {
        account_addr,
        links,
        sessions: BTreeMap::new(),
        policy: Policy {
            max_session_lifetime_ms: 1000 * 60 * 60 * 24 * 30, // 30d
            require_owner_for: ScopeBits::ACCOUNT_ADMIN,
            guardian_quorum: 0,
        },
        meta: AccountMeta { created_at: created_at_ms, bumped: 0, frozen: false },
        current_nonce: 0
    };

    let account_bytes = <Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
    let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
    println!("Made account at key_hash: {:?}", jmt_key);
    let jmt_writes = vec![(jmt_key, Some(account_bytes.clone()))];

    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    mirror.push((make_account_object_key(&account_addr), account_bytes));
    let link_key = make_link_object_key(signature_type, &signing_pub_key);
    let link_val = <ExternalLink as borsh::BorshSerialize>::try_to_vec(&link).unwrap();
    mirror.push((link_key, link_val));

    (jmt_writes, mirror)
}

/// Build writes and app-mirror inserts for linking a new external address
/// This function handles all the logic including nonce increment
pub fn build_link_account_updates<K: KVStore>(
    signing_pub_key: String,
    external_wallet: &str,
    signature_type: SignatureType,
    signer_address: &str,
    signer_type: SignerType,
    added_at_ms: u64,
    block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    if let Some(mut account) = get_account_from_signer(block_tree, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key) {
        let account_addr = account.account_addr;
        account.increment_nonce();
        
        // Add the new external link
        let link = ExternalLink {
            signature_type,
            address: external_wallet.to_string(),
            algo: default_algo_for_signature_type(signature_type),
            added_at: added_at_ms,
        };
        account.links.insert(link.clone());
        
        // Serialize the updated account
        let account_bytes = <Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));

        // Create the link object
        let link_key = make_link_object_key(signature_type, external_wallet);
        let link_val = <ExternalLink as borsh::BorshSerialize>::try_to_vec(&link).unwrap();
        mirror.push((link_key, link_val));
    }

    (jmt_writes, mirror)
}


