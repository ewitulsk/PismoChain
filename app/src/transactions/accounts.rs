use std::collections::BTreeMap;

use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::{make_key_hash_from_parts, StateReader};
use crate::standards::accounts::{
    Account, AccountMeta, ExternalLink, Policy, ScopeBits,
    default_algo_for_signature_type, derive_account_addr, make_account_object_key, make_link_object_key,
    get_account_from_signer_state, make_link_jmt_key_hash,
};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for creating a new account
/// Returns (success, (jmt_writes, mirror_inserts))
pub fn build_create_account_updates(
    signature_type: SignatureType,
    signing_pub_key: String,
    _signer_type: SignerType,
    _state: &impl StateReader
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>)) {
    let account_addr = derive_account_addr(1, signature_type, &signing_pub_key);
    let account_addr_hex = hex::encode(account_addr);
    println!("Creating account at address: {:?} (hex: {})", account_addr, account_addr_hex);
    let link = ExternalLink {
        signature_type,
        account_addr,
        algo: default_algo_for_signature_type(signature_type),
    };

    let mut links = std::collections::BTreeSet::new();
    links.insert(link.clone());

    let account = Account {
        account_addr,
        links,
        sessions: BTreeMap::new(),
        meta: AccountMeta { bumped: 0, frozen: false },
        current_nonce: 0
    };

    let account_bytes = <Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
    let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
    
    // Create link object for JMT storage - use external signer address for key derivation
    let link_val = <ExternalLink as borsh::BorshSerialize>::try_to_vec(&link).unwrap();
    let link_jmt_key = make_link_jmt_key_hash(signature_type, &signing_pub_key);
    
    let jmt_writes = vec![
        (jmt_key, Some(account_bytes.clone())),
        (link_jmt_key, Some(link_val.clone()))
    ];

    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    mirror.push((make_account_object_key(&account_addr), account_bytes));
    let link_key = make_link_object_key(signature_type, &signing_pub_key);
    mirror.push((link_key, link_val));

    (true, (jmt_writes, mirror))
}

/// Build writes and app-mirror inserts for linking a new external address
/// This function handles all the logic including nonce increment
/// Returns (success, (jmt_writes, mirror_inserts))
pub fn build_link_account_updates(
    signing_pub_key: String,
    external_wallet: &str,
    signature_type: SignatureType,
    signer_address: &str,
    signer_type: SignerType,
    state: &impl StateReader
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>)) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    if let Some(mut account) = get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key) {
        let account_addr = account.account_addr;
        account.increment_nonce();
        
        // Add the new external link
        let link = ExternalLink {
            signature_type,
            account_addr,
            algo: default_algo_for_signature_type(signature_type),
        };
        account.links.insert(link.clone());
        
        // Serialize the updated account
        let account_bytes = <Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));

        // Create the link object for both JMT and mirror storage - use external wallet address for key derivation
        let link_val = <ExternalLink as borsh::BorshSerialize>::try_to_vec(&link).unwrap();
        let link_jmt_key = make_link_jmt_key_hash(signature_type, external_wallet);
        jmt_writes.push((link_jmt_key, Some(link_val.clone())));
        
        let link_key = make_link_object_key(signature_type, external_wallet);
        mirror.push((link_key, link_val));
        
        (true, (jmt_writes, mirror))
    } else {
        (false, (jmt_writes, mirror))
    }
}


