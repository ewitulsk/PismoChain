use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::{make_key_hash_from_parts, StateReader};
use crate::standards::accounts::{get_account_from_signer, get_account_from_signer_state, make_account_object_key};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for a NoOp transaction
/// This function only increments the account nonce without making any other changes
/// Returns (success, (jmt_writes, mirror_inserts, events))
pub fn build_noop_updates(
    signing_public_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let events: Vec<(String, Vec<u8>)> = Vec::new();

    if let Some(mut account) = get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_public_key) {
        let account_addr = account.account_addr;
        // Only increment the nonce - no other changes
        account.increment_nonce();
        
        // Serialize the updated account
        let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));
        
        (true, (jmt_writes, mirror, events))
    } else {
        (false, (jmt_writes, mirror, events))
    }
}
