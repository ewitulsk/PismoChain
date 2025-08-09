use std::collections::BTreeMap;

use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::{get_jmt_value, make_key_hash_from_parts};
use crate::standards::accounts::{
    Account, AccountAddr, AccountMeta, Chain, ExternalLink, Policy, ScopeBits, Link,
    default_algo_for_chain, derive_account_addr, make_account_object_key, make_link_object_key,
};

/// Build writes and app-mirror inserts for creating a new account
pub fn build_create_account_updates<K: KVStore>(
    chain: Chain,
    external_addr: Vec<u8>,
    created_at_ms: u64,
    block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let account_addr = derive_account_addr(1, chain, &external_addr);

    let link = ExternalLink {
        chain,
        address: external_addr.clone(),
        algo: default_algo_for_chain(chain),
        added_at: created_at_ms,
    };

    let mut links = std::collections::BTreeSet::new();
    links.insert(link);

    let account = Account {
        account_addr,
        links,
        sessions: BTreeMap::new(),
        scope_nonces: BTreeMap::new(),
        policy: Policy {
            max_session_lifetime_ms: 1000 * 60 * 60 * 24 * 30, // 30d
            require_owner_for: ScopeBits::ACCOUNT_ADMIN,
            guardian_quorum: 0,
        },
        meta: AccountMeta { created_at: created_at_ms, bumped: 0, frozen: false, current_nonce: 0 },
    };

    let account_bytes = bcs::to_bytes(&account).unwrap();
    let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
    let mut jmt_writes = vec![(jmt_key, Some(account_bytes.clone()))];

    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    mirror.push((make_account_object_key(&account_addr), account_bytes));
    let link_key = make_link_object_key(chain, &external_addr);
    let link_val = bcs::to_bytes(&Link { account_addr }).unwrap();
    mirror.push((link_key, link_val));

    (jmt_writes, mirror)
}

/// Build writes and app-mirror inserts for linking a new external address
pub fn build_link_account_updates<K: KVStore>(
    account_addr: AccountAddr,
    chain: Chain,
    external_addr: Vec<u8>,
    added_at_ms: u64,
    block_tree: &AppBlockTreeView<'_, K>,
    version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let jmt_key = make_key_hash_from_parts(account_addr, b"acct");
    let existing = get_jmt_value(block_tree, jmt_key, version.saturating_sub(1)).ok().flatten();
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    if let Some(bytes) = existing {
        if let Ok(mut account) = bcs::from_bytes::<Account>(&bytes) {
            let link = ExternalLink {
                chain,
                address: external_addr.clone(),
                algo: default_algo_for_chain(chain),
                added_at: added_at_ms,
            };
            account.links.insert(link);
            let account_bytes = bcs::to_bytes(&account).unwrap();
            jmt_writes.push((jmt_key, Some(account_bytes.clone())));
            mirror.push((make_account_object_key(&account_addr), account_bytes));

            let link_key = make_link_object_key(chain, &external_addr);
            let link_val = bcs::to_bytes(&Link { account_addr }).unwrap();
            mirror.push((link_key, link_val));
        }
    }

    (jmt_writes, mirror)
}


