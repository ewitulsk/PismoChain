use jmt::{KeyHash, OwnedValue};
use borsh::BorshSerialize;

use crate::jmt_state::{make_key_hash_from_parts, make_offramp_event_key_hash, StateReader};
use crate::standards::accounts::get_account_from_signer_state;
use crate::standards::coin::{
    Coin, CoinStore, derive_coin_store_addr, make_coin_object_key,
    make_coin_store_object_key, get_coin_from_state, get_coin_store_from_state,
};
use crate::transactions::{SignerType, SignatureType};
use crate::events::OfframpEvent;

/// Build writes and app-mirror inserts for processing an offramp transaction
/// Returns (success, (jmt_writes, mirror_inserts, events))
pub fn build_offramp_updates(
    amount: u64,
    coin_addr: [u8; 32],
    recipient_addr: [u8; 32],
    destination_chain: u16,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    version: u64,
    event_index: u32,
    state: &impl StateReader
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut events: Vec<(String, Vec<u8>)> = Vec::new();

    // Step 1: Get the coin from state
    let mut coin = match get_coin_from_state(state, &coin_addr) {
        Some(c) => c,
        None => {
            println!("❌ Offramp failed: Coin does not exist");
            return (false, (vec![], vec![], vec![]));
        }
    };

    // Step 2: Validate that the coin is a bridged coin with matching canonical_chain_id
    if coin.canonical_chain_id != destination_chain as u64 {
        println!("❌ Offramp failed: Coin canonical_chain_id ({}) does not match destination_chain ({})", 
            coin.canonical_chain_id, destination_chain);
        return (false, (vec![], vec![], vec![]));
    }

    // Step 3: Get the signer's account to derive their account address
    let sender_account = match get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key) {
        Some(acc) => acc,
        None => {
            println!("❌ Offramp failed: Sender account does not exist");
            return (false, (vec![], vec![], vec![]));
        }
    };
    let sender_account_addr = sender_account.account_addr;

    // Step 4: Derive the sender's coin store address
    let sender_store_addr = derive_coin_store_addr(&sender_account_addr, &coin_addr);

    // Step 5: Get the sender's coin store
    let mut sender_store = match get_coin_store_from_state(state, &sender_store_addr) {
        Some(store) => store,
        None => {
            println!("❌ Offramp failed: Sender has no coin store for this token");
            return (false, (vec![], vec![], vec![]));
        }
    };

    // Step 6: Check if sender has sufficient balance
    if sender_store.amount < amount as u128 {
        println!("❌ Offramp failed: Insufficient balance (required: {}, available: {})", 
            amount, sender_store.amount);
        return (false, (vec![], vec![], vec![]));
    }

    // Step 7: Decrement the sender's coin store amount (burn from user)
    sender_store.amount = sender_store.amount.saturating_sub(amount as u128);

    // Step 8: Decrement the coin's total supply (burn from total supply)
    coin.total_supply = coin.total_supply.saturating_sub(amount as u128);

    // Step 9: Serialize and store the updated coin
    let coin_bytes = <Coin as borsh::BorshSerialize>::try_to_vec(&coin).unwrap();
    let coin_jmt_key = make_key_hash_from_parts(coin_addr, b"coin");
    jmt_writes.push((coin_jmt_key, Some(coin_bytes.clone())));
    mirror.push((make_coin_object_key(&coin_addr), coin_bytes));

    // Step 10: Serialize and store the updated coin store
    let store_bytes = <CoinStore as borsh::BorshSerialize>::try_to_vec(&sender_store).unwrap();
    let store_jmt_key = make_key_hash_from_parts(sender_store_addr, b"store");
    jmt_writes.push((store_jmt_key, Some(store_bytes.clone())));
    mirror.push((make_coin_store_object_key(&sender_store_addr), store_bytes));

    // Step 11: Create and emit the OfframpEvent
    let offramp_event = OfframpEvent {
        amount,
        coin_address: coin_addr,
        recipient_address: recipient_addr,
        destination_chain,
    };
    let offramp_event_bytes = offramp_event.try_to_vec().unwrap();
    events.push(("Offramp".to_string(), offramp_event_bytes.clone()));

    // Step 12: Store the offramp event in JMT for inclusion proof generation
    // This allows external chains to cryptographically verify the offramp transaction
    let offramp_event_key_hash = make_offramp_event_key_hash(version, event_index);
    jmt_writes.push((offramp_event_key_hash, Some(offramp_event_bytes)));

    println!("✅ Offramp successful: {} tokens burned from {:?} for bridge to chain {} (version={}, event_index={})", 
        amount, 
        hex::encode(&sender_account_addr[..8]),
        destination_chain,
        version,
        event_index);

    (true, (jmt_writes, mirror, events))
}

