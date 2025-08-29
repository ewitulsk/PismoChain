use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::make_key_hash_from_parts;
use crate::standards::accounts::{
    get_account_from_signer, make_account_object_key,
};
use crate::standards::orderbook::{
    Order, Orderbook, derive_orderbook_addr, 
    make_orderbook_object_key, get_orderbook, generate_order_id,
};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for creating a new orderbook
pub fn build_create_orderbook_updates<K: KVStore>(
    buy_asset: String,
    sell_asset: String,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Increment the account nonce
    if let Some(mut account) = get_account_from_signer(block_tree, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key) {
        let account_addr = account.account_addr;
        account.increment_nonce();
        
        // Serialize the updated account
        let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let account_jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((account_jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));
    }

    // Derive the orderbook address
    let orderbook_addr = derive_orderbook_addr(&buy_asset, &sell_asset);

    // Check if orderbook already exists
    if get_orderbook(block_tree, &orderbook_addr).is_some() {
        println!("❌ Orderbook already exists for {}/{}", buy_asset, sell_asset);
        return (vec![], vec![]);
    }

    // Create the orderbook object
    let orderbook = Orderbook::new(buy_asset.clone(), sell_asset.clone());

    // Serialize the orderbook
    let orderbook_bytes = <Orderbook as borsh::BorshSerialize>::try_to_vec(&orderbook).unwrap();
    
    // Create JMT write for the orderbook using the orderbook address as the key
    let jmt_key = make_key_hash_from_parts(orderbook_addr, b"orderbook");
    jmt_writes.push((jmt_key, Some(orderbook_bytes.clone())));
    
    // Create mirror entry for efficient lookups
    let orderbook_object_key = make_orderbook_object_key(&orderbook_addr);
    mirror.push((orderbook_object_key, orderbook_bytes));

    println!("✅ Created orderbook for {}/{} at address: {:?}", buy_asset, sell_asset, hex::encode(&orderbook_addr[..8]));
    
    (jmt_writes, mirror)
}

/// Build writes and app-mirror inserts for placing a new limit order
pub fn build_new_limit_order_updates<K: KVStore>(
    orderbook_address: [u8; 32],
    is_buy: bool,
    amount: u128,
    tick_price: u64,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Check if orderbook exists and account exists
    if let (Some(mut orderbook), Some(mut account)) = (
        get_orderbook(block_tree, &orderbook_address),
        get_account_from_signer(block_tree, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key)
    ) {
        account.increment_nonce();
        let account_addr = account.account_addr;
        
        // Generate a unique order ID using the current nonce (before incrementing)
        let order_id = generate_order_id(&account_addr, account.current_nonce, amount, is_buy);
        
        // Create the order
        let order = Order {
            is_buy,
            order_id,
            amount,
        };

        // Add the order to the orderbook at the specified tick price
        orderbook.add_order(tick_price, order);

        // Serialize and store the updated orderbook
        let orderbook_bytes = <Orderbook as borsh::BorshSerialize>::try_to_vec(&orderbook).unwrap();
        let orderbook_jmt_key = make_key_hash_from_parts(orderbook_address, b"orderbook");
        jmt_writes.push((orderbook_jmt_key, Some(orderbook_bytes.clone())));
        mirror.push((make_orderbook_object_key(&orderbook_address), orderbook_bytes));

        // Serialize the updated account
        let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let account_jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((account_jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));

        println!("✅ Added {} order (ID: {}) for {} at tick {} to orderbook: {:?}", 
            if is_buy { "BUY" } else { "SELL"}, 
            order_id,
            amount,
            tick_price,
            hex::encode(&orderbook_address[..8])
        );
    } else {
        println!("❌ Failed to place order: Orderbook or account not found");
    }

    (jmt_writes, mirror)
}
