use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::{make_key_hash_from_parts, StateReader};
use crate::standards::accounts::get_account_from_signer_state;
use crate::standards::book_executor::BookExecutor;
use crate::standards::orderbook::{
    Order, Orderbook, derive_orderbook_addr, 
    make_orderbook_object_key, get_orderbook_from_state, generate_order_id,
};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for creating a new orderbook
/// Returns (success, (jmt_writes, mirror_inserts, events))
pub fn build_create_orderbook_updates(
    buy_asset: String,
    sell_asset: String,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader,
    book_executor: BookExecutor
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let events: Vec<(String, Vec<u8>)> = Vec::new();

    // Verify account exists
    if get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key).is_none() {
        println!("❌ Account does not exist");
        return (false, (vec![], vec![], vec![]));
    }

    // Convert hex strings to byte arrays
    let buy_asset_bytes = hex::decode(&buy_asset)
        .map_err(|e| println!("❌ Invalid buy_asset hex: {}", e))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            } else {
                println!("❌ buy_asset must be 32 bytes");
                Err(())
            }
        });

    let sell_asset_bytes = hex::decode(&sell_asset)
        .map_err(|e| println!("❌ Invalid sell_asset hex: {}", e))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            } else {
                println!("❌ sell_asset must be 32 bytes");
                Err(())
            }
        });

    let (buy_asset_addr, sell_asset_addr) = match (buy_asset_bytes, sell_asset_bytes) {
        (Ok(buy), Ok(sell)) => (buy, sell),
        _ => {
            println!("❌ Failed to parse asset addresses");
            return (false, (vec![], vec![], vec![]));
        }
    };

    // Derive the orderbook address
    let orderbook_addr = derive_orderbook_addr(&buy_asset_addr, &sell_asset_addr);

    // Check if orderbook already exists
    if get_orderbook_from_state(state, &orderbook_addr).is_some() {
        println!("❌ Orderbook already exists for {:?}/{:?}", hex::encode(&buy_asset_addr[..8]), hex::encode(&sell_asset_addr[..8]));
        return (false, (vec![], vec![], vec![]));
    }

    // Create the orderbook object
    let orderbook = Orderbook::new(buy_asset_addr, sell_asset_addr);

    // Serialize the orderbook
    let orderbook_bytes = <Orderbook as borsh::BorshSerialize>::try_to_vec(&orderbook).unwrap();
    
    // Create JMT write for the orderbook using the orderbook address as the key
    let jmt_key = make_key_hash_from_parts(orderbook_addr, b"orderbook");
    jmt_writes.push((jmt_key, Some(orderbook_bytes.clone())));
    
    // Create mirror entry for efficient lookups
    let orderbook_object_key = make_orderbook_object_key(&orderbook_addr);
    mirror.push((orderbook_object_key, orderbook_bytes));

    // Add orderbook to the BookExecutor for tracking
    book_executor.add_orderbook(&orderbook_addr);

    println!("✅ Created orderbook for {:?}/{:?} at address: {:?}", hex::encode(&buy_asset_addr[..8]), hex::encode(&sell_asset_addr[..8]), hex::encode(&orderbook_addr[..8]));
    
    (true, (jmt_writes, mirror, events))
}

/// Build writes and app-mirror inserts for placing a new limit order
/// Returns (success, (jmt_writes, mirror_inserts, events))
pub fn build_new_limit_order_updates(
    orderbook_address: [u8; 32],
    is_buy: bool,
    amount: u128,
    tick_price: u64,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader,
    book_executor: BookExecutor
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let events: Vec<(String, Vec<u8>)> = Vec::new();

    // Check if orderbook exists and account exists
    if let (Some(mut orderbook), Some(account)) = (
        get_orderbook_from_state(state, &orderbook_address),
        get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key)
    ) {
        let account_addr = account.account_addr;
        
        // Generate a unique order ID using the current nonce
        let order_id = generate_order_id(&account_addr, account.current_nonce, amount, is_buy);
        
        // Create the order
        let order = Order {
            is_buy,
            order_id,
            amount,
            account: account_addr,
        };

        // Add the order to the orderbook at the specified tick price
        orderbook.add_order(tick_price, order);

        // Mark orderbook as changed in the BookExecutor
        book_executor.mark_orderbook_changed(&orderbook_address);

        // Serialize and store the updated orderbook
        let orderbook_bytes = <Orderbook as borsh::BorshSerialize>::try_to_vec(&orderbook).unwrap();
        let orderbook_jmt_key = make_key_hash_from_parts(orderbook_address, b"orderbook");
        jmt_writes.push((orderbook_jmt_key, Some(orderbook_bytes.clone())));
        mirror.push((make_orderbook_object_key(&orderbook_address), orderbook_bytes));

        println!("✅ Added {} order (ID: {}) for {} at tick {} to orderbook: {:?}", 
            if is_buy { "BUY" } else { "SELL"}, 
            order_id,
            amount,
            tick_price,
            hex::encode(&orderbook_address[..8])
        );
        
        (true, (jmt_writes, mirror, events))
    } else {
        println!("❌ Failed to place order: Orderbook or account not found");
        (false, (jmt_writes, mirror, events))
    }
}
