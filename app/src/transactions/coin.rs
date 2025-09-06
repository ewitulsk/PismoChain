use std::vec;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::{make_key_hash_from_parts, StateReader};
use crate::standards::accounts::{
    get_account_from_signer_state, make_account_object_key, derive_account_addr,
};
use crate::standards::coin::{
    Coin, CoinStore, derive_coin_addr, make_coin_object_key,
    derive_coin_store_addr, make_coin_store_object_key,
    get_coin_from_state, get_coin_store_from_state,
};
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for creating a new token
pub fn build_new_coin_updates(
    name: String,
    project_uri: String,
    logo_uri: String,
    total_supply: u128,
    max_supply: Option<u128>,
    canonical_chain_id: u64,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Get the seed account address - derive from the signing public key
    let seed_addr = derive_account_addr(1, signature_type, &signing_pub_key);
    
    // Derive the coin address (token address) from seed account, name, and chain id
    let coin_addr = derive_coin_addr(&seed_addr, &name, canonical_chain_id);

    // Create the coin object
    let coin = Coin {
        name: name.clone(),
        project_uri,
        logo_uri,
        total_supply,
        max_supply,
        canonical_chain_id,
    };

    // Serialize the coin
    let coin_bytes = <Coin as borsh::BorshSerialize>::try_to_vec(&coin).unwrap();
    
    // Create JMT write for the coin using the coin address as the key
    let jmt_key = make_key_hash_from_parts(coin_addr, b"coin");
    jmt_writes.push((jmt_key, Some(coin_bytes.clone())));
    
    // Create mirror entry for efficient lookups
    let coin_object_key = make_coin_object_key(&coin_addr);
    mirror.push((coin_object_key, coin_bytes));

    // If we have an existing account, increment its nonce
    if let Some(mut account) = get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key) {
        let account_addr = account.account_addr;
        account.increment_nonce();
        
        // Serialize the updated account
        let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let account_jmt_key = make_key_hash_from_parts(account_addr, b"acct");
        jmt_writes.push((account_jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr), account_bytes));
    }

    (jmt_writes, mirror)
}

/// Build writes and app-mirror inserts for minting tokens
pub fn build_mint_updates(
    coin_addr: [u8; 32],
    account_addr: [u8; 32],
    amount: u128,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Check both coin and account existence at the start
    if let (Some(mut coin), Some(mut account)) = (
        get_coin_from_state(state, &coin_addr),
        get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key)
    ) {
        // Increment the account nonce
        let account_addr_local = account.account_addr;
        account.increment_nonce();
        
        // Both coin and account exist, proceed with minting
        
        // Update the coin's total supply
        coin.total_supply = coin.total_supply.saturating_add(amount);

        if let Some(max_supply) = coin.max_supply {
            if coin.total_supply > max_supply{
                return (vec![], vec![]);
            }
        }
        
        
        // Derive the coin store address
        let coin_store_addr = derive_coin_store_addr(&account_addr, &coin_addr);
        
        // Check if coin store exists, create or update it
        let coin_store = if let Some(mut existing_store) = get_coin_store_from_state(state, &coin_store_addr) {
            // Store exists, increment the amount
            existing_store.amount = existing_store.amount.saturating_add(amount);
            existing_store
        } else {
            // Store doesn't exist, create new one
            CoinStore { amount }
        };

        // Serialize and store the updated coin
        let coin_bytes = <Coin as borsh::BorshSerialize>::try_to_vec(&coin).unwrap();
        let coin_jmt_key = make_key_hash_from_parts(coin_addr, b"coin");
        jmt_writes.push((coin_jmt_key, Some(coin_bytes.clone())));
        mirror.push((make_coin_object_key(&coin_addr), coin_bytes));

        // Serialize and store the coin store
        let store_bytes = <CoinStore as borsh::BorshSerialize>::try_to_vec(&coin_store).unwrap();
        let store_jmt_key = make_key_hash_from_parts(coin_store_addr, b"store");
        jmt_writes.push((store_jmt_key, Some(store_bytes.clone())));
        mirror.push((make_coin_store_object_key(&coin_store_addr), store_bytes));
        
        // Serialize the updated account
        let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&account).unwrap();
        let account_jmt_key = make_key_hash_from_parts(account_addr_local, b"acct");
        jmt_writes.push((account_jmt_key, Some(account_bytes.clone())));
        mirror.push((make_account_object_key(&account_addr_local), account_bytes));
    }
    // If either coin or account doesn't exist, don't create any updates

    (jmt_writes, mirror)
}

/// Build writes and app-mirror inserts for transferring tokens between accounts
pub fn build_transfer_updates(
    coin_addr: [u8; 32],
    receiver_addr: [u8; 32],
    amount: u128,
    signing_pub_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader,
    _version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Check both coin and sender account existence at the start
    if let (Some(_coin), Some(mut sender_account)) = (
        get_coin_from_state(state, &coin_addr),
        get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_pub_key)
    ) {
        // Derive sender's account address from their signing public key (CRITICAL SECURITY RULE)
        let sender_account_addr = sender_account.account_addr;
        
        // Increment the sender's account nonce
        sender_account.increment_nonce();
        
        // Derive coin store addresses
        let sender_store_addr = derive_coin_store_addr(&sender_account_addr, &coin_addr);
        let receiver_store_addr = derive_coin_store_addr(&receiver_addr, &coin_addr);
        
        // Check sender's coin store and balance
        if let Some(mut sender_store) = get_coin_store_from_state(state, &sender_store_addr) {
            // Check if sender has sufficient balance
            if sender_store.amount >= amount {
                // Deduct amount from sender's coin store
                sender_store.amount = sender_store.amount.saturating_sub(amount);
                
                // Handle receiver's coin store
                let receiver_store = if let Some(mut existing_store) = get_coin_store_from_state(state, &receiver_store_addr) {
                    // Receiver has existing store, increment the amount
                    existing_store.amount = existing_store.amount.saturating_add(amount);
                    existing_store
                } else {
                    // Receiver doesn't have store, create new one
                    CoinStore { amount }
                };
                
                // Serialize and store the updated sender's coin store
                let sender_store_bytes = <CoinStore as borsh::BorshSerialize>::try_to_vec(&sender_store).unwrap();
                let sender_store_jmt_key = make_key_hash_from_parts(sender_store_addr, b"store");
                jmt_writes.push((sender_store_jmt_key, Some(sender_store_bytes.clone())));
                mirror.push((make_coin_store_object_key(&sender_store_addr), sender_store_bytes));
                
                // Serialize and store the receiver's coin store
                let receiver_store_bytes = <CoinStore as borsh::BorshSerialize>::try_to_vec(&receiver_store).unwrap();
                let receiver_store_jmt_key = make_key_hash_from_parts(receiver_store_addr, b"store");
                jmt_writes.push((receiver_store_jmt_key, Some(receiver_store_bytes.clone())));
                mirror.push((make_coin_store_object_key(&receiver_store_addr), receiver_store_bytes));
                
                // Serialize and store the updated sender's account (with incremented nonce)
                let account_bytes = <crate::standards::accounts::Account as borsh::BorshSerialize>::try_to_vec(&sender_account).unwrap();
                let account_jmt_key = make_key_hash_from_parts(sender_account_addr, b"acct");
                jmt_writes.push((account_jmt_key, Some(account_bytes.clone())));
                mirror.push((make_account_object_key(&sender_account_addr), account_bytes));
                
                println!("✅ Transfer successful: {} tokens from {:?} to {:?}", 
                    amount, hex::encode(&sender_account_addr[..8]), hex::encode(&receiver_addr[..8]));
            } else {
                println!("❌ Transfer failed: Insufficient balance (required: {}, available: {})", amount, sender_store.amount);
            }
        } else {
            println!("❌ Transfer failed: Sender has no coin store for this token");
        }
    } else {
        println!("❌ Transfer failed: Coin or sender account does not exist");
    }

    (jmt_writes, mirror)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standards::accounts::derive_account_addr;
    use crate::standards::coin::{derive_coin_addr, Coin};
    use crate::transactions::SignatureType;

    #[test]
    fn test_coin_address_derivation() {
        let signature_type = SignatureType::SuiDev;
        let signing_pub_key = "test_public_key".to_string();
        let name = "TestCoin".to_string();
        let canonical_chain_id = 4206980085u64;
        
        // Calculate expected coin address
        let seed_addr = derive_account_addr(1, signature_type, &signing_pub_key);
        let coin_addr = derive_coin_addr(&seed_addr, &name, canonical_chain_id);
        
        // Verify the coin address is deterministic
        let coin_addr2 = derive_coin_addr(&seed_addr, &name, canonical_chain_id);
        assert_eq!(coin_addr, coin_addr2, "Coin address should be deterministic");
        
        // Verify different inputs produce different addresses
        let different_name_addr = derive_coin_addr(&seed_addr, "DifferentCoin", canonical_chain_id);
        assert_ne!(coin_addr, different_name_addr, "Different names should produce different addresses");
        
        println!("✅ Coin address derivation test passed!");
        println!("   Coin address: {:?}", hex::encode(coin_addr));
    }

    #[test]
    fn test_coin_serialization() {
        let coin = Coin {
            name: "TestCoin".to_string(),
            project_uri: "https://testcoin.com".to_string(),
            logo_uri: "https://testcoin.com/logo.png".to_string(),
            total_supply: 1_000_000u128,
            max_supply: Some(10_000_000u128),
            canonical_chain_id: 4206980085u64,
        };
        
        // Test Borsh serialization/deserialization
        let serialized = <Coin as borsh::BorshSerialize>::try_to_vec(&coin).unwrap();
        let deserialized = <Coin as borsh::BorshDeserialize>::try_from_slice(&serialized).unwrap();
        
        assert_eq!(coin.name, deserialized.name);
        assert_eq!(coin.project_uri, deserialized.project_uri);
        assert_eq!(coin.logo_uri, deserialized.logo_uri);
        assert_eq!(coin.total_supply, deserialized.total_supply);
        assert_eq!(coin.max_supply, deserialized.max_supply);
        assert_eq!(coin.canonical_chain_id, deserialized.canonical_chain_id);
        
        println!("✅ Coin serialization test passed!");
        println!("   Serialized size: {} bytes", serialized.len());
    }

    #[test]
    fn test_coin_store_derivation() {
        let account_addr = [1u8; 32];
        let coin_addr = [2u8; 32];
        
        // Test deterministic coin store address derivation
        let store_addr1 = derive_coin_store_addr(&account_addr, &coin_addr);
        let store_addr2 = derive_coin_store_addr(&account_addr, &coin_addr);
        assert_eq!(store_addr1, store_addr2, "CoinStore address should be deterministic");
        
        // Test different inputs produce different addresses
        let different_account = [3u8; 32];
        let different_store_addr = derive_coin_store_addr(&different_account, &coin_addr);
        assert_ne!(store_addr1, different_store_addr, "Different accounts should produce different store addresses");
        
        println!("✅ CoinStore address derivation test passed!");
        println!("   Store address: {:?}", hex::encode(store_addr1));
    }
    
}
