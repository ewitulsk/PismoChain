//! Transaction execution module
//! 
//! This module handles the execution of individual transactions by delegating
//! to the appropriate transaction builder functions and applying the resulting
//! state changes to the pending block state.

use hotstuff_rs::{
    block_tree::{accessors::app::AppBlockTreeView, pluggables::KVStore},
};

use crate::{
    config::Config,
    jmt_state::PendingBlockState,
    pismo_app_jmt::{PismoOperation, PismoTransaction},
    standards::book_executor::BookExecutor,
    transactions::{
        accounts::{build_create_account_updates, build_link_account_updates},
        noop::build_noop_updates,
        coin::{build_new_coin_updates, build_mint_updates, build_transfer_updates},
        orderbook::{build_create_orderbook_updates, build_new_limit_order_updates},
        onramp::build_onramp_updates,
        SignerType,
    },
};

/// Execute a single transaction and apply its state changes to the pending block state
/// 
/// This function handles the verification and execution of individual transactions by first
/// verifying the transaction (signature, chain ID, nonce) and then delegating to the
/// appropriate transaction builder functions to apply the resulting state changes.
/// 
/// # Arguments
/// * `transaction` - The transaction to execute
/// * `config` - The application configuration
/// * `block_tree` - The block tree view for state queries during verification
/// * `pending_state` - The pending block state to apply changes to
/// * `book_executor` - The orderbook executor for trading operations
/// * `version` - The JMT version for this transaction
/// 
/// # Returns
/// Returns `true` if the transaction was executed successfully, `false` if it was skipped or failed verification
pub fn execute_transaction<K: KVStore>(
    transaction: &PismoTransaction,
    config: &Config,
    block_tree: &AppBlockTreeView<'_, K>,
    pending_state: &mut PendingBlockState<K>, //We should probably make sure that each of the build_[]_updates methods can't modify version
    book_executor: &BookExecutor
) -> bool {
    // First, perform transaction verification (chain id + signature + nonce checks)
    match transaction.verify_with_state(config.chain_id, block_tree, pending_state.version) {
        Ok(true) => {}
        Ok(false) => {
            println!("❌ Tx rejected by verification (chain_id/signature/nonce)");
            return false;
        }
        Err(e) => {
            println!("❌ Tx verification error: {}", e);
            return false;
        }
    }

    let signing_pub_key = transaction.public_key.clone();
    let signer_type = transaction.signer_type;
    let signer_address = &transaction.signer;
    let signature_type = transaction.signature_type;

    // Skip non-CreateAccount transactions with NewAccount signer type
    match (&transaction.payload, signer_type) {
        (PismoOperation::CreateAccount, _) => {
            // CreateAccount is allowed with any signer type
        }
        (_, SignerType::NewAccount) => {
            println!("❌ Skipping non-CreateAccount transaction with NewAccount signer type");
            return false;
        }
        _ => {
            // Other combinations are allowed
        }
    }

    // Execute the transaction based on its payload type
    match &transaction.payload {
        PismoOperation::Onramp(vaa, guardian_set_index) => {
            let (success, (writes, mirrors, events)) = build_onramp_updates(
                vaa, 
                *guardian_set_index, 
                config, 
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::CreateAccount => {
            let (success, (writes, mirrors, events)) = build_create_account_updates(
                signature_type, 
                signing_pub_key, 
                signer_type, 
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::LinkAccount { external_wallet } => {
            let (success, (writes, mirrors, events)) = build_link_account_updates(
                signing_pub_key, 
                external_wallet, 
                signature_type, 
                signer_address, 
                signer_type, 
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::NoOp => {
            let (success, (writes, mirrors, events)) = build_noop_updates(
                signing_pub_key, 
                signer_address, 
                signer_type, 
                signature_type, 
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::NewCoin { 
            name, 
            project_uri, 
            logo_uri, 
            total_supply, 
            max_supply, 
            canonical_chain_id 
        } => {
            let (success, (writes, mirrors, events)) = build_new_coin_updates(
                name.clone(),
                project_uri.clone(),
                logo_uri.clone(),
                *total_supply,
                *max_supply,
                *canonical_chain_id,
                signing_pub_key,
                signer_address,
                signer_type,
                signature_type,
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::Mint { coin_addr, account_addr, amount } => {
            let (success, (writes, mirrors, events)) = build_mint_updates(
                *coin_addr,
                *account_addr,
                *amount,
                signing_pub_key,
                signer_address,
                signer_type,
                signature_type,
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::Transfer { coin_addr, receiver_addr, amount } => {
            let (success, (writes, mirrors, events)) = build_transfer_updates(
                *coin_addr,
                *receiver_addr,
                *amount,
                signing_pub_key,
                signer_address,
                signer_type,
                signature_type,
                pending_state
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::CreateOrderbook { buy_asset, sell_asset } => {
            let (success, (writes, mirrors, events)) = build_create_orderbook_updates(
                buy_asset.clone(),
                sell_asset.clone(),
                signing_pub_key,
                signer_address,
                signer_type,
                signature_type,
                pending_state,
                book_executor.clone()
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
        
        PismoOperation::NewLimitOrder { 
            orderbook_address, 
            is_buy, 
            amount, 
            tick_price 
        } => {
            let (success, (writes, mirrors, events)) = build_new_limit_order_updates(
                *orderbook_address,
                *is_buy,
                *amount,
                *tick_price,
                signing_pub_key,
                signer_address,
                signer_type,
                signature_type,
                pending_state,
                book_executor.clone()
            );
            if !success {
                return false;
            }
            pending_state.apply_jmt_writes(writes);
            pending_state.apply_mirror_inserts(mirrors);
            pending_state.apply_events(events);
        }
    }

    pending_state.version += 1;

    true // Transaction executed successfully
}
