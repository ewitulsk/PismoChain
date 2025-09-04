use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::make_key_hash_from_parts;
use crate::standards::accounts::get_account;
use crate::standards::book_executor::BookExecutor;
use crate::standards::orderbook::{
    Order, Orderbook, get_orderbook, make_orderbook_object_key,
};
use crate::standards::coin::{
    derive_coin_store_addr, get_coin_store, make_coin_store_object_key, CoinStore,
};

/// Result of order execution indicating remaining orders after partial fills
#[derive(Debug)]
pub struct ExecutionRes {
    /// Remaining buy order after execution (None if fully filled)
    pub buy: Option<Order>,
    /// Remaining sell order after execution (None if fully filled)
    pub sell: Option<Order>,
}

/// Build writes and app-mirror inserts for executing a trade between two orders
/// Handles partial fills and returns any remaining orders
pub fn build_execution_updates<K: KVStore>(
    buy_asset_addr: [u8; 32],
    sell_asset_addr: [u8; 32],
    mut buy_order: Order,
    mut sell_order: Order,
    execution_price: u64,
    block_tree: &AppBlockTreeView<'_, K>,
    _version: u64,
) -> (ExecutionRes, Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Verify order types
    if !buy_order.is_buy || sell_order.is_buy {
        println!("❌ Invalid order types for execution");
        return (ExecutionRes { buy: Some(buy_order), sell: Some(sell_order) }, vec![], vec![]);
    }

    // Get both accounts
    let (buyer_account_opt, seller_account_opt) = (
        get_account(block_tree, &buy_order.account),
        get_account(block_tree, &sell_order.account),
    );

    if let (Some(buyer_account), Some(seller_account)) = (buyer_account_opt, seller_account_opt) {
        // Calculate execution amounts
        let execution_amount = buy_order.amount.min(sell_order.amount);
        let total_price = execution_amount * execution_price as u128;

        // Get coin stores
        let buyer_buy_store_addr = derive_coin_store_addr(&buyer_account.account_addr, &buy_asset_addr);
        let buyer_sell_store_addr = derive_coin_store_addr(&buyer_account.account_addr, &sell_asset_addr);
        let seller_buy_store_addr = derive_coin_store_addr(&seller_account.account_addr, &buy_asset_addr);
        let seller_sell_store_addr = derive_coin_store_addr(&seller_account.account_addr, &sell_asset_addr);

        // Check if buyer has sufficient buy_asset (to pay) and seller has sufficient sell_asset
        if let (Some(mut buyer_buy_store), Some(mut seller_sell_store)) = (
            get_coin_store(block_tree, &buyer_buy_store_addr),
            get_coin_store(block_tree, &seller_sell_store_addr),
        ) {
            if buyer_buy_store.amount >= total_price && seller_sell_store.amount >= execution_amount {
                // Execute the trade
                
                // Buyer: pay total_price of buy_asset, receive execution_amount of sell_asset
                buyer_buy_store.amount = buyer_buy_store.amount.saturating_sub(total_price);
                
                let buyer_sell_store = if let Some(mut existing) = get_coin_store(block_tree, &buyer_sell_store_addr) {
                    existing.amount = existing.amount.saturating_add(execution_amount);
                    existing
                } else {
                    CoinStore { amount: execution_amount }
                };

                // Seller: receive total_price of buy_asset, pay execution_amount of sell_asset
                seller_sell_store.amount = seller_sell_store.amount.saturating_sub(execution_amount);
                
                let seller_buy_store = if let Some(mut existing) = get_coin_store(block_tree, &seller_buy_store_addr) {
                    existing.amount = existing.amount.saturating_add(total_price);
                    existing
                } else {
                    CoinStore { amount: total_price }
                };

                // Update coin stores in state
                let stores_to_update = [
                    (buyer_buy_store_addr, buyer_buy_store),
                    (buyer_sell_store_addr, buyer_sell_store),
                    (seller_buy_store_addr, seller_buy_store),
                    (seller_sell_store_addr, seller_sell_store),
                ];

                for (store_addr, store) in stores_to_update {
                    let store_bytes = <CoinStore as borsh::BorshSerialize>::try_to_vec(&store).unwrap();
                    let store_jmt_key = make_key_hash_from_parts(store_addr, b"store");
                    jmt_writes.push((store_jmt_key, Some(store_bytes.clone())));
                    mirror.push((make_coin_store_object_key(&store_addr), store_bytes));
                }

                // Update order amounts for partial fills
                buy_order.amount = buy_order.amount.saturating_sub(execution_amount);
                sell_order.amount = sell_order.amount.saturating_sub(execution_amount);

                println!("✅ Executed trade: {} {} at price {} between {:?} and {:?}", 
                    execution_amount, "tokens", execution_price,
                    hex::encode(&buy_order.account[..8]),
                    hex::encode(&sell_order.account[..8])
                );

                // Return remaining orders (None if fully filled)
                let remaining_buy = if buy_order.amount > 0 { Some(buy_order) } else { None };
                let remaining_sell = if sell_order.amount > 0 { Some(sell_order) } else { None };

                (ExecutionRes { buy: remaining_buy, sell: remaining_sell }, jmt_writes, mirror)
            } else {
                println!("❌ Insufficient balances for trade execution");
                (ExecutionRes { buy: Some(buy_order), sell: Some(sell_order) }, vec![], vec![])
            }
        } else {
            println!("❌ Missing coin stores for trade execution");
            (ExecutionRes { buy: Some(buy_order), sell: Some(sell_order) }, vec![], vec![])
        }
    } else {
        println!("❌ Missing accounts for trade execution");
        (ExecutionRes { buy: Some(buy_order), sell: Some(sell_order) }, vec![], vec![])
    }
}

/// Build writes and app-mirror inserts for processing all changed orderbooks
/// This function implements the orderbook matching engine
pub fn build_executor_updates<K: KVStore>(
    book_executor: &BookExecutor,
    block_tree: &AppBlockTreeView<'_, K>,
    version: u64,
) -> (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>) {
    let mut jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mut mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Get all orderbook addresses that need processing
    let orderbook_addresses = book_executor.get_orderbook_addresses();
    
    for orderbook_addr in orderbook_addresses {
        if let Some(mut orderbook) = get_orderbook(block_tree, &orderbook_addr) {
            // Get all ticks sorted by price (lowest to highest)
            let sorted_ticks = orderbook.get_active_ticks_sorted();
            
            let mut lowest_buy_tick: Option<u64> = None;
            let mut lowest_sell_tick: Option<u64> = None;

            // Process matching logic and track lowest ticks in a single loop
            for &tick in &sorted_ticks {
                // Get order IDs first to avoid borrowing conflicts
                let (buy_ids, sell_ids) = if let Some(tick_data) = orderbook.get_tick_data(tick) {
                    // Track lowest ticks while we're processing
                    if !tick_data.buy_list.is_empty() && lowest_buy_tick.is_none() {
                        lowest_buy_tick = Some(tick);
                    }
                    if !tick_data.sell_list.is_empty() && lowest_sell_tick.is_none() {
                        lowest_sell_tick = Some(tick);
                    }
                    
                    (tick_data.buy_list.clone(), tick_data.sell_list.clone())
                } else {
                    continue;
                };

                // Check for matches within the same tick
                if !buy_ids.is_empty() && !sell_ids.is_empty() {
                    // Same tick match - guaranteed execution
                    let mut buy_idx = 0;
                    let mut sell_idx = 0;
                    
                    while buy_idx < buy_ids.len() && sell_idx < sell_ids.len() {
                        let buy_id = buy_ids[buy_idx];
                        let sell_id = sell_ids[sell_idx];
                        
                        if let (Some(buy_order), Some(sell_order)) = (
                            orderbook.get_order(buy_id).cloned(),
                            orderbook.get_order(sell_id).cloned()
                        ) {
                            // Execute the trade
                            let (exec_result, exec_writes, exec_mirrors) = build_execution_updates(
                                orderbook.buy_asset, 
                                orderbook.sell_asset, 
                                buy_order,
                                sell_order,
                                tick,
                                block_tree,
                                version,
                            );
                            
                            jmt_writes.extend(exec_writes);
                            mirror.extend(exec_mirrors);

                            // Remove executed orders from orderbook
                            orderbook.remove_order(tick, buy_id);
                            orderbook.remove_order(tick, sell_id);

                            // Add back any remaining orders
                            if let Some(remaining_buy) = exec_result.buy {
                                orderbook.add_order(tick, remaining_buy);
                            }
                            if let Some(remaining_sell) = exec_result.sell {
                                orderbook.add_order(tick, remaining_sell);
                            }

                            // Move to next orders
                            buy_idx += 1;
                            sell_idx += 1;
                        } else {
                            break; // Orders not found, exit loop
                        }
                    }
                }
            }

            // Check for cross-tick matches (sell at lower price than buy)
            if let (Some(lowest_sell), Some(lowest_buy)) = (lowest_sell_tick, lowest_buy_tick) {
                if lowest_sell < lowest_buy {
                    // There's a profitable trade opportunity
                    // TODO: Implement cross-tick matching logic
                    println!("🔍 Cross-tick opportunity detected: sell at {} < buy at {}", lowest_sell, lowest_buy);
                }
            }

            // Update the orderbook in state
            let orderbook_bytes = <Orderbook as borsh::BorshSerialize>::try_to_vec(&orderbook).unwrap();
            let orderbook_jmt_key = make_key_hash_from_parts(orderbook_addr, b"orderbook");
            jmt_writes.push((orderbook_jmt_key, Some(orderbook_bytes.clone())));
            mirror.push((make_orderbook_object_key(&orderbook_addr), orderbook_bytes));
        }
    }

    // Clear the changed orderbooks list after processing
    book_executor.clear_changed_orderbooks();

    (jmt_writes, mirror)
}
