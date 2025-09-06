use serde::{Deserialize, Serialize};
use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};
use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;

use crate::types::BorshIndexMap;
use crate::jmt_state::StateReader;

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct Order {
    /// true for buy orders, false for sell orders
    pub is_buy: bool,
    /// Unique identifier for this order
    pub order_id: u128,
    /// Amount of the order
    pub amount: u128,
    /// Account address that placed this order
    pub account: [u8; 32],
}

/// Type alias for a list of order IDs
pub type OrderList = Vec<u128>;

/// Tick structure that separates buy and sell orders at a specific price level
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Tick {
    /// List of buy order IDs at this price level
    pub buy_list: OrderList,
    /// List of sell order IDs at this price level
    pub sell_list: OrderList,
}

impl Tick {
    pub fn new() -> Self {
        Self {
            buy_list: Vec::new(),
            sell_list: Vec::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Orderbook {
    /// Asset being bought (base asset) - coin address
    pub buy_asset: [u8; 32],
    /// Asset being sold (quote asset) - coin address
    pub sell_asset: [u8; 32],
    /// Map of price ticks to tick data (supports 2^64 possible price levels)
    /// Using BorshIndexMap for fast access with deterministic serialization
    pub ticks: BorshIndexMap<u64, Tick>,
    /// Map from order ID to actual order data
    pub orders: BorshIndexMap<u128, Order>,
}

impl Orderbook {
    /// Create a new orderbook for a trading pair
    pub fn new(buy_asset: [u8; 32], sell_asset: [u8; 32]) -> Self {
        Self {
            buy_asset,
            sell_asset,
            ticks: BorshIndexMap::new(),
            orders: BorshIndexMap::new(),
        }
    }

    /// Add an order to the orderbook at the specified price tick
    pub fn add_order(&mut self, tick: u64, order: Order) {
        let order_id = order.order_id;
        let is_buy = order.is_buy;
        self.orders.insert(order_id, order);
        
        let tick_data = self.ticks.entry(tick).or_insert_with(Tick::new);
        if is_buy {
            tick_data.buy_list.push(order_id);
        } else {
            tick_data.sell_list.push(order_id);
        }
    }

    /// Remove an order from the orderbook by order_id and tick
    pub fn remove_order(&mut self, tick: u64, order_id: u128) -> Option<Order> {
        if let Some(order) = self.orders.shift_remove(&order_id) {
            if let Some(tick_data) = self.ticks.get_mut(&tick) {
                // Remove from the appropriate list based on order type
                if order.is_buy {
                    if let Some(pos) = tick_data.buy_list.iter().position(|&id| id == order_id) {
                        tick_data.buy_list.remove(pos);
                    }
                } else {
                    if let Some(pos) = tick_data.sell_list.iter().position(|&id| id == order_id) {
                        tick_data.sell_list.remove(pos);
                    }
                }
            }
            Some(order)
        } else {
            None
        }
    }

    /// Get an order by its ID
    pub fn get_order(&self, order_id: u128) -> Option<&Order> {
        self.orders.get(&order_id)
    }

    /// Get tick data at a specific price tick
    pub fn get_tick_data(&self, tick: u64) -> Option<&Tick> {
        self.ticks.get(&tick)
    }

    /// Get all orders at a specific price tick
    pub fn get_orders_at_tick(&self, tick: u64) -> Vec<&Order> {
        self.ticks
            .get(&tick)
            .map(|tick_data| {
                tick_data.buy_list.iter()
                    .chain(tick_data.sell_list.iter())
                    .filter_map(|&id| self.orders.get(&id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all buy orders across all price ticks
    pub fn get_buy_orders(&self) -> Vec<&Order> {
        self.ticks
            .values()
            .flat_map(|tick_data| {
                tick_data.buy_list.iter()
                    .filter_map(|&id| self.orders.get(&id))
            })
            .collect()
    }

    /// Get all sell orders across all price ticks
    pub fn get_sell_orders(&self) -> Vec<&Order> {
        self.ticks
            .values()
            .flat_map(|tick_data| {
                tick_data.sell_list.iter()
                    .filter_map(|&id| self.orders.get(&id))
            })
            .collect()
    }

    /// Get the best buy price (highest tick with buy orders)
    pub fn best_buy_price(&self) -> Option<u64> {
        // Since IndexMap doesn't guarantee price ordering, we need to find the max price
        self.ticks
            .iter()
            .filter(|(_, tick_data)| !tick_data.buy_list.is_empty())
            .map(|(tick, _)| *tick)
            .max()
    }

    /// Get the best sell price (lowest tick with sell orders)
    pub fn best_sell_price(&self) -> Option<u64> {
        // Since IndexMap doesn't guarantee price ordering, we need to find the min price
        self.ticks
            .iter()
            .filter(|(_, tick_data)| !tick_data.sell_list.is_empty())
            .map(|(tick, _)| *tick)
            .min()
    }

    /// Get the total volume of buy orders at a specific tick
    pub fn get_buy_volume_at_tick(&self, tick: u64) -> u128 {
        self.ticks
            .get(&tick)
            .map(|tick_data| {
                tick_data.buy_list.iter()
                    .filter_map(|&id| self.orders.get(&id))
                    .map(|order| order.amount)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Get the total volume of sell orders at a specific tick
    pub fn get_sell_volume_at_tick(&self, tick: u64) -> u128 {
        self.ticks
            .get(&tick)
            .map(|tick_data| {
                tick_data.sell_list.iter()
                    .filter_map(|&id| self.orders.get(&id))
                    .map(|order| order.amount)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Remove empty tick entries to keep the orderbook clean
    /// We could run this on like every block or every 10 blocks or something
    pub fn cleanup_empty_ticks(&mut self) {
        self.ticks.retain(|_, tick_data| {
            !tick_data.buy_list.is_empty() || !tick_data.sell_list.is_empty()
        });
    }

    /// Get all price ticks that have orders, in insertion order
    pub fn get_active_ticks(&self) -> Vec<u64> {
        self.ticks
            .iter()
            .filter(|(_, tick_data)| {
                !tick_data.buy_list.is_empty() || !tick_data.sell_list.is_empty()
            })
            .map(|(tick, _)| *tick)
            .collect()
    }

    /// Get all price ticks sorted by price (ascending)
    pub fn get_active_ticks_sorted(&self) -> Vec<u64> {
        let mut ticks = self.get_active_ticks();
        ticks.sort_unstable();
        ticks
    }

    /// Get the total number of orders in the orderbook
    pub fn total_order_count(&self) -> usize {
        self.orders.len()
    }

    /// Get the total number of active price ticks
    pub fn active_tick_count(&self) -> usize {
        self.ticks.values().filter(|tick_data| {
            !tick_data.buy_list.is_empty() || !tick_data.sell_list.is_empty()
        }).count()
    }
}

pub type OrderbookAddr = [u8; 32];

/// Generate the orderbook address using Sha3(buy_asset || sell_asset || "spot_orderbook")
pub fn derive_orderbook_addr(buy_asset: &[u8; 32], sell_asset: &[u8; 32]) -> OrderbookAddr {
    let mut hasher = Sha3_256::new();
    hasher.update(buy_asset);
    hasher.update(sell_asset);
    hasher.update(b"spot_orderbook");
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// Create the object key for storing orderbook data in the app state
pub fn make_orderbook_object_key(orderbook_addr: &OrderbookAddr) -> Vec<u8> {
    let mut k = b"orderbook/".to_vec();
    k.extend_from_slice(orderbook_addr);
    k
}

/// Fetch an `Orderbook` by `orderbook_addr` from committed state using the app-level mirror
pub fn get_orderbook<K: KVStore>(
    block_tree: &AppBlockTreeView<'_, K>,
    orderbook_addr: &OrderbookAddr,
) -> Option<Orderbook> {
    get_orderbook_from_state(block_tree, orderbook_addr)
}

pub fn get_orderbook_from_state(
    state: &impl StateReader,
    orderbook_addr: &OrderbookAddr,
) -> Option<Orderbook> {
    let mirror_key = make_orderbook_object_key(orderbook_addr);
    if let Some(bytes) = state.get_mirror_value(&mirror_key) {
        if let Ok(orderbook) = <Orderbook as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            return Some(orderbook);
        }
    }
    None
}

/// Generate a unique order ID based on account address, nonce, amount, and order type
/// This ensures deterministic order ID generation for reproducible state
pub fn generate_order_id(account_addr: &[u8; 32], nonce: u64, amount: u128, is_buy: bool) -> u128 {
    let mut hasher = Sha3_256::new();
    hasher.update(account_addr);
    hasher.update(nonce.to_le_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(&[is_buy as u8]);
    let order_hash = hasher.finalize();
    u128::from_le_bytes(order_hash[..16].try_into().unwrap())
}
