mod database;
mod jmt_state;
mod pismo_app_jmt;
mod transactions;
mod crypto;
mod config;
mod types;
mod standards;
mod utils;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use utils::{
    submit_transactions::submit_transaction,
};
use standards::{
    accounts::Account,
    coin::{Coin, CoinStore},
};
use database::mem_db::MemDB;
use pismo_app_jmt::PismoAppJMT;
use pismo_app_jmt::PismoTransaction;
use config::load_config;
 

// Add Sui SDK imports for signing
use sui_sdk::types::crypto::{SuiKeyPair, get_key_pair_from_rng};
use rand_core::OsRng;

use hotstuff_rs::{
    replica::{Configuration, Replica, ReplicaSpec},
    types::{
        crypto_primitives::VerifyingKey,
        data_types::{ChainID, Power, BufferSize, EpochLength},
        validator_set::{ValidatorSet, ValidatorSetState},
        update_sets::ValidatorSetUpdates,
    },
    networking::{network::Network, messages::Message},
};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
 
use tokio::signal;

use std::{
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    collections::HashMap,
};

use crate::jmt_state::make_key_hash_from_parts;
use jmt::{JellyfishMerkleTree, storage::TreeReader, KeyHash, Version, OwnedValue, storage::{Node, NodeKey, LeafNode}};

 

// Mock network implementation for single node setup
#[derive(Clone)]
struct MockNetwork {
    my_verifying_key: VerifyingKey,
    all_peers: HashMap<VerifyingKey, Sender<(VerifyingKey, Message)>>,
    inbox: Arc<Mutex<Receiver<(VerifyingKey, Message)>>>,
}

impl MockNetwork {
    fn new(verifying_key: VerifyingKey) -> Self {
        let (sender, receiver) = mpsc::channel();
        let mut all_peers = HashMap::new();
        all_peers.insert(verifying_key, sender);
        
        Self {
            my_verifying_key: verifying_key,
            all_peers,
            inbox: Arc::new(Mutex::new(receiver)),
        }
    }
}

impl Network for MockNetwork {
    fn init_validator_set(&mut self, _validator_set: ValidatorSet) {
        // No-op for single node
    }

    fn update_validator_set(&mut self, _updates: ValidatorSetUpdates) {
        // No-op for single node
    }

    fn send(&mut self, peer: VerifyingKey, message: Message) {
        if let Some(peer_sender) = self.all_peers.get(&peer) {
            let _ = peer_sender.send((self.my_verifying_key, message));
        }
    }
    
    fn broadcast(&mut self, message: Message) {
        for (_, peer_sender) in &self.all_peers {
            let _ = peer_sender.send((self.my_verifying_key, message.clone()));
        }
    }

    fn recv(&mut self) -> Option<(VerifyingKey, Message)> {
        match self.inbox.lock().unwrap().try_recv() {
            Ok(message) => Some(message),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }
}

#[tokio::main]
async fn main() {
    println!("🚀 Starting PismoChain Counter App with Transaction Validation...");
    println!("================================================================");
    
    // Load configuration from CONFIG_PATH environment variable or default path
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            eprintln!("💡 Set CONFIG_PATH environment variable or ensure configs/testnet.toml exists");
            std::process::exit(1);
        }
    };

    // Generate signing key for this replica
    let mut rng = OsRng;
    let validator_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
    
    // Convert the Sui keypair to a HotStuff SigningKey using the same underlying Ed25519 key material
    let keypair = crypto::sui_keypair_to_hotstuff_signing_key(&validator_keypair);
    let verifying_key = keypair.verifying_key();
    
    println!("🔑 Generated single Ed25519 keypair used for both validator and consensus:");
    println!("   Validator public key: {:?}", validator_keypair.public());
    println!("   HotStuff verifying key: {:?}", verifying_key.to_bytes());

    // Create the KV store using RocksDB (use default CF for simplicity)
    // let db_path = "./data/pismo_db";
    // let kv_store = RocksDBStore::new(db_path)
    //     .expect("Failed to initialize RocksDB store");

    let kv_store = MemDB::new();

    // Initialize the app state with counter = 0
    let init_app_state = PismoAppJMT::initial_app_state();

    // Initialize validator set with just this replica
    let mut init_vs_updates = ValidatorSetUpdates::new();
    init_vs_updates.insert(verifying_key, Power::new(1));
    
    let mut init_vs = ValidatorSet::new();
    init_vs.apply_updates(&init_vs_updates);
    let init_vs_state = ValidatorSetState::new(init_vs.clone(), init_vs, None, true);

    // Create transaction queue for the counter app
    let tx_queue = Arc::new(Mutex::new(Vec::new()));
    let pismo_app = PismoAppJMT::new(tx_queue.clone(), config.clone());

    // Configure the replica with faster view times
    let configuration = Configuration::builder()
        .me(keypair)
        .chain_id(ChainID::new(4206980085))
        .block_sync_request_limit(10)
        .block_sync_server_advertise_time(Duration::new(10, 0))
        .block_sync_response_timeout(Duration::new(3, 0))
        .block_sync_blacklist_expiry_time(Duration::new(10, 0))
        .block_sync_trigger_min_view_difference(2)
        .block_sync_trigger_timeout(Duration::new(60, 0))
        .progress_msg_buffer_capacity(BufferSize::new(1024))
        .epoch_length(EpochLength::new(50))
        .max_view_time(Duration::from_millis(2000)) // Match test timing requirements
        .log_events(false) // Disable verbose consensus logs
        .build();

    // Initialize replica storage first
    println!("🔧 Initializing replica storage with RocksDB...");
    let kv_store_for_init = kv_store.clone();
    Replica::initialize(kv_store_for_init, init_app_state, init_vs_state);
    println!("✅ Replica storage initialized successfully");
    
    // Give storage a moment to ensure all writes are fully persisted
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Build and start the replica with the original kv_store
    let kv_store_for_rpc = kv_store.clone(); // Clone KV store for RPC access
    let _replica = ReplicaSpec::builder()
        .app(pismo_app)
        .network(MockNetwork::new(verifying_key))
        .kv_store(kv_store)
        .configuration(configuration)
        .build()
        .start();

    println!("✅ PismoChain replica started with transaction validation!");
    println!("📊 Initial counter value: 0");
    println!("================================================================");

    // Start JSON-RPC server to accept transactions (async)
    let server = ServerBuilder::default()
        .build("127.0.0.1:9944")
        .await
        .expect("start jsonrpc server");

    let mut module = RpcModule::new(());
    let txq = tx_queue.clone();
    let expected_chain_id = config.chain_id;
    module
        .register_method("submit_borsh_tx", move |params, _mdata, _ctx| {
            use jsonrpsee::types::ErrorObjectOwned;
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine;
            println!("Recieved TX");

            // Extract single base64 string param (jsonrpsee will auto-convert param errors)
            let b64: String = params.one()?;

            // Decode base64
            let bytes = BASE64.decode(&b64).map_err(|e| {
                println!("❌ Invalid base64 in submit_borsh_tx: {}", e);
                ErrorObjectOwned::owned(-32602, "Invalid params: base64 decode failed", Some(e.to_string()))
            })?;

            println!("Decoded TX");

            // Deserialize Borsh transaction
            let tx: PismoTransaction = <PismoTransaction as borsh::BorshDeserialize>::try_from_slice(&bytes)
                .map_err(|e| {
                    println!("❌ Borsh deserialization failed: {}", e);
                    ErrorObjectOwned::owned(-32602, "Invalid params: Borsh transaction decode failed", Some(e.to_string()))
                })?;

            println!("Tx: {:?}", tx);

            // Submit + verify; surface verification errors to RPC client
            match submit_transaction(txq.clone(), tx, expected_chain_id) {
                Ok(_) => {
                    println!("Successfully submitted transaction");
                    Ok(true)
                }
                Err(e) => {
                    println!("❌ Transaction submission failed: {}", e);
                    Err(ErrorObjectOwned::owned(
                        -32001,
                        "Transaction verification failed",
                        Some(e.to_string()),
                    ))
                }
            }
        })
        .expect("register method");

    // Add view method for querying state using JMT
    let kv_store_for_view = kv_store_for_rpc.clone();
    module
        .register_method("view", move |params, _mdata, _ctx| {
            use jsonrpsee::types::ErrorObjectOwned;
            use serde_json::Value;
            use hotstuff_rs::block_tree::pluggables::KVStore;

            // Simple JMT reader that works directly with KVStore for RPC queries
            struct DirectJMTReader<'a, K: KVStore> {
                kv_store: &'a K,
            }

            impl<'a, K: KVStore> TreeReader for DirectJMTReader<'a, K> {
                fn get_node_option(&self, node_key: &NodeKey) -> anyhow::Result<Option<Node>> {
                    let mut key = Vec::new();
                    key.push(3); // COMMITTED_APP_STATE prefix from HotStuff
                    key.extend_from_slice(b"__jmt_node__");
                    key.extend_from_slice(&bincode::serialize(node_key)?);
                    
                    Ok(self.kv_store.get(&key)
                        .map(|bytes| bincode::deserialize(&bytes))
                        .transpose()?)
                }

                fn get_value_option(&self, max_version: Version, key_hash: KeyHash) -> anyhow::Result<Option<OwnedValue>> {
                    println!("Getting latest value");
                    
                    // Check the latest version index for this key
                    let mut latest_key = Vec::new();
                    latest_key.push(3); // COMMITTED_APP_STATE prefix from HotStuff
                    latest_key.extend_from_slice(b"__jmt_latest__");
                    latest_key.extend_from_slice(&key_hash.0);
                    
                    if let Some(vbytes) = self.kv_store.get(&latest_key) {
                        if vbytes.len() >= 8 {
                            let latest = Version::from_le_bytes(vbytes[..8].try_into()?);
                            
                            if latest <= max_version {
                                let mut value_key = Vec::new();
                                value_key.push(3); // COMMITTED_APP_STATE prefix from HotStuff
                                value_key.extend_from_slice(b"__jmt_value__");
                                value_key.extend_from_slice(&latest.to_le_bytes());
                                value_key.extend_from_slice(&key_hash.0);
                                return Ok(self.kv_store.get(&value_key));
                            }
                        }
                    }
                    Ok(None)
                }

                fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
                    Ok(None) // Not needed for simple queries
                }
            }

            // Parse parameters: {"address": "hex_string", "type": "Account|Coin|CoinStore"}
            let params_obj: Value = params.parse()?;
            
            let address_hex = params_obj.get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'address' parameter", None::<String>))?;
                
            let struct_type = params_obj.get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'type' parameter", None::<String>))?;

            // Decode hex address to bytes
            let address_bytes = hex::decode(address_hex).map_err(|e| {
                ErrorObjectOwned::owned(-32602, "Invalid hex address", Some(e.to_string()))
            })?;

            if address_bytes.len() != 32 {
                return Err(ErrorObjectOwned::owned(-32602, "Address must be 32 bytes", None::<String>));
            }

            let address: [u8; 32] = address_bytes.try_into().unwrap();
            println!("View looking for address: {:?}", address);

            // Create JMT reader and tree directly with KVStore
            let reader = DirectJMTReader { kv_store: &kv_store_for_view };
            let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
            
            // Use u64::MAX as version to get the latest committed value
            let version = u64::MAX;

            // Query based on struct type using JMT
            let result = match struct_type {
                "Account" => {
                    // Create JMT key hash for account
                    let key_hash = make_key_hash_from_parts(address, b"acct");
                    
                    println!("Looking for account with key_hash: {:?}", key_hash);
                    
                    match tree.get(key_hash, version) {
                        Ok(Some(bytes)) => {
                            match <Account as borsh::BorshDeserialize>::try_from_slice(&bytes) {
                                Ok(account) => serde_json::to_value(&account).map_err(|e| {
                                    ErrorObjectOwned::owned(-32001, "Failed to serialize Account", Some(e.to_string()))
                                })?,
                                Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to deserialize Account", Some(e.to_string()))),
                            }
                        }
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to query JMT", Some(e.to_string()))),
                    }
                }
                "Coin" => {
                    // Create JMT key hash for coin
                    let key_hash = make_key_hash_from_parts(address, b"coin");
                    
                    match tree.get(key_hash, version) {
                        Ok(Some(bytes)) => {
                            match <Coin as borsh::BorshDeserialize>::try_from_slice(&bytes) {
                                Ok(coin) => serde_json::to_value(&coin).map_err(|e| {
                                    ErrorObjectOwned::owned(-32001, "Failed to serialize Coin", Some(e.to_string()))
                                })?,
                                Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to deserialize Coin", Some(e.to_string()))),
                            }
                        }
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to query JMT", Some(e.to_string()))),
                    }
                }
                "CoinStore" => {
                    // Create JMT key hash for coin store
                    let key_hash = make_key_hash_from_parts(address, b"store");
                    
                    match tree.get(key_hash, version) {
                        Ok(Some(bytes)) => {
                            match <CoinStore as borsh::BorshDeserialize>::try_from_slice(&bytes) {
                                Ok(coin_store) => serde_json::to_value(&coin_store).map_err(|e| {
                                    ErrorObjectOwned::owned(-32001, "Failed to serialize CoinStore", Some(e.to_string()))
                                })?,
                                Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to deserialize CoinStore", Some(e.to_string()))),
                            }
                        }
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to query JMT", Some(e.to_string()))),
                    }
                }
                _ => {
                    return Err(ErrorObjectOwned::owned(-32602, "Unsupported type. Use: Account, Coin, or CoinStore", None::<String>));
                }
            };

            Ok(result)
        })
        .expect("register view method");

    let server_handle = server.start(module);
    println!("🔌 JSON-RPC server listening on http://127.0.0.1:9944");
    println!("   Methods: submit_borsh_tx, view");

    // Keep the node alive using tokio::select! (exit on RPC stop or ctrl-c)
    tokio::select! {
        _ = server_handle.stopped() => {
            println!("🛑 JSON-RPC server stopped");
        }
        _ = signal::ctrl_c() => {
            println!("👋 Caught ctrl-c, shutting down");
        }
    }
}
