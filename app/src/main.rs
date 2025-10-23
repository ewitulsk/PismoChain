mod database;
mod jmt_state;
mod pismo_app_jmt;
mod transactions;
mod config;
mod types;
mod standards;
mod utils;
mod validator_keys;
mod execution;
mod networking;
mod events;
mod grpc;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use utils::{
    submit_transactions::submit_transaction,
};
use standards::{
    accounts::{Account, ExternalLink, make_link_jmt_key_hash},
    coin::{Coin, CoinStore},
};
use transactions::SignatureType;
use pismo_app_jmt::PismoAppJMT;
use pismo_app_jmt::PismoTransaction;
use config::load_config;
 
use tracing::error;

use validator_keys::{load_validator_keys, save_validator_keys, generate_validator_keypair};

use hotstuff_rs::{
    replica::{Configuration, Replica, ReplicaSpec},
    types::{
        crypto_primitives::VerifyingKey,
        data_types::{ChainID, Power, BufferSize, EpochLength},
        validator_set::{ValidatorSet, ValidatorSetState},
        update_sets::ValidatorSetUpdates,
    },
};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
 
use tokio::signal;


use crate::{
    database::rocks_db::RocksDBStore, events::{get_events_range, get_transactions_range, store_events, store_transaction, CommittedEvents, Event}, jmt_state::{make_key_hash_from_parts, DirectJMTReader}, networking::{create_libp2p_keypair_from_validator, load_network_config, LibP2PNetwork, MockNetwork, NetworkRuntimeConfig}, pismo_app_jmt::BlockPayload, standards::book_executor::BookExecutor
};
use jmt::JellyfishMerkleTree;
use hotstuff_rs::block_tree::accessors::public::BlockTreeCamera;
use borsh::BorshDeserialize;

/// Buffer capacity for the event broadcast channel used for live event streaming.
/// This determines how many uncommitted events can be buffered before slow subscribers
/// start to lag. If a subscriber lags by more than this amount, they will be disconnected
/// to prevent memory buildup.
const EVENT_BROADCAST_CHANNEL_CAPACITY: usize = 1000;

/// Build validator set from network configuration
fn build_validator_set_from_network_config(
    network_config: &networking::NetworkConfig,
) -> anyhow::Result<ValidatorSet> {
    let mut init_vs_updates = ValidatorSetUpdates::new();
    
    for validator in &network_config.validators {
        // Parse verifying key from hex string
        let vk_bytes = hex::decode(&validator.verifying_key)?;
        let verifying_key = VerifyingKey::try_from(vk_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Invalid verifying key: {:?}", e))?;
        
        // Add each validator with equal power
        init_vs_updates.insert(verifying_key, Power::new(1));
    }
    
    let mut validator_set = ValidatorSet::new();
    validator_set.apply_updates(&init_vs_updates);
    Ok(validator_set)
}

/// Shared commit handler logic for both libp2p and MockNetwork
fn handle_commit_block(
    event: &hotstuff_rs::events::CommitBlockEvent,
    kv_store: &RocksDBStore,
    _is_listener: bool,
    event_broadcast_tx: Option<&tokio::sync::broadcast::Sender<crate::events::CommittedEvents>>,
) { 
    let block_tree_camera = BlockTreeCamera::new(kv_store.clone());
    let snapshot = block_tree_camera.snapshot();
    
    if snapshot.block(&event.block).is_ok() {
        let block_data = match snapshot.block_data(&event.block) {
            Ok(Some(data)) => {
                data
            },
            Ok(None) => {
                return;
            }
            Err(_) => {
                return;
            }
        };
        
        if !block_data.vec().is_empty() {
            if let Ok(block_payload) = BlockPayload::try_from_slice(block_data.vec()[0].bytes().as_slice()) {
                let transaction_count = block_payload.transactions.len();

                let start_version = block_payload.start_version;
                for (i, tx) in block_payload.transactions.iter().enumerate() {
                    let tx_version = start_version + i as u64;
                    if let Err(e) = store_transaction(kv_store, tx_version, tx) {
                        error!("❌ Failed to store transaction at version {}: {}", tx_version, e);
                    }
                }
                
                if !block_payload.events.is_empty() {
                    match store_events(kv_store, block_payload.final_version, block_payload.events.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("❌ Failed to store events for version {}: {}", block_payload.final_version, e);
                        }
                    }
                    
                    if let Some(sender) = event_broadcast_tx {
                        let committed = CommittedEvents {
                            version: block_payload.final_version,
                            events: block_payload.events.iter().enumerate().map(|(idx, (event_type, event_data))| {
                                Event {
                                    version: block_payload.final_version,
                                    event_index: idx as u32,
                                    event_type: event_type.clone(),
                                    event_data: event_data.clone(),
                                }
                            }).collect(),
                        };

                        let _ = sender.send(committed);
                    }
                }
                
                transaction_count
            } else {
                0
            }
        } else {
            0
        };
    }
}

#[tokio::main]
async fn main() {

    tracing_subscriber::fmt::init();

    // Network layer selection based on environment variable
    let use_libp2p = std::env::var("PISMO_NETWORK").unwrap_or_default() == "libp2p";
    let node_role = std::env::var("PISMO_NODE_ROLE")
        .unwrap_or_else(|_| "validator".to_string());
    let is_listener = node_role.to_lowercase() == "listener";
    let validator_keys_path = std::env::var("VALIDATOR_KEYS_PATH")
        .unwrap_or_else(|_| "./validator.keys".to_string());
    let network_config_path = std::env::var("PISMO_NETWORK_CONFIG")
        .unwrap_or_else(|_| "config/network.toml".to_string());
    let db_path = std::env::var("PISMO_DB_PATH")
        .unwrap_or_else(|_| "./data/pismo_db".to_string());
    let server_port = std::env::var("PISMO_RPC_PORT")
        .unwrap_or_else(|_| "9944".to_string());
    
    println!("🚀 Starting PismoChain Counter App with Transaction Validation...");
    println!("================================================================");
    println!("📋 Environment Variables:");
    println!("   PISMO_NETWORK=libp2p      - Enable distributed networking (current: {})", 
        if use_libp2p { "libp2p" } else { "mock" });
    println!("   PISMO_NODE_ROLE=listener  - Run as listener (read-only, no consensus) (current: {})", node_role);
    println!("   PISMO_NETWORK_CONFIG=path - Network config file (current: {})", 
        network_config_path);
    println!("   VALIDATOR_KEYS_PATH=path  - Validator keys file (current: {})", 
        validator_keys_path);
    println!("   PISMO_DB_PATH=path        - Database path (current: {})", db_path);
    println!("   PISMO_RPC_PORT=port       - RPC port (current: {})", server_port);
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

    // Load or generate validator keypair
    let keypair = match load_validator_keys(&validator_keys_path) {
        Ok(keypair) => {
            println!("📂 Loaded existing validator keypair from {}", validator_keys_path);
            keypair
        }
        Err(_) => {
            println!("🔑 Generating new validator keypair...");
            let keypair = generate_validator_keypair();
            if let Err(e) = save_validator_keys(&validator_keys_path, &keypair) {
                eprintln!("⚠️  Warning: Failed to save validator keypair: {}", e);
                eprintln!("   The keypair will be regenerated on next restart.");
            } else {
                println!("💾 Saved new validator keypair to {}", validator_keys_path);
            }
            keypair
        }
    };
    let verifying_key = keypair.verifying_key();
    
    println!("🔑 Validator Ed25519 keypair loaded:");
    println!("   Public key: {}", hex::encode(verifying_key.to_bytes()));

    // Load network configuration early (before KV store)
    let network_config = match load_network_config(&network_config_path) {
        Ok(config) => {
            println!("📁 Loaded network config from {}", network_config_path);
            config
        }
        Err(e) if !use_libp2p => {
            // For MockNetwork mode, create single-validator config if file missing
            println!("⚠️  Network config not found ({}), creating single-validator config", e);
            let mut config = networking::NetworkConfig::default();
            config.validators.push(crate::networking::config::ValidatorConfig {
                verifying_key: hex::encode(verifying_key.to_bytes()),
                peer_id: "mock-peer".to_string(),
                multiaddrs: vec!["/ip4/127.0.0.1/udp/9000/quic-v1".to_string()],
            });
            config
        }
        Err(e) => {
            eprintln!("❌ Failed to load network config from {}: {}", network_config_path, e);
            eprintln!("💡 Create a network config file or set PISMO_NETWORK_CONFIG to a valid path");
            std::process::exit(1);
        }
    };

    // Validate that this node is in the network config
    let my_hex_key = hex::encode(verifying_key.to_bytes());
    let is_in_validator_config = network_config.validators.iter().any(|v| v.verifying_key == my_hex_key);
    let is_in_listener_config = network_config.listeners.iter().any(|l| l.verifying_key == my_hex_key);

    if is_listener {
        // Listener mode: must be in listener config
        if !is_in_listener_config {
            eprintln!("❌ ERROR: This listener is not in the network configuration!");
            eprintln!("   My key: {}", my_hex_key);
            eprintln!("   Configured listeners:");
            for (i, l) in network_config.listeners.iter().enumerate() {
                eprintln!("     {}. {}", i + 1, l.verifying_key);
            }
            eprintln!("");
            eprintln!("💡 Either:");
            eprintln!("   - Add this listener to {} in [[listeners]] section", network_config_path);
            eprintln!("   - Use a listener key that's already in the config");
            eprintln!("   - Set VALIDATOR_KEYS_PATH to point to a configured listener's keys");
            std::process::exit(1);
        }
        println!("👂 Running as LISTENER (read-only, no consensus participation)");
    } else {
        // Validator mode: must be in validator config
        if !is_in_validator_config {
            eprintln!("❌ ERROR: This validator is not in the network configuration!");
            eprintln!("   My key: {}", my_hex_key);
            eprintln!("   Configured validators:");
            for (i, v) in network_config.validators.iter().enumerate() {
                eprintln!("     {}. {}", i + 1, v.verifying_key);
            }
            eprintln!("");
            eprintln!("💡 Either:");
            eprintln!("   - Add this validator to {}", network_config_path);
            eprintln!("   - Use a validator key that's already in the config");
            eprintln!("   - Set VALIDATOR_KEYS_PATH to point to a configured validator's keys");
            eprintln!("   - Set PISMO_NODE_ROLE=listener to run as a listener instead");
            std::process::exit(1);
        }
    }

    // Build validator set from network config
    let network_validator_set = match build_validator_set_from_network_config(&network_config) {
        Ok(vs) => {
            println!("🔐 Network validator set contains {} validators:", vs.len());
            for (vk, power) in vs.validators_and_powers() {
                let is_me = &vk == &verifying_key;
                println!("   - {} (power: {}){}", 
                    &hex::encode(vk.to_bytes())[..16], // Show first 16 chars 
                    power.int(),
                    if is_me { " <- This node" } else { "" }
                );
            }
            vs
        }
        Err(e) => {
            eprintln!("❌ Failed to build validator set from config: {}", e);
            std::process::exit(1);
        }
    };

    // Create the KV store using RocksDB (use default CF for simplicity)
    let kv_store = RocksDBStore::new(&db_path)
        .expect("Failed to initialize RocksDB store");

    // Create validator set state from network config
    let init_vs_state = ValidatorSetState::new(
        network_validator_set.clone(),
        network_validator_set.clone(),
        None,
        true
    );

    // Create transaction queue for the counter app
    let tx_queue = Arc::new(Mutex::new(Vec::new()));
    
    // Create the BookExecutor for orderbook tracking
    let book_executor = BookExecutor::new();

    // Configure the replica with faster view times  
    let configuration = Configuration::builder()
        .me(keypair.clone())
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
        // .log_events(true) // Enable consensus logs for debugging
        .log_events(false)
        .build();

    // Add debug logging for consensus
    println!("📊 Consensus configuration:");
    println!("   Chain ID: {}", configuration.chain_id.int());
    println!("   My validator key: {}", hex::encode(verifying_key.to_bytes()));
    println!("   Total validators: {}", network_validator_set.len());
    println!("   Validators in set:");
    for (vk, power) in network_validator_set.validators_and_powers() {
        let is_me = &vk == &verifying_key;
        println!("   - {} (power: {}){}", 
            hex::encode(vk.to_bytes()), 
            power.int(),
            if is_me { " <- This node" } else { "" }
        );
    }

    // Check if storage is empty (no committed validator set)
    let storage_is_empty = {
        let block_tree_camera = BlockTreeCamera::new(kv_store.clone());
        let snapshot = block_tree_camera.snapshot();
        snapshot.committed_validator_set().is_err()
    };

    // Auto-initialize if storage is empty
    let should_initialize = storage_is_empty;

    if should_initialize {
        println!("🔧 Empty storage detected - initializing with genesis state...");
        
        let init_app_state = PismoAppJMT::initial_app_state();
        Replica::initialize(kv_store.clone(), init_app_state, init_vs_state);
        
        if is_listener {
            println!("✅ Listener storage initialized with {} validators in the validator set", network_validator_set.len());
            println!("   This listener will replicate blocks but won't participate in consensus");
        } else {
            println!("✅ Validator storage initialized with {} validators", network_validator_set.len());
        }
    } else {
        println!("📂 Using existing storage");
        
        // Optionally warn if we can read the stored validator set and it differs
        let block_tree_camera = BlockTreeCamera::new(kv_store.clone());
        let snapshot = block_tree_camera.snapshot();
        match snapshot.committed_validator_set() {
            Ok(stored_vs) if stored_vs.len() != network_validator_set.len() => {
                println!("⚠️  WARNING: Stored validator set has {} validators, but network config has {}",
                    stored_vs.len(), network_validator_set.len());
                println!("   Consider deleting the database directory to reinitialize with network config");
            }
            _ => {}
        }
    }

    // Give storage a moment to ensure writes are persisted
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Read the latest version from app state
    let initial_version = {
        let block_tree_camera = BlockTreeCamera::new(kv_store.clone());
        PismoAppJMT::read_latest_version(&block_tree_camera)
    };
    println!("📊 Starting with JMT version: {}", initial_version);

    // Create PismoAppJMT with correct initial version
    let pismo_app = PismoAppJMT::new(tx_queue.clone(), config.clone(), book_executor, initial_version, is_listener);
    
    println!("Created Pismo App");

    // Build and start the replica with the original kv_store
    let kv_store_for_rpc = kv_store.clone(); // Clone KV store for RPC access
    let kv_store_for_commit_handler = kv_store.clone(); // Clone KV store for commit logging
    let is_listener_for_handler = is_listener;
    
    // Create event streaming channel (only for listeners)
    // Use broadcast channel for gRPC - allows multiple subscribers and handles backpressure
    let (event_broadcast_tx, event_broadcast_rx) = if is_listener {
        let (tx, _rx) = tokio::sync::broadcast::channel(EVENT_BROADCAST_CHANNEL_CAPACITY); 
        (Some(tx.clone()), Some(tx.subscribe()))
    } else {
        (None, None)
    };
    
    let replica = if use_libp2p {
        println!("🌐 Using LibP2P + QUIC networking layer");
        
        // The network_config is already loaded above, use it for LibP2P
        let runtime_config = match NetworkRuntimeConfig::from_network_config(network_config.clone()) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("❌ Failed to create network runtime config: {}", e);
                std::process::exit(1);
            }
        };
        
        // Create libp2p keypair from the same Ed25519 key material as the validator
        let libp2p_keypair = match create_libp2p_keypair_from_validator(&keypair) {
            Ok(keypair) => keypair,
            Err(e) => {
                eprintln!("❌ Failed to create libp2p keypair: {}", e);
                std::process::exit(1);
            }
        };
        
        // Create LibP2P network
        let network = match LibP2PNetwork::new(libp2p_keypair, runtime_config, verifying_key).await {
            Ok(network) => network,
            Err(e) => {
                eprintln!("❌ Failed to initialize LibP2P network: {}", e);
                std::process::exit(1);
            }
        };
        
        println!("🔗 LibP2P network initialized with peer ID: {}", network.local_peer_id());
        println!("🔐 Using same Ed25519 key material for both consensus and networking");
        
        let kv_for_commit = kv_store_for_commit_handler.clone();
        let is_listener_commit = is_listener_for_handler;
        let event_broadcast_for_commit = event_broadcast_tx.clone();
        
        ReplicaSpec::builder()
            .app(pismo_app)
            .network(network)
            .kv_store(kv_store)
            .configuration(configuration)
            .on_commit_block(move |event| {
                handle_commit_block(
                    &event,
                    &kv_for_commit,
                    is_listener_commit,
                    event_broadcast_for_commit.as_ref(),
                );
            })
            .build()
            .start()
    } else {
        println!("🔧 Using MockNetwork (single node development mode)");
        println!("   Note: MockNetwork still uses validator set from network.toml");
        println!("💡 Set PISMO_NETWORK=libp2p to enable distributed networking");
        
        let kv_for_commit = kv_store_for_commit_handler.clone();
        let is_listener_commit = is_listener_for_handler;
        let event_broadcast_for_commit = event_broadcast_tx.clone();
        
        ReplicaSpec::builder()
            .app(pismo_app)
            .network(MockNetwork::new(verifying_key))
            .kv_store(kv_store)
            .configuration(configuration)
            .on_commit_block(move |event| {
                handle_commit_block(
                    &event,
                    &kv_for_commit,
                    is_listener_commit,
                    event_broadcast_for_commit.as_ref(),
                );
            })
            .build()
            .start()
    };

    println!("✅ PismoChain replica started with transaction validation!");
    println!("📊 Initial counter value: 0");
    
    if use_libp2p {
        println!("🌐 Network: LibP2P + QUIC (distributed consensus ready)");
    } else {
        println!("🔧 Network: MockNetwork (single node development)");
    }
    println!("================================================================");

    // Start gRPC event streaming server (listener nodes only)
    if is_listener {
        if let (Some(broadcast_tx), Some(_broadcast_rx)) = (event_broadcast_tx.clone(), event_broadcast_rx) {
            let grpc_port = std::env::var("PISMO_GRPC_PORT")
                .unwrap_or_else(|_| "50051".to_string());
            
            let event_service = grpc::EventStreamService::new(
                kv_store_for_rpc.clone(),
                broadcast_tx,
            );
            
            let addr = format!("0.0.0.0:{}", grpc_port).parse()
                .expect("Failed to parse gRPC address");
            
            tokio::spawn(async move {
                use grpc::proto::event_stream_server::EventStreamServer;
                
                println!("📡 Starting gRPC event streaming on port {}", grpc_port);
                
                if let Err(e) = tonic::transport::Server::builder()
                    .add_service(EventStreamServer::new(event_service))
                    .serve(addr)
                    .await
                {
                    eprintln!("❌ gRPC server error: {}", e);
                }
            });
            
            println!("📡 gRPC event streaming enabled on port {}", std::env::var("PISMO_GRPC_PORT").unwrap_or_else(|_| "50051".to_string()));
        }
    }

    // Start JSON-RPC server to accept transactions (async)
    let server_addr = format!("127.0.0.1:{}", server_port);
    
    let server = ServerBuilder::default()
        .build(&server_addr)
        .await
        .expect("start jsonrpc server");

    let mut module = RpcModule::new(());
    
    // Only register transaction submission for validators
    if !is_listener {
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
    } else {
        println!("👂 Listener mode: submit_borsh_tx disabled (read-only)");
    }

    // Add view method for querying state using JMT
    let kv_store_for_view = kv_store_for_rpc.clone();
    module
        .register_method("view", move |params, _mdata, _ctx| {
            use jsonrpsee::types::ErrorObjectOwned;
            use serde_json::Value;



            // Parse parameters: {"address": "hex_string", "type": "Account|Coin|CoinStore|Link", "signature_type"?: number, "external_address"?: string}
            let params_obj: Value = params.parse()?;
            
            let address_hex = params_obj.get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'address' parameter", None::<String>))?;
                
            let struct_type = params_obj.get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'type' parameter", None::<String>))?;

            // For Link queries, we don't need to validate the address as 32 bytes since we use external_address
            let address: [u8; 32] = if struct_type == "Link" {
                // For Link queries, the address parameter is not used, so we can use a dummy value
                [0u8; 32]
            } else {
                // For other query types, decode and validate the hex address
                let address_bytes = hex::decode(address_hex).map_err(|e| {
                    ErrorObjectOwned::owned(-32602, "Invalid hex address", Some(e.to_string()))
                })?;

                if address_bytes.len() != 32 {
                    return Err(ErrorObjectOwned::owned(-32602, "Address must be 32 bytes", None::<String>));
                }

                address_bytes.try_into().unwrap()
            };

            // Create JMT reader and tree directly with KVStore
            let reader = DirectJMTReader::new(&kv_store_for_view);
            let tree = JellyfishMerkleTree::<_, sha2::Sha256>::new(&reader);
            
            // Use u64::MAX as version to get the latest committed value
            let version = u64::MAX;

            // Query based on struct type using JMT
            let result = match struct_type {
                "Account" => {
                    // Create JMT key hash for account
                    let key_hash = make_key_hash_from_parts(address, b"acct");
                                        
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
                "Link" => {
                    // For Link queries, we need signature_type and external_address parameters
                    let signature_type_num = params_obj.get("signature_type")
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'signature_type' parameter for Link query", None::<String>))?;
                    
                    let external_address = params_obj.get("external_address")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Missing 'external_address' parameter for Link query", None::<String>))?;
                    
                    // Convert signature_type number to enum
                    let signature_type = match signature_type_num {
                        0 => SignatureType::SuiDev,
                        1 => SignatureType::PhantomSolanaEd25519,
                        _ => return Err(ErrorObjectOwned::owned(-32602, "Invalid signature_type. Use 0 for SuiDev, 1 for PhantomSolanaEd25519", None::<String>)),
                    };
                    
                    // Create JMT key hash for link using external address and signature type
                    let key_hash = make_link_jmt_key_hash(signature_type, external_address);
                    
                    match tree.get(key_hash, version) {
                        Ok(Some(bytes)) => {
                            match <ExternalLink as borsh::BorshDeserialize>::try_from_slice(&bytes) {
                                Ok(link) => serde_json::to_value(&link).map_err(|e| {
                                    ErrorObjectOwned::owned(-32001, "Failed to serialize Link", Some(e.to_string()))
                                })?,
                                Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to deserialize Link", Some(e.to_string()))),
                            }
                        }
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to query JMT", Some(e.to_string()))),
                    }
                }
                "Orderbook" => {
                    // Create JMT key hash for orderbook
                    let key_hash = make_key_hash_from_parts(address, b"orderbook");
                    
                    match tree.get(key_hash, version) {
                        Ok(Some(bytes)) => {
                            // Import Orderbook type
                            use crate::standards::orderbook::Orderbook;
                            match <Orderbook as borsh::BorshDeserialize>::try_from_slice(&bytes) {
                                Ok(orderbook) => serde_json::to_value(&orderbook).map_err(|e| {
                                    ErrorObjectOwned::owned(-32001, "Failed to serialize Orderbook", Some(e.to_string()))
                                })?,
                                Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to deserialize Orderbook", Some(e.to_string()))),
                            }
                        }
                        Ok(None) => Value::Null,
                        Err(e) => return Err(ErrorObjectOwned::owned(-32001, "Failed to query JMT", Some(e.to_string()))),
                    }
                }
                _ => {
                    return Err(ErrorObjectOwned::owned(-32602, "Unsupported type. Use: Account, Coin, CoinStore, Link, or Orderbook", None::<String>));
                }
            };

            Ok(result)
        })
        .expect("register view method");

    // Add method to get events in a version range
    let kv_store_for_events = kv_store_for_rpc.clone();
    module
        .register_method("get_events", move |params, _mdata, _ctx| {
            use jsonrpsee::types::ErrorObjectOwned;

            // Parse parameters: [start_version, end_version]
            let (start_ver, end_ver): (u64, u64) = params.parse()?;
            
            match get_events_range(&kv_store_for_events, start_ver, end_ver) {
                Ok(events) => {
                    serde_json::to_value(&events).map_err(|e| {
                        ErrorObjectOwned::owned(-32001, "Failed to serialize events", Some(e.to_string()))
                    })
                }
                Err(e) => {
                    Err(ErrorObjectOwned::owned(-32001, "Failed to query events", Some(e.to_string())))
                }
            }
        })
        .expect("register get_events method");

    // Add method to get transactions in a version range
    let kv_store_for_txs = kv_store_for_rpc.clone();
    module
        .register_method("get_transactions", move |params, _mdata, _ctx| {
            use jsonrpsee::types::ErrorObjectOwned;
            use serde_json::Value;

            // Parse parameters: [start_version, end_version]
            let (start_ver, end_ver): (u64, u64) = params.parse()?;
            
            match get_transactions_range(&kv_store_for_txs, start_ver, end_ver) {
                Ok(transactions) => {
                    // Convert transactions to a JSON-friendly format
                    let tx_list: Vec<Value> = transactions.into_iter().map(|(version, tx)| {
                        serde_json::json!({
                            "version": version,
                            "transaction": tx
                        })
                    }).collect();
                    
                    Ok(Value::Array(tx_list))
                }
                Err(e) => {
                    Err(ErrorObjectOwned::owned(-32001, "Failed to query transactions", Some(e.to_string())))
                }
            }
        })
        .expect("register get_transactions method");

    let server_handle = server.start(module);
    println!("🔌 JSON-RPC server listening on http://{}", server_addr);
    if is_listener {
        println!("   Methods:");
        println!("   - view (types: Account, Coin, CoinStore, Link, Orderbook) [READ-ONLY]");
        println!("   - get_events(start_version, end_version) [READ-ONLY]");
        println!("   - get_transactions(start_version, end_version) [READ-ONLY]");
    } else {
        println!("   Methods:");
        println!("   - submit_borsh_tx");
        println!("   - view (types: Account, Coin, CoinStore, Link, Orderbook)");
        println!("   - get_events(start_version, end_version)");
        println!("   - get_transactions(start_version, end_version)");
    }

    // Keep the node alive using tokio::select! (exit on RPC stop or ctrl-c)
    // The replica variable is kept in scope to prevent it from being dropped
    tokio::select! {
        _ = server_handle.stopped() => {
            println!("🛑 JSON-RPC server stopped");
        }
        _ = signal::ctrl_c() => {
            println!("👋 Caught ctrl-c, shutting down");
        }
    }
    
    // Explicitly drop the replica at the end to ensure clean shutdown
    drop(replica);
}
