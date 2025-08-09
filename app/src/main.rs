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
    thread,
};
use utils::{
    submit_transactions::submit_transaction,
    sign_transactions::submit_sui_signed_transaction
};
use database::mem_db::MemDB;
use pismo_app_jmt::{PismoAppJMT, PismoOperation};
use transactions::Transaction;
use config::load_config;
use borsh::BorshDeserialize;

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

use std::{
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    collections::HashMap,
};

use crate::pismo_app_jmt::BlockPayload;

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

fn main() {
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
    
    // Give RocksDB a moment to ensure all writes are fully persisted
    thread::sleep(Duration::from_millis(100));
    
    // Build and start the replica with the original kv_store
    let replica = ReplicaSpec::builder()
        .app(pismo_app)
        .network(MockNetwork::new(verifying_key))
        .kv_store(kv_store)
        .configuration(configuration)
        .build()
        .start();

    println!("✅ PismoChain replica started with transaction validation!");
    println!("📊 Initial counter value: 0");
    println!("================================================================");
    
    // Demo: Submit Sui-signed transactions (adjusted to new ops)
    let tx_queue_clone = tx_queue.clone();
    let cfg_chain_id = config.chain_id;
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(500)); // Wait for startup
        
        // Create Sui signers for different users
        let mut rng = OsRng;
        let alice_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        let bob_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        
        println!("🔑 Created Sui signers:");
        println!("   Alice: {:?}", alice_keypair.public());
        println!("   Bob: {:?}", bob_keypair.public());
        println!("   Charlie: {:?}", alice_keypair.public());
        println!("================================================================");
        
        // CreateAccount for Alice
        let create_acct = PismoOperation::CreateAccount { chain: crate::standards::accounts::Chain::SolanaEd25519, external_addr: vec![0u8; 32], created_at_ms: 0 };
        let mut tx = Transaction::new(create_acct, 0, cfg_chain_id);
        tx.chain_id = cfg_chain_id;
        tx.nonce = 0;
        tx.sign(&alice_keypair).ok();
        let _ = submit_transaction(tx_queue_clone.clone(), tx, &alice_keypair.public());
        
        thread::sleep(Duration::from_millis(800));
        // LinkAccount (will likely fail nonce/account unless correct addr is used; this is just a flow demo)
        let link = PismoOperation::LinkAccount { account_addr: [0u8;32], chain: crate::standards::accounts::Chain::SolanaEd25519, external_addr: vec![1u8;32], added_at_ms: 0 };
        let mut tx2 = Transaction::new(link, 1, cfg_chain_id);
        tx2.chain_id = cfg_chain_id;
        tx2.nonce = 0;
        tx2.sign(&bob_keypair).ok();
        let _ = submit_transaction(tx_queue_clone.clone(), tx2, &bob_keypair.public());
        
        // Demonstrate Onramp transaction with VAA verification
        thread::sleep(Duration::from_millis(1200));
        println!("🌉 Testing Onramp transaction with Wormhole VAA verification...");
        let sample_vaa = "AQAAAAABAGZIrvrMZB2Jzud966+Fajf5ZL2kKl6xWHsYFVo805BVY0K0OxD0FwkxYo6ixo/zChGu3dIaO+lyHASMR2ijsqoAaI7t6gAAAAEAFWNKOelP1x3cVrH/mbj9b2cvfAwC5Ddw9Kkl9yTeQhk0AAAAAAAAAAAAT05SQU1QAAAAMTAwMDAwMAAAAKuNG1pTEclADj6vXDtkHxD7SLQ8ww02X6ipimymvUhlAAAAdC01zGY0wFMpJaO41C0yqKffqiwAAABiZWYxNjE4ZGI0ZmFjMGQ2NzM2NzkyZTZhYTcxNTZiNWIzOGJiZjQzMjBmOWE3NDQ4YjNhMmMxZjcyMjYzMzg0Ojp0ZXN0X2NvaW46OlRFU1RfQ09JTgAAADE3NTQxOTc0ODI3NDU=";
        let guardian_set_index = 0u64; // Testnet guardian set
        
        let onramp_operation = PismoOperation::Onramp(sample_vaa.to_string(), guardian_set_index);
        if let Err(e) = submit_sui_signed_transaction(tx_queue_clone.clone(), &bob_keypair, onramp_operation, 2, cfg_chain_id) {
            println!("❌ Failed to submit Onramp transaction: {}", e);
        } else {
            println!("✅ Onramp transaction submitted successfully!");
        }
    });

        // Query with less frequent updates
    thread::spawn(move || {
            let mut last_value = 0i64;
        loop {
            thread::sleep(Duration::from_millis(300)); // Less frequent queries
            let snapshot = replica.block_tree_camera().snapshot();
                                // Get counter from HotStuff's committed state (JMT state is managed internally)
            use crate::jmt_state::make_state_key;
            const COUNTER_ADDR: [u8; 32] = [0u8; 32];
            const COUNTER_TAG: &[u8] = b"counter";
            let counter_key = make_state_key(COUNTER_ADDR, COUNTER_TAG);
            
            let counter_value = if let Some(counter_bytes) = snapshot.committed_app_state(&counter_key) {
                i64::from_le_bytes(counter_bytes.try_into().unwrap_or([0u8; 8]))
            } else {
                0
            };
            
            // Get the current transaction version from the latest committed block
            let current_transaction_version = if let Ok(Some(highest_block)) = snapshot.highest_committed_block() {
                if let Ok(Some(block_data)) = snapshot.block_data(&highest_block) {
                    if let Some(datum) = block_data.vec().first() {
                        // Try to deserialize the BlockPayload to get the final_version
                        if let Ok(block_payload) = BlockPayload::deserialize(
                            &mut datum.bytes().as_slice()
                        ) {
                            block_payload.final_version
                        } else {
                            0u64 // If deserialization fails, default to 0
                        }
                    } else {
                        0u64 // If no data in block, default to 0
                    }
                } else {
                    0u64 // If no block data, default to 0
                }
            } else {
                0u64 // If no committed block, default to 0
            };
            
            if counter_value != last_value {
                println!("🔢 COUNTER CHANGED: {} → {} ⭐ (TX Version: {})", last_value, counter_value, current_transaction_version);
                last_value = counter_value;
            } else {
                print!("🔢 Counter: {} (V: {}) ", counter_value, current_transaction_version);
                // Print dots to show time passing
                for _ in 0..3 {
                    thread::sleep(Duration::from_millis(100));
                    print!(".");
                }
                println!(); // New line
            }
        }
    });

    // Keep the main thread alive
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
