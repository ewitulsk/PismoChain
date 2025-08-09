use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{task, time::sleep};

use crate::{
    utils::{
        submit_transactions::submit_transaction,
        sign_transactions::submit_sui_signed_transaction
    },
    database::mem_db::MemDB,
    pismo_app_jmt::{PismoAppJMT, PismoOperation, BlockPayload},
    transactions::Transaction,
    config::load_config,
    jmt_state::make_state_key,
};

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

#[tokio::test]
// #[ignore] // Use #[ignore] so it doesn't run by default with `cargo test`
async fn integration_test_pismo_chain() {
    println!("🧪 Starting PismoChain Integration Test...");
    println!("================================================================");
    
    // Load configuration from CONFIG_PATH environment variable or default path
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            eprintln!("💡 Set CONFIG_PATH environment variable or ensure configs/testnet.toml exists");
            panic!("Configuration error: {}", e);
        }
    };

    // Generate signing key for this replica
    let mut rng = OsRng;
    let validator_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
    
    // Convert the Sui keypair to a HotStuff SigningKey using the same underlying Ed25519 key material
    let keypair = crate::crypto::sui_keypair_to_hotstuff_signing_key(&validator_keypair);
    let verifying_key = keypair.verifying_key();
    
    println!("🔑 Generated single Ed25519 keypair used for both validator and consensus:");
    println!("   Validator public key: {:?}", validator_keypair.public());
    println!("   HotStuff verifying key: {:?}", verifying_key.to_bytes());

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
    let counter_app = PismoAppJMT::new(tx_queue.clone(), config);

    // Configure the replica with faster view times for testing
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
        .max_view_time(Duration::from_millis(1000)) // Faster for testing
        .log_events(false) // Disable verbose consensus logs
        .build();

    // Initialize replica storage first
    println!("🔧 Initializing replica storage...");
    let kv_store_for_init = kv_store.clone();
    Replica::initialize(kv_store_for_init, init_app_state, init_vs_state);
    println!("✅ Replica storage initialized successfully");
    
    // Give storage a moment to ensure all writes are fully persisted
    sleep(Duration::from_millis(100)).await;
    
    // Build and start the replica with the original kv_store
    let replica = ReplicaSpec::builder()
        .app(counter_app)
        .network(MockNetwork::new(verifying_key))
        .kv_store(kv_store)
        .configuration(configuration)
        .build()
        .start();

    println!("✅ PismoChain replica started for integration testing!");
    println!("📊 Initial counter value: 0");
    println!("================================================================");
    
    // Test transaction submission in a separate task
    let tx_queue_clone = tx_queue.clone();
    let tx_task = task::spawn(async move {
        sleep(Duration::from_millis(500)).await; // Wait for startup
        
        // Create Sui signers for different users
        let mut rng = OsRng;
        let alice_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        let bob_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        let charlie_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        
        println!("🔑 Created test Sui signers:");
        println!("   Alice: {:?}", alice_keypair.public());
        println!("   Bob: {:?}", bob_keypair.public());
        println!("   Charlie: {:?}", charlie_keypair.public());
        println!("================================================================");
        
        // Test 1: Submit Sui-signed Increment transaction from Alice
        println!("🧪 TEST 1: Submitting Sui-signed Increment transaction from Alice...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &alice_keypair, PismoOperation::Increment) {
            Ok(_) => {
                println!("✅ Test 1: Alice Increment transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 1: Failed to submit Alice Increment: {}", e);
            }
        }
        
        sleep(Duration::from_millis(1500)).await;
        
        // Test 2: Submit Sui-signed Increment transaction from Bob
        println!("🧪 TEST 2: Submitting Sui-signed Increment transaction from Bob...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &bob_keypair, PismoOperation::Increment) {
            Ok(_) => {
                println!("✅ Test 2: Bob Increment transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 2: Failed to submit Bob Increment: {}", e);
            }
        }
        
        sleep(Duration::from_millis(1500)).await;
        
        // Test 3: Submit Sui-signed Set(10) transaction from Charlie
        println!("🧪 TEST 3: Submitting Sui-signed Set(10) transaction from Charlie...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &charlie_keypair, PismoOperation::Set(10)) {
            Ok(_) => {
                println!("✅ Test 3: Charlie Set(10) transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 3: Failed to submit Charlie Set(10): {}", e);
            }
        }
        
        sleep(Duration::from_millis(1500)).await;
        
        // Test 4: Submit Sui-signed Decrement transaction from Alice
        println!("🧪 TEST 4: Submitting Sui-signed Decrement transaction from Alice...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &alice_keypair, PismoOperation::Decrement) {
            Ok(_) => {
                println!("✅ Test 4: Alice Decrement transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 4: Failed to submit Alice Decrement: {}", e);
            }
        }
        
        sleep(Duration::from_millis(1500)).await;
        
        // Test 5: Submit another Increment from Bob
        println!("🧪 TEST 5: Submitting another Increment transaction from Bob...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &bob_keypair, PismoOperation::Increment) {
            Ok(_) => {
                println!("✅ Test 5: Bob second Increment transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 5: Failed to submit Bob second Increment: {}", e);
            }
        }
        
        sleep(Duration::from_millis(1500)).await;
        
        // Test 6: Submit Set(42) from Charlie
        println!("🧪 TEST 6: Submitting Set(42) transaction from Charlie...");
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &charlie_keypair, PismoOperation::Set(42)) {
            Ok(_) => {
                println!("✅ Test 6: Charlie Set(42) transaction submitted");
            },
            Err(e) => {
                println!("❌ Test 6: Failed to submit Charlie Set(42): {}", e);
            }
        }

        // Test 7: Test invalid transaction handling
        sleep(Duration::from_millis(1500)).await;
        println!("🧪 TEST 7: Testing invalid transaction (unsigned)...");
        let invalid_tx = Transaction::new(PismoOperation::Set(999));
        let dummy_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        let dummy_public_key = dummy_keypair.public();
        
        // Don't sign the transaction - it should be rejected
        match submit_transaction(tx_queue_clone.clone(), invalid_tx, &dummy_public_key) {
            Err(_) => {
                println!("✅ Test 7: Successfully rejected unsigned transaction");
            },
            Ok(_) => {
                println!("❌ Test 7: Unsigned transaction was incorrectly accepted");
            }
        }
        
        // Test 8: Test Onramp transaction with VAA verification
        sleep(Duration::from_millis(1500)).await;
        println!("🧪 TEST 8: Testing Onramp transaction with Wormhole VAA verification...");
        let sample_vaa = "AQAAAAABAGZIrvrMZB2Jzud966+Fajf5ZL2kKl6xWHsYFVo805BVY0K0OxD0FwkxYo6ixo/zChGu3dIaO+lyHASMR2ijsqoAaI7t6gAAAAEAFWNKOelP1x3cVrH/mbj9b2cvfAwC5Ddw9Kkl9yTeQhk0AAAAAAAAAAAAT05SQU1QAAAAMTAwMDAwMAAAAKuNG1pTEclADj6vXDtkHxD7SLQ8ww02X6ipimymvUhlAAAAdC01zGY0wFMpJaO41C0yqKffqiwAAABiZWYxNjE4ZGI0ZmFjMGQ2NzM2NzkyZTZhYTcxNTZiNWIzOGJiZjQzMjBmOWE3NDQ4YjNhMmMxZjcyMjYzMzg0Ojp0ZXN0X2NvaW46OlRFU1RfQ09JTgAAADE3NTQxOTc0ODI3NDU=";
        let guardian_set_index = 0u64; // Testnet guardian set
        
        let onramp_operation = PismoOperation::Onramp(sample_vaa.to_string(), guardian_set_index);
        match submit_sui_signed_transaction(tx_queue_clone.clone(), &bob_keypair, onramp_operation) {
            Ok(_) => {
                println!("✅ Test 8: Onramp transaction submitted successfully");
            },
            Err(e) => {
                println!("❌ Test 8: Failed to submit Onramp transaction: {}", e);
            }
        }
    });

    // Monitor counter value changes and verify expected behavior
    // Note: We'll run this in a blocking task since replica access requires Send bounds
    let block_tree_camera = replica.block_tree_camera().clone();
    let monitor_task = task::spawn_blocking(move || {
        let mut last_value = 0i64;
        let mut test_step = 0;
        let expected_values = [0, 1, 2, 10, 9, 10, 42]; // Expected counter progression
        
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let snapshot = block_tree_camera.snapshot();
            
            // Get counter from HotStuff's committed state
            const COUNTER_ADDR: [u8; 32] = [0u8; 32];
            const COUNTER_TAG: &[u8] = b"counter";
            let counter_key = make_state_key(COUNTER_ADDR, COUNTER_TAG);
            
            let counter_value = if let Some(counter_bytes) = snapshot.committed_app_state(&counter_key) {
                i64::from_le_bytes(counter_bytes.try_into().unwrap_or([0u8; 8]))
            } else {
                0
            };
            
            // Get the current transaction version
            let current_transaction_version = if let Ok(Some(highest_block)) = snapshot.highest_committed_block() {
                if let Ok(Some(block_data)) = snapshot.block_data(&highest_block) {
                    if let Some(datum) = block_data.vec().first() {
                        if let Ok(block_payload) = BlockPayload::deserialize(
                            &mut datum.bytes().as_slice()
                        ) {
                            block_payload.final_version
                        } else {
                            0u64
                        }
                    } else {
                        0u64
                    }
                } else {
                    0u64
                }
            } else {
                0u64
            };
            
            if counter_value != last_value {
                println!("🔢 COUNTER CHANGED: {} → {} ⭐ (TX Version: {})", last_value, counter_value, current_transaction_version);
                
                last_value = counter_value;
            } else {
                print!("🔢 Counter: {} (V: {}) ", counter_value, current_transaction_version);
                // Print dots to show time passing
                for _ in 0..3 {
                    std::thread::sleep(Duration::from_millis(100));
                    print!(".");
                }
                println!();
            }
        }
    });

    // Wait for a reasonable amount of time to let the test complete
    sleep(Duration::from_secs(15)).await;
    
    // Kill the monitor task
    monitor_task.abort();
    tx_task.abort();
    drop(replica);
}

