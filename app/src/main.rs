mod database;
mod jmt_state;
mod pismo_app_jmt;
mod transactions;
mod crypto;
mod config;
mod types;
mod standards;
mod utils;
mod tests;
mod networking;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
    thread,
};
// Transaction utilities are available but not used directly in main
// use utils::{
//     submit_transactions::submit_transaction,
//     sign_transactions::submit_sui_signed_transaction
// };
// use database::mem_db::MemDB;
use pismo_app_jmt::PismoAppJMT;
// use transactions::Transaction;
use config::load_config;
// use borsh::BorshDeserialize;

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

use crate::{database::rocks_db::RocksDBStore, networking::{Libp2pNetwork, NetworkWrapper}};

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
    let db_path = "./data/pismo_db";
    let kv_store = RocksDBStore::new(db_path)
        .expect("Failed to initialize RocksDB store");

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
    let counter_app = PismoAppJMT::new(tx_queue.clone(), config.clone());

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
        .log_events(false) // Disable verbose consensus logs
        .build();

    // Initialize replica storage first
    println!("🔧 Initializing replica storage with RocksDB...");
    let kv_store_for_init = kv_store.clone();
    Replica::initialize(kv_store_for_init, init_app_state, init_vs_state);
    println!("✅ Replica storage initialized successfully");
    
    // Give RocksDB a moment to ensure all writes are fully persisted
    thread::sleep(Duration::from_millis(100));
    
    // Choose network implementation based on configuration
    let network = if config.network.single_node_mode {
        println!("🔧 Using MockNetwork for single-node mode");
        NetworkWrapper::Mock(MockNetwork::new(verifying_key))
    } else {
        println!("🌐 Using libp2p network with QUIC transport");
        let libp2p_config = config.network.to_libp2p_config()
            .expect("Failed to convert network config");
        
        let libp2p_network = Libp2pNetwork::new(&keypair, libp2p_config)
            .expect("Failed to initialize libp2p network");
        
        println!("✅ Libp2p network initialized on {}", config.network.listen_addr);
        if !config.network.bootstrap_peers.is_empty() {
            println!("📡 Connecting to {} bootstrap peers", config.network.bootstrap_peers.len());
        }
        
        NetworkWrapper::Libp2p(libp2p_network)
    };
    
    // Build and start the replica with the original kv_store
    let _replica = ReplicaSpec::builder()
        .app(counter_app)
        .network(network)
        .kv_store(kv_store)
        .configuration(configuration)
        .build()
        .start();

    println!("✅ PismoChain replica started with transaction validation!");
    println!("📊 Initial counter value: 0");
    println!("================================================================");

    // Keep the main thread alive
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
