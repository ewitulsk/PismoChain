use std::{sync::{Arc, Mutex}, time::Duration, thread};
use crate::pismo_app_jmt::{PismoAppJMT, PismoOperation};
use crate::config::load_config;
use crate::transactions::Transaction;
use crate::utils::submit_transactions::submit_transaction;
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
use crate::database::mem_db::MemDB;
use crate::crypto;
use sui_sdk::types::crypto::{SuiKeyPair, get_key_pair_from_rng};
use rand_core::OsRng;

#[test]
fn boot_and_accept_tx() {
    // Spin up a minimal replica similar to main and submit a no-op tx
    let config = load_config().expect("config");
    let mut rng = OsRng;
    let validator_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
    let keypair = crypto::sui_keypair_to_hotstuff_signing_key(&validator_keypair);
    let verifying_key = keypair.verifying_key();
    let kv_store = MemDB::new();

    let init_app_state = PismoAppJMT::initial_app_state();

    let mut init_vs_updates = ValidatorSetUpdates::new();
    init_vs_updates.insert(verifying_key, Power::new(1));
    let mut init_vs = ValidatorSet::new();
    init_vs.apply_updates(&init_vs_updates);
    let init_vs_state = ValidatorSetState::new(init_vs.clone(), init_vs, None, true);

    let tx_queue = Arc::new(Mutex::new(Vec::new()));
    let app = PismoAppJMT::new(tx_queue.clone(), config.clone());

    let configuration = Configuration::builder()
        .me(keypair)
        .chain_id(ChainID::new(4206980085))
        .progress_msg_buffer_capacity(BufferSize::new(128))
        .epoch_length(EpochLength::new(10))
        .max_view_time(Duration::from_millis(500))
        .log_events(false)
        .build();

    Replica::initialize(kv_store.clone(), init_app_state, init_vs_state);
    let _replica = ReplicaSpec::builder()
        .app(app)
        .network(super::super::super::main::MockNetwork { my_verifying_key: verifying_key, all_peers: Default::default(), inbox: Arc::new(Mutex::new(std::sync::mpsc::channel().1)) })
        .kv_store(kv_store)
        .configuration(configuration)
        .build()
        .start();

    // CreateAccount tx
    let op = PismoOperation::CreateAccount { chain: crate::standards::accounts::Chain::SolanaEd25519, external_addr: vec![0u8;32], created_at_ms: 0 };
    let mut tx = Transaction::new(op, 0, config.chain_id);
    tx.sign(&validator_keypair).unwrap();
    submit_transaction(tx_queue, tx, config.chain_id).unwrap();
    thread::sleep(Duration::from_millis(200));
}
