use std::{
    sync::{Arc, Mutex, mpsc::{self, Receiver, Sender, TryRecvError}},
    collections::HashMap,
};

use hotstuff_rs::{
    types::{
        crypto_primitives::VerifyingKey,
        update_sets::ValidatorSetUpdates,
        validator_set::ValidatorSet,
    },
    networking::{network::Network, messages::Message},
};

// Mock network implementation for single node setup
#[derive(Clone)]
pub struct MockNetwork {
    my_verifying_key: VerifyingKey,
    all_peers: HashMap<VerifyingKey, Sender<(VerifyingKey, Message)>>,
    inbox: Arc<Mutex<Receiver<(VerifyingKey, Message)>>>,
}

impl MockNetwork {
    pub fn new(verifying_key: VerifyingKey) -> Self {
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
