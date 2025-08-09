pub mod libp2p_network;

pub use libp2p_network::Libp2pNetwork;

use hotstuff_rs::{
    networking::{network::Network, messages::Message},
    types::{
        crypto_primitives::VerifyingKey,
        validator_set::ValidatorSet,
        update_sets::ValidatorSetUpdates,
    },
};

/// Wrapper enum to handle different network implementations
/// This is needed because the Network trait is not dyn compatible
#[derive(Clone)]
pub enum NetworkWrapper {
    Mock(crate::MockNetwork),
    Libp2p(Libp2pNetwork),
}

impl Network for NetworkWrapper {
    fn init_validator_set(&mut self, validator_set: ValidatorSet) {
        match self {
            NetworkWrapper::Mock(net) => net.init_validator_set(validator_set),
            NetworkWrapper::Libp2p(net) => net.init_validator_set(validator_set),
        }
    }
    
    fn update_validator_set(&mut self, updates: ValidatorSetUpdates) {
        match self {
            NetworkWrapper::Mock(net) => net.update_validator_set(updates),
            NetworkWrapper::Libp2p(net) => net.update_validator_set(updates),
        }
    }
    
    fn send(&mut self, peer: VerifyingKey, message: Message) {
        match self {
            NetworkWrapper::Mock(net) => net.send(peer, message),
            NetworkWrapper::Libp2p(net) => net.send(peer, message),
        }
    }
    
    fn broadcast(&mut self, message: Message) {
        match self {
            NetworkWrapper::Mock(net) => net.broadcast(message),
            NetworkWrapper::Libp2p(net) => net.broadcast(message),
        }
    }
    
    fn recv(&mut self) -> Option<(VerifyingKey, Message)> {
        match self {
            NetworkWrapper::Mock(net) => net.recv(),
            NetworkWrapper::Libp2p(net) => net.recv(),
        }
    }
}