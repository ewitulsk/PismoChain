use libp2p::{
    identify::{self, Behaviour as IdentifyBehaviour},
    swarm::NetworkBehaviour,
    PeerId,
};
use tracing::{info, error};

use hotstuff_rs::{
    networking::messages::Message,
};

use crate::networking::{
    config::NetworkRuntimeConfig,
    stream_behaviour::{StreamBehaviour, StreamEvent},
};

/// Unified events from the composite behaviour
pub enum CompositeEvent {
    /// Stream-related events
    Stream(StreamEvent),
    /// Identify protocol events
    Identify(identify::Event),
}

/// Composite NetworkBehaviour combining HotStuff streams and peer identification
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CompositeEvent")]
pub struct HotstuffNetworkBehaviour {
    /// HotStuff message streaming
    stream: StreamBehaviour,
    /// Peer identification and discovery
    identify: IdentifyBehaviour,
}

impl HotstuffNetworkBehaviour {
    /// Create a new composite behaviour
    pub fn new(
        local_peer_id: PeerId,
        local_public_key: libp2p::identity::PublicKey,
        config: NetworkRuntimeConfig,
    ) -> Self {
        //info!("🏗️ Creating HotstuffNetworkBehaviour for peer: {}", local_peer_id);
        
        // Create identify behaviour for peer discovery
        let identify = IdentifyBehaviour::new(identify::Config::new(
            "/hotstuff/identify/1.0.0".to_string(),
            local_public_key,
        ));
        //info!("✅ IdentifyBehaviour created");

        // Create stream behaviour for HotStuff messages
        let stream = StreamBehaviour::new(local_peer_id, config);
        //info!("✅ StreamBehaviour created");

        let composite = Self {
            stream,
            identify,
        };
        //info!("✅ HotstuffNetworkBehaviour created successfully");
        composite
    }

    /// Send a message to a specific peer
    pub fn send_message(&mut self, peer_id: PeerId, message: Message) -> Result<(), String> {
        //info!("🚀 CompositeeBehaviour: Sending message to peer {}", peer_id);
        let result = self.stream.send_message(peer_id, message);
        match &result {
            Ok(_) => {}, //info!("✅ Message queued successfully"),
            Err(e) => error!("⚠️ Message queueing failed: {}", e),
        }
        result
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast_message(&mut self, message: Message) -> Vec<Result<(), String>> {
        self.stream.broadcast_message(message)
    }

    /// Get connection status for a peer
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.stream.is_connected(peer_id)
    }

    /// Get number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.stream.connected_peer_count()
    }

    /// Handle connection establishment
    pub fn handle_connection_established(&mut self, peer_id: PeerId) {
        self.stream.handle_connection_established(peer_id);
    }

    /// Handle connection closure
    pub fn handle_connection_closed(&mut self, peer_id: PeerId) {
        self.stream.handle_connection_closed(peer_id);
    }

    /// Get peers needing reconnection
    pub fn peers_needing_reconnection(&self) -> Vec<PeerId> {
        self.stream.peers_needing_reconnection()
    }

    /// Clean up expired connections
    pub fn cleanup_expired_connections(&mut self) {
        self.stream.cleanup_expired_connections();
    }
}

// Implement From traits for the NetworkBehaviour derive macro
impl From<StreamEvent> for CompositeEvent {
    fn from(event: StreamEvent) -> Self {
        CompositeEvent::Stream(event)
    }
}

impl From<identify::Event> for CompositeEvent {
    fn from(event: identify::Event) -> Self {
        CompositeEvent::Identify(event)
    }
}

/// Convert composite events to the unified stream event format for backward compatibility
impl CompositeEvent {
    pub fn into_stream_event(self, _config: &NetworkRuntimeConfig) -> Option<StreamEvent> {
        match self {
            CompositeEvent::Stream(event) => Some(event),
            CompositeEvent::Identify(id_event) => {
                // Convert identify events to stream events for compatibility
                match id_event {
                    identify::Event::Received { peer_id, .. } => {
                        Some(StreamEvent::PeerIdentified { peer_id })
                    }
                    identify::Event::Sent { peer_id, .. } => {
                        Some(StreamEvent::PeerIdentified { peer_id })
                    }
                    identify::Event::Pushed { peer_id, .. } => {
                        Some(StreamEvent::PeerIdentified { peer_id })
                    }
                    identify::Event::Error { peer_id, error } => {
                        Some(StreamEvent::SendFailed {
                            peer_id,
                            error: error.to_string(),
                        })
                    }
                }
            }
        }
    }
}
