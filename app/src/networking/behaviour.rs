use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use libp2p::{
    identify::{self, Behaviour as IdentifyBehaviour},
    request_response::{self, Behaviour as RequestResponseBehaviour, OutboundRequestId},
    swarm::{NetworkBehaviour, ToSwarm, ConnectionId},
    PeerId, Multiaddr,
};
use std::task::{Context, Poll};

use hotstuff_rs::{
    types::crypto_primitives::VerifyingKey,
    networking::messages::Message,
};

use crate::networking::{
    codec::{HotstuffCodec, HotstuffProtocol},
    config::NetworkRuntimeConfig,
};

/// Events emitted by the HotstuffBehaviour
pub enum HotstuffEvent {
    /// Received a hotstuff message from a peer
    MessageReceived {
        peer_id: PeerId,
        verifying_key: VerifyingKey,
        message: Message,
    },
    /// Successfully sent a message to a peer
    MessageSent {
        peer_id: PeerId,
        request_id: OutboundRequestId,
    },
    /// Failed to send a message to a peer
    SendFailed {
        peer_id: PeerId,
        error: String,
    },
    /// Peer identified itself
    PeerIdentified {
        peer_id: PeerId,
    },
    /// Connection established with peer
    ConnectionEstablished {
        peer_id: PeerId,
    },
    /// Connection closed with peer
    ConnectionClosed {
        peer_id: PeerId,
    },
}

/// Connection state tracking
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub peer_id: PeerId,
    pub connected: bool,
    pub last_seen: Instant,
    pub retry_count: u32,
    pub next_retry: Option<Instant>,
}

/// Pending outbound request tracking
pub struct PendingRequest {
    pub peer_id: PeerId,
    pub message: Message,
    pub timestamp: Instant,
}

/// Custom NetworkBehaviour for Hotstuff consensus
pub struct HotstuffBehaviour {
    /// Request-response protocol for hotstuff messages
    request_response: RequestResponseBehaviour<HotstuffCodec>,
    /// Identify protocol for peer discovery and metadata
    identify: IdentifyBehaviour,
    /// Configuration
    config: NetworkRuntimeConfig,
    /// Connection state tracking
    connections: HashMap<PeerId, ConnectionState>,
    /// Pending outbound requests
    pending_requests: HashMap<OutboundRequestId, PendingRequest>,
    /// Message queue for disconnected peers
    message_queue: HashMap<PeerId, VecDeque<Message>>,
    /// Keep-alive timer
    last_keepalive: Instant,
}

impl HotstuffBehaviour {
    /// Create a new HotstuffBehaviour
    pub fn new(
        local_peer_id: PeerId,
        local_public_key: libp2p::identity::PublicKey,
        config: NetworkRuntimeConfig,
    ) -> Self {
        use libp2p::request_response::ProtocolSupport;
        
        let request_response = RequestResponseBehaviour::new(
            [(HotstuffProtocol, ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(config.connection_timeout),
        );

        // Use the actual public key for the identify protocol
        let identify = IdentifyBehaviour::new(identify::Config::new(
            "/hotstuff/1.0.0".to_string(),
            local_public_key,
        ));

        let mut connections = HashMap::new();
        let now = Instant::now();
        
        // Initialize connection states for all known peers
        for peer_id in config.all_peer_ids() {
            if peer_id != local_peer_id {
                connections.insert(
                    peer_id,
                    ConnectionState {
                        peer_id,
                        connected: false,
                        last_seen: now,
                        retry_count: 0,
                        next_retry: None,
                    },
                );
            }
        }

        Self {
            request_response,
            identify,
            config,
            connections,
            pending_requests: HashMap::new(),
            message_queue: HashMap::new(),
            last_keepalive: now,
        }
    }

    /// Send a message to a specific peer
    pub fn send_message(&mut self, peer_id: PeerId, message: Message) -> Result<OutboundRequestId, String> {
        // Check if peer is known
        if !self.config.peer_id_to_verifying_key.contains_key(&peer_id) {
            return Err(format!("Unknown peer: {}", peer_id));
        }

        // Check connection state
        if let Some(conn_state) = self.connections.get(&peer_id) {
            if !conn_state.connected {
                // Queue message for later delivery
                let queue = self.message_queue.entry(peer_id).or_insert_with(VecDeque::new);
                if queue.len() >= self.config.message_queue_size {
                    queue.pop_front(); // Drop oldest message
                }
                queue.push_back(message.clone());
                return Err(format!("Peer {} not connected, message queued", peer_id));
            }
        }

        // Send message immediately
        let request_id = self.request_response.send_request(&peer_id, message.clone());
        
        // Track the request
        self.pending_requests.insert(
            request_id,
            PendingRequest {
                peer_id,
                message,
                timestamp: Instant::now(),
            },
        );

        Ok(request_id)
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast_message(&mut self, message: Message) -> Vec<Result<OutboundRequestId, String>> {
        let mut results = Vec::new();
        let peer_ids: Vec<_> = self.config.all_peer_ids().collect();
        
        for peer_id in peer_ids {
            let result = self.send_message(peer_id, message.clone());
            results.push(result);
        }
        
        results
    }

    /// Get connection status for a peer
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connections
            .get(peer_id)
            .map(|state| state.connected)
            .unwrap_or(false)
    }

    /// Get number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.connections
            .values()
            .filter(|state| state.connected)
            .count()
    }

    /// Process queued messages for a newly connected peer
    fn process_queued_messages(&mut self, peer_id: PeerId) {
        if let Some(mut queue) = self.message_queue.remove(&peer_id) {
            while let Some(message) = queue.pop_front() {
                match self.send_message(peer_id, message.clone()) {
                    Ok(_) => {} // Message sent successfully
                    Err(_) => {
                        // Put remaining messages back in queue
                        queue.push_front(message);
                        self.message_queue.insert(peer_id, queue);
                        break;
                    }
                }
            }
        }
    }

    /// Handle connection establishment
    pub fn handle_connection_established(&mut self, peer_id: PeerId) {
        if let Some(state) = self.connections.get_mut(&peer_id) {
            state.connected = true;
            state.last_seen = Instant::now();
            state.retry_count = 0;
            state.next_retry = None;
        }

        // Process any queued messages
        self.process_queued_messages(peer_id);
    }

    /// Handle connection closure
    pub fn handle_connection_closed(&mut self, peer_id: PeerId) {
        if let Some(state) = self.connections.get_mut(&peer_id) {
            state.connected = false;
            state.last_seen = Instant::now();
            
            // Schedule retry if we haven't exceeded max attempts
            if state.retry_count < self.config.max_retry_attempts {
                let backoff = self.config.retry_backoff_base * (2_u32.pow(state.retry_count));
                state.next_retry = Some(Instant::now() + backoff);
                state.retry_count += 1;
            }
        }
    }

    /// Check for peers that need reconnection attempts
    pub fn peers_needing_reconnection(&self) -> Vec<PeerId> {
        let now = Instant::now();
        self.connections
            .values()
            .filter(|state| {
                !state.connected
                    && state.retry_count < self.config.max_retry_attempts
                    && state.next_retry.map(|retry_time| now >= retry_time).unwrap_or(false)
            })
            .map(|state| state.peer_id)
            .collect()
    }

    /// Clean up expired pending requests
    pub fn cleanup_expired_requests(&mut self) {
        let now = Instant::now();
        let timeout = self.config.connection_timeout;
        
        let expired_requests: Vec<_> = self.pending_requests
            .iter()
            .filter(|(_, req)| now.duration_since(req.timestamp) > timeout)
            .map(|(id, _)| *id)
            .collect();
            
        for request_id in expired_requests {
            self.pending_requests.remove(&request_id);
        }
    }
}

// Manual NetworkBehaviour implementation since the derive macro has issues
impl NetworkBehaviour for HotstuffBehaviour {
    type ConnectionHandler = <RequestResponseBehaviour<HotstuffCodec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = HotstuffEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        // Delegate to request_response behaviour
        self.request_response.handle_established_inbound_connection(_connection_id, peer, _local_addr, _remote_addr)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        // Delegate to request_response behaviour
        self.request_response.handle_established_outbound_connection(_connection_id, peer, _addr, _role_override)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        // Delegate to both behaviours
        self.request_response.on_swarm_event(event);
        self.identify.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // Delegate to request_response behaviour
        self.request_response.on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        // Poll request_response first
        if let Poll::Ready(event) = self.request_response.poll(cx) {
            match event {
                ToSwarm::GenerateEvent(rr_event) => {
                    // Convert request_response event to HotstuffEvent
                    let hotstuff_event = match rr_event {
                        request_response::Event::Message { peer, message } => {
                            match message {
                                request_response::Message::Request { request, .. } => {
                                    // Look up verifying key for this peer
                                    let verifying_key = self.config.get_verifying_key(&peer)
                                        .unwrap_or_else(|| VerifyingKey::default());
                                    HotstuffEvent::MessageReceived {
                                        peer_id: peer,
                                        verifying_key,
                                        message: request,
                                    }
                                }
                                request_response::Message::Response { .. } => {
                                    // We don't use responses in hotstuff protocol
                                    return Poll::Pending;
                                }
                            }
                        }
                        request_response::Event::OutboundFailure { peer, error, .. } => {
                            HotstuffEvent::SendFailed {
                                peer_id: peer,
                                error: error.to_string(),
                            }
                        }
                        request_response::Event::InboundFailure { peer, error, .. } => {
                            HotstuffEvent::SendFailed {
                                peer_id: peer,
                                error: error.to_string(),
                            }
                        }
                        request_response::Event::ResponseSent { .. } => {
                            // We don't use responses in hotstuff protocol
                            return Poll::Pending;
                        }
                    };
                    return Poll::Ready(ToSwarm::GenerateEvent(hotstuff_event));
                }
                _ => {} // Handle other events by continuing to poll identify
            }
        }

        // Poll identify
        if let Poll::Ready(event) = self.identify.poll(cx) {
            match event {
                ToSwarm::GenerateEvent(id_event) => {
                    let hotstuff_event = match id_event {
                        identify::Event::Received { peer_id, .. } => {
                            HotstuffEvent::PeerIdentified { peer_id }
                        }
                        identify::Event::Sent { peer_id, .. } => {
                            HotstuffEvent::PeerIdentified { peer_id }
                        }
                        identify::Event::Pushed { peer_id, .. } => {
                            HotstuffEvent::PeerIdentified { peer_id }
                        }
                        identify::Event::Error { peer_id, error } => {
                            HotstuffEvent::SendFailed {
                                peer_id,
                                error: error.to_string(),
                            }
                        }
                    };
                    return Poll::Ready(ToSwarm::GenerateEvent(hotstuff_event));
                }
                _ => {} // Handle other events by continuing
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_behaviour_creation() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let public_key = keypair.public();
        let config = NetworkRuntimeConfig::from_network_config(
            crate::networking::config::NetworkConfig::default()
        ).unwrap();

        let behaviour = HotstuffBehaviour::new(peer_id, public_key, config);
        assert_eq!(behaviour.connected_peer_count(), 0);
    }

    #[test]
    fn test_connection_state_tracking() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let public_key = keypair.public();
        let config = NetworkRuntimeConfig::from_network_config(
            crate::networking::config::NetworkConfig::default()
        ).unwrap();

        let mut behaviour = HotstuffBehaviour::new(peer_id, public_key, config);
        let test_peer = PeerId::random();

        // Initially not connected
        assert!(!behaviour.is_connected(&test_peer));

        // Simulate connection
        behaviour.handle_connection_established(test_peer);
        assert!(behaviour.is_connected(&test_peer));

        // Simulate disconnection
        behaviour.handle_connection_closed(test_peer);
        assert!(!behaviour.is_connected(&test_peer));
    }
}
