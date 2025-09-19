use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
    task::{Context, Poll},
};

use libp2p::{
    swarm::{NetworkBehaviour, ToSwarm, ConnectionId, THandlerInEvent, THandlerOutEvent, THandler},
    PeerId, Multiaddr,
};

use hotstuff_rs::{
    types::crypto_primitives::VerifyingKey,
    networking::messages::Message,
};

use crate::networking::{
    config::NetworkRuntimeConfig,
    stream_handler::{HotstuffStreamHandler, HandlerInEvent, HandlerOutEvent},
};
use tracing::{debug, warn, info};

/// Events emitted by the StreamBehaviour
pub enum StreamEvent {
    /// Received a hotstuff message from a peer
    MessageReceived {
        peer_id: PeerId,
        verifying_key: VerifyingKey,
        message: Message,
    },
    /// Successfully sent a message to a peer
    MessageSent {
        peer_id: PeerId,
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

/// Pure NetworkBehaviour for Hotstuff consensus using streams
pub struct StreamBehaviour {
    /// Configuration
    config: NetworkRuntimeConfig,
    /// Connection state tracking
    connections: HashMap<PeerId, ConnectionState>,
    /// Message queue for disconnected peers
    message_queue: HashMap<PeerId, VecDeque<Message>>,
    /// Pending events to emit
    pending_events: VecDeque<StreamEvent>,
    /// Keep-alive timer
    last_keepalive: Instant,
}

impl StreamBehaviour {
    /// Create a new StreamBehaviour
    pub fn new(
        local_peer_id: PeerId,
        config: NetworkRuntimeConfig,
    ) -> Self {
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
            config,
            connections,
            message_queue: HashMap::new(),
            pending_events: VecDeque::new(),
            last_keepalive: now,
        }
    }

    /// Send a message to a specific peer
    pub fn send_message(&mut self, peer_id: PeerId, message: Message) -> Result<(), String> {
        //info!("🎯 StreamBehaviour::send_message to peer_id: {}", peer_id);
        //info!("🎯 Message type: {:?}", std::mem::discriminant(&message));
        
        // Check if peer is known
        if !self.config.peer_id_to_verifying_key.contains_key(&peer_id) {
            warn!("❌ Unknown peer: {}", peer_id);
            return Err(format!("Unknown peer: {}", peer_id));
        }

        // ALWAYS queue the message, regardless of connection state
        let queue = self.message_queue.entry(peer_id).or_insert_with(VecDeque::new);
        if queue.len() >= self.config.message_queue_size {
            warn!("📤 Message queue full for peer {}, dropping oldest message", peer_id);
            queue.pop_front(); // Drop oldest message
        }
        queue.push_back(message);
        //info!("📤 Message queued for peer {}, queue size: {}", peer_id, queue.len());

        // Return appropriate status based on connection state
        if let Some(conn_state) = self.connections.get(&peer_id) {
            if conn_state.connected {
                //info!("✅ Peer {} is connected, message will be sent by poll()", peer_id);
                Ok(()) // Will be sent immediately by poll()
            } else {
                //info!("⏳ Peer {} not connected, message queued for later", peer_id);
                Err(format!("Peer {} not connected, message queued", peer_id))
            }
        } else {
            //info!("⏳ No connection state for peer {}, message queued", peer_id);
            Err(format!("Peer {} not connected, message queued", peer_id))
        }
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast_message(&mut self, message: Message) -> Vec<Result<(), String>> {
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
        if let Some(queue) = self.message_queue.get_mut(&peer_id) {
            // We'll process the queue in the poll method
            // For now, just mark that we need to process it
            if !queue.is_empty() {
                self.pending_events.push_back(StreamEvent::ConnectionEstablished { peer_id });
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

    /// Clean up expired connections
    pub fn cleanup_expired_connections(&mut self) {
        // This is simpler than before - no pending requests to track
        let now = Instant::now();
        let timeout = self.config.connection_timeout;
        
        for (peer_id, state) in self.connections.iter_mut() {
            if !state.connected && now.duration_since(state.last_seen) > timeout * 10 {
                // Clear message queue for long-disconnected peers
                self.message_queue.remove(peer_id);
            }
        }
    }
}

impl NetworkBehaviour for StreamBehaviour {
    type ConnectionHandler = HotstuffStreamHandler;
    type ToSwarm = StreamEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.handle_connection_established(peer);
        Ok(HotstuffStreamHandler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        self.handle_connection_established(peer);
        Ok(HotstuffStreamHandler::new())
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        // Handle connection events
        match event {
            libp2p::swarm::FromSwarm::ConnectionEstablished(ev) => {
                self.handle_connection_established(ev.peer_id);
            }
            libp2p::swarm::FromSwarm::ConnectionClosed(ev) => {
                self.handle_connection_closed(ev.peer_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            HandlerOutEvent::MessageReceived(message) => {
                // Look up verifying key for this peer
                let verifying_key = self.config.get_verifying_key(&peer_id)
                    .unwrap_or_else(|| VerifyingKey::default());
                self.pending_events.push_back(StreamEvent::MessageReceived {
                    peer_id,
                    verifying_key,
                    message,
                });
            }
            HandlerOutEvent::MessageSent => {
                self.pending_events.push_back(StreamEvent::MessageSent { peer_id });
            }
            HandlerOutEvent::SendError(e) => {
                self.pending_events.push_back(StreamEvent::SendFailed {
                    peer_id,
                    error: e.to_string(),
                });
            }
            HandlerOutEvent::ReceiveError(e) => {
                self.pending_events.push_back(StreamEvent::SendFailed {
                    peer_id,
                    error: format!("Receive error: {}", e),
                });
            }
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // First, check if we have any pending events
        if let Some(event) = self.pending_events.pop_front() {
            // Handle special case for connection established - send queued messages
            if let StreamEvent::ConnectionEstablished { peer_id } = &event {
                if let Some(mut queue) = self.message_queue.remove(peer_id) {
                    while let Some(message) = queue.pop_front() {
                        return Poll::Ready(ToSwarm::NotifyHandler {
                            peer_id: *peer_id,
                            handler: libp2p::swarm::NotifyHandler::Any,
                            event: HandlerInEvent::SendMessage(message),
                        });
                    }
                }
            }
            
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        
        // Check for messages to send from queues (for newly connected peers)
        for (peer_id, conn_state) in &self.connections {
            if conn_state.connected {
                if let Some(queue) = self.message_queue.get_mut(peer_id) {
                    if let Some(message) = queue.pop_front() {
                        return Poll::Ready(ToSwarm::NotifyHandler {
                            peer_id: *peer_id,
                            handler: libp2p::swarm::NotifyHandler::Any,
                            event: HandlerInEvent::SendMessage(message),
                        });
                    }
                }
            }
        }
        
        
        Poll::Pending
    }
}
