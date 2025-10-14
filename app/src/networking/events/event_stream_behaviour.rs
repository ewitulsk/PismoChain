use std::{
    collections::{HashMap, VecDeque},
    task::{Context, Poll},
    time::Instant,
};

use libp2p::{
    swarm::{NetworkBehaviour, ToSwarm, ConnectionId, THandlerInEvent, THandlerOutEvent, THandler},
    PeerId, Multiaddr,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, warn, info, error};

use crate::{
    database::rocks_db::RocksDBStore,
    events::{Event, get_events_range, CommittedEvents},
};
use hotstuff_rs::block_tree::pluggables::{KVStore, KVGet};

use super::event_codec::{EventStreamRequest, EventStreamResponse, MAX_BATCH_SIZE, MAX_BUFFER_SIZE};
use super::event_stream_handler::{EventStreamHandler, HandlerInEvent, HandlerOutEvent};

/// State of an active subscription
#[derive(Debug)]
struct SubscriptionState {
    /// The peer ID of the subscriber
    peer_id: PeerId,
    /// Start version (inclusive)
    start_version: u64,
    /// Optional end version (inclusive)
    end_version: Option<u64>,
    /// Next version we need to send
    next_version_to_send: u64,
    /// Whether we've caught up to live events
    is_live: bool,
    /// Buffer of events waiting to be sent
    buffer: VecDeque<Event>,
    /// Last time we sent a batch
    last_sent: Instant,
}

/// Events emitted by the event stream behaviour
#[derive(Debug)]
pub enum EventStreamEvent {
    /// A new subscription was requested
    SubscriptionRequested {
        peer_id: PeerId,
        request: EventStreamRequest,
    },
    /// A batch was successfully sent
    BatchSent {
        peer_id: PeerId,
    },
    /// Subscription completed (reached end_version)
    SubscriptionComplete {
        peer_id: PeerId,
    },
    /// Client buffer overflow - dropping client
    BufferOverflow {
        peer_id: PeerId,
    },
    /// Error occurred
    Error {
        peer_id: PeerId,
        error: String,
    },
}

/// Network behaviour for event streaming
pub struct EventStreamBehaviour {
    /// Active subscriptions keyed by peer ID
    subscriptions: HashMap<PeerId, SubscriptionState>,
    /// Channel to receive newly committed events
    event_receiver: UnboundedReceiver<CommittedEvents>,
    /// KVStore for querying historic events
    kv_store: RocksDBStore,
    /// Pending events to emit
    pending_events: VecDeque<EventStreamEvent>,
    /// Last time we checked for timeouts
    last_timeout_check: Instant,
}

impl EventStreamBehaviour {
    /// Create a new event stream behaviour
    pub fn new(
        kv_store: RocksDBStore,
        event_receiver: UnboundedReceiver<CommittedEvents>,
    ) -> Self {
        Self {
            subscriptions: HashMap::new(),
            event_receiver,
            kv_store,
            pending_events: VecDeque::new(),
            last_timeout_check: Instant::now(),
        }
    }

    /// Get the current latest version from storage
    fn get_current_version(&self) -> u64 {
        // Read the latest version key from the KVStore
        // This is the same key used in jmt_state.rs
        const LATEST_VERSION_KEY: &[u8] = b"__jmt_latest_version__";
        const COMMITTED_APP_STATE: u8 = 3;
        
        let mut key = Vec::new();
        key.push(COMMITTED_APP_STATE);
        key.extend_from_slice(LATEST_VERSION_KEY);
        
        if let Some(version_bytes) = self.kv_store.get(&key) {
            if version_bytes.len() >= 8 {
                return u64::from_le_bytes(version_bytes[..8].try_into().unwrap_or([0u8; 8]));
            }
        }
        0
    }

    /// Handle a new subscription request
    fn handle_subscription_request(&mut self, peer_id: PeerId, request: EventStreamRequest) {
        info!("📡 New event stream subscription: peer={}, start={}, end={:?}", 
            peer_id, request.start_version, request.end_version);
        
        let subscription = SubscriptionState {
            peer_id,
            start_version: request.start_version,
            end_version: request.end_version,
            next_version_to_send: request.start_version,
            is_live: false,
            buffer: VecDeque::new(),
            last_sent: Instant::now(),
        };
        
        self.subscriptions.insert(peer_id, subscription);
        
        // Immediately try to fetch and buffer historic events
        self.fetch_historic_events(peer_id);
    }

    /// Fetch historic events for a subscription
    fn fetch_historic_events(&mut self, peer_id: PeerId) {
        // First, extract the info we need from the subscription
        let (is_live, next_version, end_version) = {
            let subscription = match self.subscriptions.get(&peer_id) {
                Some(sub) => sub,
                None => return,
            };
            (subscription.is_live, subscription.next_version_to_send, subscription.end_version)
        };
        
        // Don't fetch if we're already live
        if is_live {
            return;
        }
        
        let current_version = self.get_current_version();
        let start = next_version;
        
        // Calculate the end of this batch
        let batch_end = if let Some(end_version) = end_version {
            end_version.min(current_version).min(start + MAX_BATCH_SIZE as u64 - 1)
        } else {
            current_version.min(start + MAX_BATCH_SIZE as u64 - 1)
        };
        
        if start > batch_end {
            // We've caught up! Switch to live mode
            if let Some(subscription) = self.subscriptions.get_mut(&peer_id) {
                subscription.is_live = true;
            }
            debug!("📡 Subscription {} caught up, switching to live mode", peer_id);
            return;
        }
        
        // Fetch events from storage
        match get_events_range(&self.kv_store, start, batch_end) {
            Ok(events) => {
                debug!("📡 Fetched {} historic events for subscription {}", events.len(), peer_id);
                
                // Get mutable subscription to update it
                let subscription = match self.subscriptions.get_mut(&peer_id) {
                    Some(sub) => sub,
                    None => return,
                };
                
                // Add events to buffer
                for event in events {
                    subscription.buffer.push_back(event);
                    
                    // Check buffer size
                    if subscription.buffer.len() > MAX_BUFFER_SIZE {
                        warn!("📡 Buffer overflow for subscription {}, dropping client", peer_id);
                        self.pending_events.push_back(EventStreamEvent::BufferOverflow { peer_id });
                        self.subscriptions.remove(&peer_id);
                        return;
                    }
                }
                
                // Update next version to send
                subscription.next_version_to_send = batch_end + 1;
                
                // Check if we've reached the end
                if let Some(end_version) = subscription.end_version {
                    if batch_end >= end_version {
                        debug!("📡 Subscription {} reached end version", peer_id);
                        // Don't remove yet, let the batch be sent first
                    }
                }
                
                // Check if we've caught up to current
                if batch_end >= current_version {
                    subscription.is_live = true;
                    debug!("📡 Subscription {} caught up to current version, switching to live mode", peer_id);
                }
            }
            Err(e) => {
                error!("📡 Failed to fetch historic events for subscription {}: {}", peer_id, e);
                self.pending_events.push_back(EventStreamEvent::Error {
                    peer_id,
                    error: format!("Failed to fetch events: {}", e),
                });
                self.subscriptions.remove(&peer_id);
            }
        }
    }

    /// Distribute a batch of live events to all live subscriptions
    fn distribute_live_events(&mut self, committed: CommittedEvents) {
        debug!("📡 Distributing {} live events at version {}", committed.events.len(), committed.version);
        
        let peer_ids: Vec<_> = self.subscriptions.keys().copied().collect();
        let mut to_complete = Vec::new();
        let mut to_overflow = Vec::new();
        
        for peer_id in peer_ids {
            let should_continue = {
                let subscription = match self.subscriptions.get_mut(&peer_id) {
                    Some(sub) => sub,
                    None => continue,
                };
                
                // Only distribute to live subscriptions
                if !subscription.is_live {
                    continue;
                }
                
                // Check if this version is within the subscription range
                if committed.version < subscription.next_version_to_send {
                    continue; // Already sent
                }
                
                if let Some(end_version) = subscription.end_version {
                    if committed.version > end_version {
                        // This subscription has ended
                        debug!("📡 Subscription {} reached end version {}", peer_id, end_version);
                        to_complete.push(peer_id);
                        continue;
                    }
                }
                
                // Add events to buffer
                let mut overflowed = false;
                for event in &committed.events {
                    subscription.buffer.push_back(event.clone());
                    
                    // Check buffer size
                    if subscription.buffer.len() > MAX_BUFFER_SIZE {
                        warn!("📡 Buffer overflow for subscription {}, dropping client", peer_id);
                        overflowed = true;
                        break;
                    }
                }
                
                if overflowed {
                    to_overflow.push(peer_id);
                    false
                } else {
                    // Update next version
                    subscription.next_version_to_send = committed.version + 1;
                    true
                }
            };
            
            if !should_continue {
                continue;
            }
        }
        
        // Handle completions and overflows
        for peer_id in to_complete {
            self.pending_events.push_back(EventStreamEvent::SubscriptionComplete { peer_id });
            self.subscriptions.remove(&peer_id);
        }
        
        for peer_id in to_overflow {
            self.pending_events.push_back(EventStreamEvent::BufferOverflow { peer_id });
            self.subscriptions.remove(&peer_id);
        }
    }
}

impl NetworkBehaviour for EventStreamBehaviour {
    type ConnectionHandler = EventStreamHandler;
    type ToSwarm = EventStreamEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(EventStreamHandler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(EventStreamHandler::new())
    }

    fn on_swarm_event(&mut self, _event: libp2p::swarm::FromSwarm) {
        // No special swarm event handling needed for now
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            HandlerOutEvent::RequestReceived(request) => {
                self.handle_subscription_request(peer_id, request);
            }
            HandlerOutEvent::BatchSent => {
                debug!("📡 Batch sent successfully to peer {}", peer_id);
                self.pending_events.push_back(EventStreamEvent::BatchSent { peer_id });
            }
            HandlerOutEvent::StreamClosed => {
                debug!("📡 Stream closed for peer {}", peer_id);
                self.subscriptions.remove(&peer_id);
            }
            HandlerOutEvent::Error(error) => {
                error!("📡 Event stream error for peer {}: {}", peer_id, error);
                self.pending_events.push_back(EventStreamEvent::Error { peer_id, error });
                self.subscriptions.remove(&peer_id);
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // First, emit any pending events
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        // Check for new committed events
        match self.event_receiver.poll_recv(cx) {
            Poll::Ready(Some(committed)) => {
                self.distribute_live_events(committed);
                cx.waker().wake_by_ref(); // Continue polling
                return Poll::Pending;
            }
            Poll::Ready(None) => {
                warn!("📡 Event receiver channel closed");
            }
            Poll::Pending => {}
        }

        // Process subscriptions and send batches
        let peer_ids: Vec<_> = self.subscriptions.keys().copied().collect();
        let current_version = self.get_current_version();
        
        for peer_id in peer_ids {
            let (has_events, is_live) = {
                let subscription = match self.subscriptions.get(&peer_id) {
                    Some(sub) => sub,
                    None => continue,
                };
                (!subscription.buffer.is_empty(), subscription.is_live)
            };
            
            // If buffer has events, prepare a batch
            if has_events {
                let subscription = match self.subscriptions.get_mut(&peer_id) {
                    Some(sub) => sub,
                    None => continue,
                };
                
                let batch_size = subscription.buffer.len().min(MAX_BATCH_SIZE);
                let mut events = Vec::with_capacity(batch_size);
                
                for _ in 0..batch_size {
                    if let Some(event) = subscription.buffer.pop_front() {
                        events.push(event);
                    }
                }
                
                if !events.is_empty() {
                    let is_live = subscription.is_live;
                    let response = EventStreamResponse {
                        events,
                        is_live,
                        current_version,
                    };
                    
                    subscription.last_sent = Instant::now();
                    
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler: libp2p::swarm::NotifyHandler::Any,
                        event: HandlerInEvent::SendBatch(response),
                    });
                }
            } else if !is_live {
                // No events in buffer and not live yet, fetch more historic events
                self.fetch_historic_events(peer_id);
                cx.waker().wake_by_ref(); // Continue polling after fetch
            }
        }

        Poll::Pending
    }
}

