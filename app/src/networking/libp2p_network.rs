use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use libp2p::{
    identity::Keypair,
    noise,
    quic,
    swarm::{SwarmEvent, Swarm},
    tcp, yamux, PeerId, SwarmBuilder,
};
use libp2p_identity;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};
use hex;

use hotstuff_rs::{
    networking::{network::Network, messages::Message},
    types::{
        crypto_primitives::VerifyingKey,
        update_sets::ValidatorSetUpdates,
        validator_set::ValidatorSet,
    },
};

use crate::networking::{
    composite_behaviour::HotstuffNetworkBehaviour,
    stream_behaviour::StreamEvent,
    config::NetworkRuntimeConfig,
};

/// Commands sent to the network task
pub enum NetworkCommand {
    /// Send a message to a specific peer
    Send {
        peer: VerifyingKey,
        message: Message,
    },
    /// Broadcast a message to all peers
    Broadcast {
        message: Message,
    },
    /// Update the validator set (for future use)
    UpdateValidatorSet {
        updates: ValidatorSetUpdates,
    },
    /// Shutdown the network
    Shutdown,
}

/// Events received from the network task
pub struct NetworkEvent {
    pub peer: VerifyingKey,
    pub message: Message,
}

/// Shutdown guard that handles network cleanup when the last reference is dropped
struct ShutdownGuard {
    command_sender: UnboundedSender<NetworkCommand>,
    task_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        // Only the last reference will trigger shutdown
        //info!("ShutdownGuard: Sending shutdown command to network task");
        let _ = self.command_sender.send(NetworkCommand::Shutdown);
        
        // Abort the task if it's still running
        if let Ok(mut handle) = self.task_handle.try_lock() {
            if let Some(task) = handle.take() {
                //info!("ShutdownGuard: Aborting network task");
                task.abort();
            }
        }
    }
}

/// LibP2P-based network implementation for Hotstuff
pub struct LibP2PNetwork {
    /// Channel to send commands to the network task
    command_sender: UnboundedSender<NetworkCommand>,
    /// Channel to receive messages from the network task
    message_receiver: Arc<Mutex<UnboundedReceiver<NetworkEvent>>>,
    /// Channel to send loopback messages directly to self
    loopback_sender: UnboundedSender<NetworkEvent>,
    /// Runtime configuration
    config: NetworkRuntimeConfig,
    /// Local peer ID
    local_peer_id: PeerId,
    /// My verifying key for self-identification
    my_verifying_key: VerifyingKey,
    /// Shutdown guard - only the last reference will trigger shutdown
    _shutdown_guard: Arc<ShutdownGuard>,
}

impl LibP2PNetwork {
    /// Create a new LibP2P network instance
    pub async fn new(
        keypair: Keypair,
        config: NetworkRuntimeConfig,
        my_verifying_key: VerifyingKey,
    ) -> Result<Self> {
        let local_peer_id = PeerId::from(keypair.public());
        //info!("Starting LibP2P network with peer ID: {}", local_peer_id);

        // Create channels for communication with the network task
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, message_receiver) = mpsc::unbounded_channel();
        let message_receiver = Arc::new(Mutex::new(message_receiver));
        
        // Create loopback channel for self-messages
        let (loopback_sender, loopback_receiver) = mpsc::unbounded_channel();

        // Build the transport
        let transport = Self::build_transport(&keypair)?;

        // Create the composite behaviour
        let behaviour = HotstuffNetworkBehaviour::new(local_peer_id, keypair.public(), config.clone());

        // Create the swarm using the new API
        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .build();

        // Listen on configured addresses
        for addr in &config.listen_addresses {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => {} //info!("Listening on {}", addr),
                Err(e) => warn!("Failed to listen on {}: {}", addr, e),
            }
        }

        // Start dialing known peers (validators and listeners)
        for peer_id in config.all_peer_ids_including_listeners() {
            if peer_id != local_peer_id {
                if let Some(addresses) = config.get_peer_addresses(&peer_id) {
                    for addr in addresses {
                        //info!("Dialing peer {} at {}", peer_id, addr);
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("Failed to dial {}: {}", addr, e);
                        }
                    }
                }
            }
        }

        //info!("Spawning network task...");
        // Spawn the network task
        let config_for_task = config.clone();
        let task_handle = Arc::new(Mutex::new(Some(tokio::spawn(async move {
            //info!("Network task spawned, calling network_task function");
            Self::network_task(
                swarm,
                command_receiver,
                event_sender,
                loopback_receiver,
                config_for_task,
            ).await;
            //info!("Network task function returned");
        }))));

        // Create shutdown guard with cloned references
        let shutdown_guard = Arc::new(ShutdownGuard {
            command_sender: command_sender.clone(),
            task_handle: task_handle.clone(),
        });

        Ok(Self {
            command_sender,
            message_receiver,
            loopback_sender,
            config,
            local_peer_id,
            my_verifying_key,
            _shutdown_guard: shutdown_guard,
        })
    }

    /// Build the libp2p transport with QUIC support
    fn build_transport(keypair: &Keypair) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
        use libp2p::core::Transport;
        
        // Configure QUIC with basic settings (many advanced options not available in current libp2p version)
        let quic_config = quic::Config::new(keypair);
        
        // Configure Yamux with better settings for consensus
        let mut yamux_config = yamux::Config::default();
        yamux_config.set_max_num_streams(1000);           // Allow more streams
        // Note: Some yamux config methods are deprecated but still functional
        
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(keypair).unwrap())
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20)) // Add transport-level timeout
            .or_transport(quic::tokio::Transport::new(quic_config))
            .map(|either_output, _| match either_output {
                futures::future::Either::Left((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
                futures::future::Either::Right((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
            })
            .boxed();

        Ok(transport)
    }

    /// Main network task that handles swarm events and commands
    async fn network_task(
        mut swarm: Swarm<HotstuffNetworkBehaviour>,
        mut command_receiver: UnboundedReceiver<NetworkCommand>,
        event_sender: UnboundedSender<NetworkEvent>,
        mut loopback_receiver: UnboundedReceiver<NetworkEvent>,
        config: NetworkRuntimeConfig,
    ) {

        println!("Starting Network Task");

        // Set up panic hook to catch any panics in this task
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            error!("Network task panic: {}", panic_info);
            default_hook(panic_info);
        }));

        println!("Set Hook");

        let mut reconnect_interval = tokio::time::interval(Duration::from_secs(15)); // More frequent reconnection attempts
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(120)); // Less frequent cleanup

        //info!("Network task is ready");
        println!("Network task is ready");

        //info!("Network task: Entering main event loop");
        loop {
            let loop_result: Result<bool, Box<dyn std::error::Error + Send + Sync>> = tokio::select! {
                // Handle swarm events
                maybe_event = swarm.next() => {
                    match maybe_event {
                        Some(event_result) => {
                            //info!("Network task: Received swarm event");
                            match event_result {
                        SwarmEvent::Behaviour(composite_event) => {
                            //info!("Handling behaviour event: {:?}", std::mem::discriminant(&composite_event));
                            if let Some(stream_event) = composite_event.into_stream_event(&config) {
                                Self::handle_behaviour_event(stream_event, &event_sender, &config).await;
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            //info!("Connection established with peer: {}", peer_id);
                            swarm.behaviour_mut().handle_connection_established(peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            //info!("Connection closed with peer {}: {:?}", peer_id, cause);
                            swarm.behaviour_mut().handle_connection_closed(peer_id);
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            //info!("Local node is listening on {}", address);
                        }
                        SwarmEvent::IncomingConnection { .. } => {
                            //info!("Incoming connection");
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("Incoming connection error: {}", error);
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            warn!("❌ Outgoing connection error to {:?}: {}", peer_id, error);
                            // Log more detailed error information
                            match &error {
                                libp2p::swarm::DialError::Transport(transports) => {
                                    for (addr, transport_error) in transports {
                                        warn!("  Transport error for {}: {}", addr, transport_error);
                                    }
                                }
                                libp2p::swarm::DialError::NoAddresses => {
                                    warn!("  No addresses available for peer {:?}", peer_id);
                                }
                                libp2p::swarm::DialError::LocalPeerId { .. } => {
                                    warn!("  Attempted to dial local peer ID");
                                }
                                libp2p::swarm::DialError::Aborted => {
                                    warn!("  Connection attempt was aborted");
                                }
                                libp2p::swarm::DialError::WrongPeerId { obtained, endpoint } => {
                                    warn!("  Wrong peer ID: expected {:?}, got {:?} at {:?}", peer_id, obtained, endpoint);
                                }
                                libp2p::swarm::DialError::Denied { cause } => {
                                    warn!("  Connection denied: {}", cause);
                                }
                                libp2p::swarm::DialError::DialPeerConditionFalse(_) => {
                                    warn!("  Dial peer condition was false");
                                }
                            }
                        }
                        SwarmEvent::Dialing { peer_id, connection_id } => {
                            debug!("Dialing peer {:?} with connection {:?}", peer_id, connection_id);
                        }
                        SwarmEvent::ExpiredListenAddr { address, .. } => {
                            warn!("Listen address expired: {}", address);
                        }
                        SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                            warn!("Listener closed for addresses {:?}, reason: {:?}", addresses, reason);
                        }
                        SwarmEvent::ListenerError { error, .. } => {
                            error!("Listener error: {}", error);
                        }
                        event => {
                            debug!("Unhandled swarm event: {:?}", std::mem::discriminant(&event));
                        }
                    }
                    Ok(false) // Continue loop
                        }
                        None => {
                            error!("Network task: Swarm stream ended unexpectedly!");
                            Ok(true) // Exit loop
                        }
                    }
                }

                // Handle commands from the Network trait implementation
                command = command_receiver.recv() => {
                    debug!("Network task: Received command");
                    match command {
                        Some(NetworkCommand::Send { peer, message }) => {
                            //info!("📨 Network task: Processing Send command for peer {:?}", hex::encode(&peer.to_bytes()[..8]));
                            Self::handle_send_command(&mut swarm, peer, message, &config).await;
                            Ok(false) // Continue loop
                        }
                        Some(NetworkCommand::Broadcast { message }) => {
                            debug!("Network task: Processing Broadcast command");
                            Self::handle_broadcast_command(&mut swarm, message).await;
                            Ok(false) // Continue loop
                        }
                        Some(NetworkCommand::UpdateValidatorSet { updates: _ }) => {
                            // TODO: Handle validator set updates
                            debug!("Validator set update received (not implemented)");
                            Ok(false) // Continue loop
                        }
                        Some(NetworkCommand::Shutdown) => {
                            //info!("Network shutdown requested");
                            Ok(true) // Exit loop
                        }
                        None => {
                            //info!("Command channel closed, shutting down network task");
                            Ok(true) // Exit loop
                        }
                    }
                }

                // Handle loopback messages (self-delivery)
                loopback_event = loopback_receiver.recv() => {
                    match loopback_event {
                        Some(network_event) => {
                            //info!("🔄 Network task: Processing loopback message from self");
                            //info!("🔄 Loopback message type: {:?}", std::mem::discriminant(&network_event.message));
                            // Forward loopback message directly to event_sender
                            if let Err(e) = event_sender.send(network_event) {
                                error!("Failed to forward loopback message: {}", e);
                            } else {
                                //info!("✅ Loopback message forwarded successfully");
                            }
                            Ok(false) // Continue loop
                        }
                        None => {
                            //info!("Loopback channel closed");
                            Ok(false) // Continue loop - loopback channel closing shouldn't stop the network task
                        }
                    }
                }

                // Periodic reconnection attempts
                _ = reconnect_interval.tick() => {
                    debug!("Network task: Processing reconnection tick");
                    Self::handle_reconnection_attempts(&mut swarm, &config).await;
                    Ok(false) // Continue loop
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    debug!("Network task: Processing cleanup tick");
                    swarm.behaviour_mut().cleanup_expired_connections();
                    Ok(false) // Continue loop
                }
            };

            match loop_result {
                Ok(should_exit) => {
                    if should_exit {
                        break;
                    }
                    debug!("Network task: Completed select loop iteration");
                }
                Err(e) => {
                    error!("Network task: Error in select loop: {}", e);
                    break;
                }
            }
        }

        //info!("Network task shutting down");
    }

    /// Handle behaviour events from the swarm
    async fn handle_behaviour_event(
        event: StreamEvent,
        event_sender: &UnboundedSender<NetworkEvent>,
        config: &NetworkRuntimeConfig,
    ) {
        match event {
            StreamEvent::MessageReceived { peer_id, message, .. } => {
                //info!("🎯 StreamEvent::MessageReceived from peer_id: {}", peer_id);
                //info!("🎯 Message type: {:?}", std::mem::discriminant(&message));
                
                // Look up the verifying key for this peer
                if let Some(verifying_key) = config.get_verifying_key(&peer_id) {
                    //info!("🎯 Found verifying_key for peer: {:?}", hex::encode(&verifying_key.to_bytes()[..8]));
                    let network_event = NetworkEvent {
                        peer: verifying_key,
                        message,
                    };
                    
                    if let Err(e) = event_sender.send(network_event) {
                        error!("Failed to send network event: {}", e);
                    } else {
                        //info!("✅ Successfully forwarded message to HotStuff consensus");
                    }
                } else {
                    warn!("Received message from unknown peer: {}", peer_id);
                }
            }
            StreamEvent::MessageSent { peer_id } => {
                debug!("Message sent successfully to peer: {}", peer_id);
            }
            StreamEvent::SendFailed { peer_id, error } => {
                warn!("Failed to send message to peer {}: {}", peer_id, error);
            }
            StreamEvent::PeerIdentified { peer_id } => {
                debug!("Peer identified: {}", peer_id);
            }
            StreamEvent::ConnectionEstablished { peer_id } => {
                //info!("Behaviour reported connection established: {}", peer_id);
            }
            StreamEvent::ConnectionClosed { peer_id } => {
                //info!("Behaviour reported connection closed: {}", peer_id);
            }
        }
    }

    /// Handle send command
    async fn handle_send_command(
        swarm: &mut Swarm<HotstuffNetworkBehaviour>,
        peer: VerifyingKey,
        message: Message,
        config: &NetworkRuntimeConfig,
    ) {
        //info!("🔍 Looking up peer_id for VerifyingKey: {:?}", hex::encode(&peer.to_bytes()[..8]));
        if let Some(peer_id) = config.get_peer_id(&peer) {
            //info!("✅ Found peer_id: {} for VerifyingKey", peer_id);
            match swarm.behaviour_mut().send_message(peer_id, message) {
                Ok(_) => {
                    //info!("✅ Message queued for peer: {}", peer_id);
                }
                Err(e) => {
                    warn!("❌ Failed to queue message for peer {}: {}", peer_id, e);
                }
            }
        } else {
            error!("❌ Attempted to send message to unknown peer: {:?}", hex::encode(&peer.to_bytes()[..8]));
            //info!("🔍 Available peers in config:");
            for (vk, pid) in &config.verifying_key_to_peer_id {
                //info!("   - {:?} -> {}", hex::encode(&vk.to_bytes()[..8]), pid);
            }
        }
    }

    /// Handle broadcast command
    async fn handle_broadcast_command(
        swarm: &mut Swarm<HotstuffNetworkBehaviour>,
        message: Message,
    ) {
        let results = swarm.behaviour_mut().broadcast_message(message);
        let successful = results.iter().filter(|r| r.is_ok()).count();
        let failed = results.len() - successful;
        
        if failed > 0 {
            debug!("Broadcast: {} successful, {} failed", successful, failed);
        } else {
            debug!("Broadcast: {} messages queued", successful);
        }
    }

    /// Handle reconnection attempts for disconnected peers
    async fn handle_reconnection_attempts(
        swarm: &mut Swarm<HotstuffNetworkBehaviour>,
        config: &NetworkRuntimeConfig,
    ) {
        let peers_to_reconnect = swarm.behaviour().peers_needing_reconnection();
        
        if !peers_to_reconnect.is_empty() {
            //info!("🔄 Attempting reconnection to {} disconnected peers", peers_to_reconnect.len());
        }
        
        for peer_id in peers_to_reconnect {
            if let Some(addresses) = config.get_peer_addresses(&peer_id) {
                for addr in addresses {
                    debug!("Attempting to reconnect to peer {} at {}", peer_id, addr);
                    if let Err(e) = swarm.dial(addr.clone()) {
                        warn!("Failed to dial {} during reconnection: {}", addr, e);
                    }
                }
            }
        }
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }


    /// Get connection statistics
    pub fn connection_stats(&self) -> HashMap<String, usize> {
        // This would need to be implemented by querying the behaviour
        // For now, return empty stats
        HashMap::new()
    }
}

impl Clone for LibP2PNetwork {
    fn clone(&self) -> Self {
        Self {
            command_sender: self.command_sender.clone(),
            message_receiver: self.message_receiver.clone(),
            loopback_sender: self.loopback_sender.clone(),
            config: self.config.clone(),
            local_peer_id: self.local_peer_id,
            my_verifying_key: self.my_verifying_key,
            _shutdown_guard: self._shutdown_guard.clone(),
        }
    }
}

impl Network for LibP2PNetwork {
    fn init_validator_set(&mut self, _validator_set: ValidatorSet) {
        // The validator set is already configured during initialization
        // This is a no-op for now since we're using a fixed validator set
        debug!("init_validator_set called (no-op for fixed validator set)");
    }

    fn update_validator_set(&mut self, updates: ValidatorSetUpdates) {
        // Send update command to the network task
        let command = NetworkCommand::UpdateValidatorSet { updates };
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send validator set update command: {}", e);
        }
    }

    fn send(&mut self, peer: VerifyingKey, message: Message) {
        //info!("🌐 LibP2PNetwork::send called for peer: {:?}", hex::encode(&peer.to_bytes()[..8]));
        //info!("📤 Message type: {:?}", std::mem::discriminant(&message));
        
        // Check if this is a self-message
        if peer == self.my_verifying_key {
            //info!("🔄 Self-message detected, delivering via loopback (skipping LibP2P)");
            // Create a NetworkEvent for immediate self-delivery
            let network_event = NetworkEvent {
                peer: self.my_verifying_key,
                message,
            };
            
            // Send via loopback channel
            if let Err(e) = self.loopback_sender.send(network_event) {
                error!("Failed to send loopback message: {}", e);
            } else {
                //info!("✅ Self-message sent via loopback channel");
            }
            return;
        }
        
        // Not a self-message, use normal LibP2P path
        let command = NetworkCommand::Send { peer, message };
        // println!("Sending message to peer: {:?}", peer);
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send message command: {}", e);
        } else {
            //info!("✅ Command sent to network task successfully");
        }
    }

    fn broadcast(&mut self, message: Message) {
        //info!("📻 LibP2PNetwork::broadcast called");
        //info!("📻 Broadcast message type: {:?}", std::mem::discriminant(&message));
        
        // For broadcast, we need to handle self-delivery AND send to others
        // First, deliver to self via loopback
        let network_event = NetworkEvent {
            peer: self.my_verifying_key,
            message: message.clone(),
        };
        
        if let Err(e) = self.loopback_sender.send(network_event) {
            error!("Failed to send loopback broadcast message: {}", e);
        } else {
            //info!("✅ Broadcast self-message sent via loopback");
        }
        
        // Then send to others via LibP2P
        let command = NetworkCommand::Broadcast { message };
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send broadcast command: {}", e);
        } else {
            //info!("✅ Broadcast command sent to network task successfully");
        }
    }

    fn recv(&mut self) -> Option<(VerifyingKey, Message)> {
        // Try to receive a message from the network task
        if let Ok(mut receiver) = self.message_receiver.try_lock() {
            match receiver.try_recv() {
                Ok(event) => {
                    //info!("📥 LibP2PNetwork::recv got message from peer: {:?}", hex::encode(&event.peer.to_bytes()[..8]));
                    //info!("📥 Message type: {:?}", std::mem::discriminant(&event.message));
                    //info!("🎯 RETURNING MESSAGE TO HOTSTUFF: peer={:?}, type={:?}", 
                        //   hex::encode(&event.peer.to_bytes()[..8]), 
                        //   std::mem::discriminant(&event.message));
                    Some((event.peer, event.message))
                },
                Err(mpsc::error::TryRecvError::Empty) => {
                    None
                },
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    error!("Network event channel disconnected");
                    None
                }
            }
        } else {
            // Could not acquire lock, return None
            None
        }
    }
}

// Drop implementation removed - shutdown is now handled by ShutdownGuard
// when the last Arc reference is dropped

/// Helper function to create a libp2p keypair from raw Ed25519 private key bytes
/// This allows using the same key material for both HotStuff and libp2p
pub fn create_libp2p_keypair_from_bytes(private_key_bytes: &[u8; 32]) -> Result<Keypair> {
    // Create libp2p Ed25519 keypair from the private key bytes
    // libp2p_identity::ed25519::Keypair::try_from_bytes expects a 64-byte array (private + public key)
    // But we only have the 32-byte private key, so we'll use the from_secret_key approach
    let secret_key = libp2p_identity::ed25519::SecretKey::try_from_bytes(private_key_bytes.clone())
        .map_err(|e| anyhow!("Failed to create Ed25519 secret key: {}", e))?;
    
    let ed25519_keypair = libp2p_identity::ed25519::Keypair::from(secret_key);
    Ok(Keypair::from(ed25519_keypair))
}

/// Create a libp2p keypair from a HotStuff validator SigningKey
/// This ensures both the consensus layer and networking layer use the same cryptographic identity
pub fn create_libp2p_keypair_from_validator(validator_signing_key: &hotstuff_rs::types::crypto_primitives::SigningKey) -> Result<Keypair> {
    // Extract the 32-byte private key from the validator's SigningKey
    let private_key_bytes = validator_signing_key.to_bytes();
    
    // Create libp2p Ed25519 keypair from the same private key bytes
    create_libp2p_keypair_from_bytes(&private_key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::config::NetworkConfig;

    #[tokio::test]
    async fn test_network_creation() {
        // Generate a validator keypair
        use crate::validator_keys::generate_validator_keypair;
        let validator_keypair = generate_validator_keypair();
        let verifying_key = validator_keypair.verifying_key();
        
        let keypair = Keypair::generate_ed25519();
        let config = NetworkRuntimeConfig::from_network_config(
            NetworkConfig::default()
        ).unwrap();

        let result = LibP2PNetwork::new(keypair, config, verifying_key).await;
        assert!(result.is_ok());

        let network = result.unwrap();
        assert!(!network.local_peer_id().to_string().is_empty());
    }

    #[test]
    fn test_keypair_conversion() {
        use crate::validator_keys::generate_validator_keypair;
        
        // Generate a validator keypair
        let validator_keypair = generate_validator_keypair();
        let validator_public_key = validator_keypair.verifying_key().to_bytes();
        
        // Convert to libp2p keypair
        let libp2p_keypair = create_libp2p_keypair_from_validator(&validator_keypair).unwrap();
        let libp2p_peer_id = PeerId::from(libp2p_keypair.public());
        
        // Verify the conversion worked
        assert!(!libp2p_peer_id.to_string().is_empty());
        
        // The peer ID should be deterministic from the same private key
        let libp2p_keypair2 = create_libp2p_keypair_from_validator(&validator_keypair).unwrap();
        let libp2p_peer_id2 = PeerId::from(libp2p_keypair2.public());
        assert_eq!(libp2p_peer_id, libp2p_peer_id2);
        
        println!("✅ Validator public key: {}", hex::encode(validator_public_key));
        println!("✅ LibP2P peer ID: {}", libp2p_peer_id);
    }
}
