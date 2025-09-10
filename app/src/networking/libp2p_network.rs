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

use hotstuff_rs::{
    networking::{network::Network, messages::Message},
    types::{
        crypto_primitives::VerifyingKey,
        update_sets::ValidatorSetUpdates,
        validator_set::ValidatorSet,
    },
};

use crate::networking::{
    behaviour::{HotstuffBehaviour, HotstuffEvent},
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
        info!("ShutdownGuard: Sending shutdown command to network task");
        let _ = self.command_sender.send(NetworkCommand::Shutdown);
        
        // Abort the task if it's still running
        if let Ok(mut handle) = self.task_handle.try_lock() {
            if let Some(task) = handle.take() {
                info!("ShutdownGuard: Aborting network task");
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
    /// Runtime configuration
    config: NetworkRuntimeConfig,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Shutdown guard - only the last reference will trigger shutdown
    _shutdown_guard: Arc<ShutdownGuard>,
}

impl LibP2PNetwork {
    /// Create a new LibP2P network instance
    pub async fn new(
        keypair: Keypair,
        config: NetworkRuntimeConfig,
    ) -> Result<Self> {
        let local_peer_id = PeerId::from(keypair.public());
        info!("Starting LibP2P network with peer ID: {}", local_peer_id);

        // Create channels for communication with the network task
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, message_receiver) = mpsc::unbounded_channel();
        let message_receiver = Arc::new(Mutex::new(message_receiver));

        // Build the transport
        let transport = Self::build_transport(&keypair)?;

        // Create the behaviour
        let behaviour = HotstuffBehaviour::new(local_peer_id, keypair.public(), config.clone());

        // Create the swarm using the new API
        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behaviour)?
            .build();

        // Listen on configured addresses
        for addr in &config.listen_addresses {
            match swarm.listen_on(addr.clone()) {
                Ok(_) => info!("Listening on {}", addr),
                Err(e) => warn!("Failed to listen on {}: {}", addr, e),
            }
        }

        // Start dialing known peers
        for peer_id in config.all_peer_ids() {
            if peer_id != local_peer_id {
                if let Some(addresses) = config.get_peer_addresses(&peer_id) {
                    for addr in addresses {
                        info!("Dialing peer {} at {}", peer_id, addr);
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("Failed to dial {}: {}", addr, e);
                        }
                    }
                }
            }
        }

        info!("Spawning network task...");
        // Spawn the network task
        let config_for_task = config.clone();
        let task_handle = Arc::new(Mutex::new(Some(tokio::spawn(async move {
            info!("Network task spawned, calling network_task function");
            Self::network_task(
                swarm,
                command_receiver,
                event_sender,
                config_for_task,
            ).await;
            info!("Network task function returned");
        }))));

        // Create shutdown guard with cloned references
        let shutdown_guard = Arc::new(ShutdownGuard {
            command_sender: command_sender.clone(),
            task_handle: task_handle.clone(),
        });

        Ok(Self {
            command_sender,
            message_receiver,
            config,
            local_peer_id,
            _shutdown_guard: shutdown_guard,
        })
    }

    /// Build the libp2p transport with QUIC support
    fn build_transport(keypair: &Keypair) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
        use libp2p::core::Transport;
        
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(keypair).unwrap())
            .multiplex(yamux::Config::default())
            .or_transport(quic::tokio::Transport::new(quic::Config::new(keypair)))
            .map(|either_output, _| match either_output {
                futures::future::Either::Left((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
                futures::future::Either::Right((peer_id, muxer)) => (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer)),
            })
            .boxed();

        Ok(transport)
    }

    /// Main network task that handles swarm events and commands
    async fn network_task(
        mut swarm: Swarm<HotstuffBehaviour>,
        mut command_receiver: UnboundedReceiver<NetworkCommand>,
        event_sender: UnboundedSender<NetworkEvent>,
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

        let mut reconnect_interval = tokio::time::interval(Duration::from_secs(30));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        info!("Network task is ready");
        println!("Network task is ready");

        info!("Network task: Entering main event loop");
        loop {
            info!("Network task: Starting select loop iteration");
            
            // Wrap each select operation in a result for better error handling
            info!("Network task: About to enter tokio::select!");
            let loop_result: Result<bool, Box<dyn std::error::Error + Send + Sync>> = tokio::select! {
                // Handle swarm events
                maybe_event = swarm.next() => {
                    match maybe_event {
                        Some(event_result) => {
                            info!("Network task: Received swarm event");
                            match event_result {
                        SwarmEvent::Behaviour(hotstuff_event) => {
                            info!("Handling behaviour event: {:?}", std::mem::discriminant(&hotstuff_event));
                            Self::handle_behaviour_event(hotstuff_event, &event_sender, &config).await;
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            info!("Connection established with peer: {}", peer_id);
                            swarm.behaviour_mut().handle_connection_established(peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            info!("Connection closed with peer {}: {:?}", peer_id, cause);
                            swarm.behaviour_mut().handle_connection_closed(peer_id);
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Local node is listening on {}", address);
                        }
                        SwarmEvent::IncomingConnection { .. } => {
                            info!("Incoming connection");
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("Incoming connection error: {}", error);
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            warn!("Outgoing connection error to {:?}: {}", peer_id, error);
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
                            debug!("Network task: Processing Send command for peer {:?}", peer);
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
                            info!("Network shutdown requested");
                            Ok(true) // Exit loop
                        }
                        None => {
                            info!("Command channel closed, shutting down network task");
                            Ok(true) // Exit loop
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
                    swarm.behaviour_mut().cleanup_expired_requests();
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

        info!("Network task shutting down");
    }

    /// Handle behaviour events from the swarm
    async fn handle_behaviour_event(
        event: HotstuffEvent,
        event_sender: &UnboundedSender<NetworkEvent>,
        config: &NetworkRuntimeConfig,
    ) {
        match event {
            HotstuffEvent::MessageReceived { peer_id, message, .. } => {
                // Look up the verifying key for this peer
                if let Some(verifying_key) = config.get_verifying_key(&peer_id) {
                    let network_event = NetworkEvent {
                        peer: verifying_key,
                        message,
                    };
                    
                    if let Err(e) = event_sender.send(network_event) {
                        error!("Failed to send network event: {}", e);
                    }
                } else {
                    warn!("Received message from unknown peer: {}", peer_id);
                }
            }
            HotstuffEvent::MessageSent { peer_id, .. } => {
                debug!("Message sent successfully to peer: {}", peer_id);
            }
            HotstuffEvent::SendFailed { peer_id, error } => {
                warn!("Failed to send message to peer {}: {}", peer_id, error);
            }
            HotstuffEvent::PeerIdentified { peer_id } => {
                debug!("Peer identified: {}", peer_id);
            }
            HotstuffEvent::ConnectionEstablished { peer_id } => {
                info!("Behaviour reported connection established: {}", peer_id);
            }
            HotstuffEvent::ConnectionClosed { peer_id } => {
                info!("Behaviour reported connection closed: {}", peer_id);
            }
        }
    }

    /// Handle send command
    async fn handle_send_command(
        swarm: &mut Swarm<HotstuffBehaviour>,
        peer: VerifyingKey,
        message: Message,
        config: &NetworkRuntimeConfig,
    ) {
        if let Some(peer_id) = config.get_peer_id(&peer) {
            match swarm.behaviour_mut().send_message(peer_id, message) {
                Ok(_) => {
                    debug!("Message queued for peer: {}", peer_id);
                }
                Err(e) => {
                    debug!("Failed to queue message for peer {}: {}", peer_id, e);
                }
            }
        } else {
            warn!("Attempted to send message to unknown peer: {:?}", peer);
        }
    }

    /// Handle broadcast command
    async fn handle_broadcast_command(
        swarm: &mut Swarm<HotstuffBehaviour>,
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
        swarm: &mut Swarm<HotstuffBehaviour>,
        config: &NetworkRuntimeConfig,
    ) {
        let peers_to_reconnect = swarm.behaviour().peers_needing_reconnection();
        
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
            config: self.config.clone(),
            local_peer_id: self.local_peer_id,
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
        let command = NetworkCommand::Send { peer, message };
        println!("Sending message to peer: {:?}", peer);
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send message command: {}", e);
        }
    }

    fn broadcast(&mut self, message: Message) {
        let command = NetworkCommand::Broadcast { message };
        if let Err(e) = self.command_sender.send(command) {
            error!("Failed to send broadcast command: {}", e);
        }
    }

    fn recv(&mut self) -> Option<(VerifyingKey, Message)> {
        // Try to receive a message from the network task
        if let Ok(mut receiver) = self.message_receiver.try_lock() {
            match receiver.try_recv() {
                Ok(event) => Some((event.peer, event.message)),
                Err(mpsc::error::TryRecvError::Empty) => None,
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
        let keypair = Keypair::generate_ed25519();
        let config = NetworkRuntimeConfig::from_network_config(
            NetworkConfig::default()
        ).unwrap();

        let result = LibP2PNetwork::new(keypair, config).await;
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
