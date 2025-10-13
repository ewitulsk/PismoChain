use std::{collections::HashMap, time::Duration};
use serde::{Deserialize, Serialize};
use hotstuff_rs::types::crypto_primitives::VerifyingKey;
use libp2p::{PeerId, Multiaddr};

/// Configuration for a single validator in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// The validator's verifying key (used by hotstuff consensus)
    pub verifying_key: String, // hex-encoded
    /// The validator's libp2p peer ID
    pub peer_id: String,
    /// List of multiaddresses where this validator can be reached
    pub multiaddrs: Vec<String>,
}

/// Configuration for a single listener in the network
/// Listeners replicate the block tree but don't participate in consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// The listener's verifying key (for identification)
    pub verifying_key: String, // hex-encoded
    /// The listener's libp2p peer ID
    pub peer_id: String,
    /// List of multiaddresses where this listener can be reached
    pub multiaddrs: Vec<String>,
}

/// Network configuration for the libp2p layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// List of all validators in the network
    pub validators: Vec<ValidatorConfig>,
    /// List of all listeners in the network (optional)
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    /// Local listen addresses
    pub listen_addresses: Vec<String>,
    /// Connection timeout
    pub connection_timeout: Option<u64>, // seconds
    /// Maximum number of connections per peer
    pub max_connections_per_peer: Option<u32>,
    /// Message queue size
    pub message_queue_size: Option<usize>,
    /// Connection retry attempts
    pub max_retry_attempts: Option<u32>,
    /// Retry backoff base duration in milliseconds
    pub retry_backoff_base_ms: Option<u64>,
    /// Substream creation timeout in seconds
    pub substream_timeout: Option<u64>,
    /// Protocol handshake timeout in seconds
    pub handshake_timeout: Option<u64>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            listeners: Vec::new(),
            listen_addresses: vec!["/ip4/0.0.0.0/udp/0/quic-v1".to_string()],
            connection_timeout: Some(20),
            max_connections_per_peer: Some(1),
            message_queue_size: Some(1000),
            max_retry_attempts: Some(3),
            retry_backoff_base_ms: Some(500),
            substream_timeout: Some(10),
            handshake_timeout: Some(15),
        }
    }
}

/// Runtime configuration for network operations
#[derive(Debug, Clone)]
pub struct NetworkRuntimeConfig {
    /// Mapping from VerifyingKey to PeerId
    pub verifying_key_to_peer_id: HashMap<VerifyingKey, PeerId>,
    /// Mapping from PeerId to VerifyingKey
    pub peer_id_to_verifying_key: HashMap<PeerId, VerifyingKey>,
    /// Mapping from PeerId to multiaddresses
    pub peer_addresses: HashMap<PeerId, Vec<Multiaddr>>,
    /// Local listen addresses
    pub listen_addresses: Vec<Multiaddr>,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Maximum connections per peer
    pub max_connections_per_peer: u32,
    /// Message queue size
    pub message_queue_size: usize,
    /// Maximum retry attempts
    pub max_retry_attempts: u32,
    /// Retry backoff base duration
    pub retry_backoff_base: Duration,
    /// Substream creation timeout
    pub substream_timeout: Duration,
    /// Protocol handshake timeout
    pub handshake_timeout: Duration,
}

impl NetworkRuntimeConfig {
    /// Create runtime config from network config
    pub fn from_network_config(config: NetworkConfig) -> anyhow::Result<Self> {
        let mut verifying_key_to_peer_id = HashMap::new();
        let mut peer_id_to_verifying_key = HashMap::new();
        let mut peer_addresses = HashMap::new();

        // Process validators
        for validator in config.validators {
            // Parse verifying key
            let vk_bytes = hex::decode(&validator.verifying_key)?;
            let verifying_key = VerifyingKey::try_from(vk_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("Invalid verifying key: {:?}", e))?;

            // Parse peer ID
            let peer_id: PeerId = validator.peer_id.parse()
                .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;

            // Parse multiaddresses
            let multiaddrs: Result<Vec<Multiaddr>, _> = validator.multiaddrs
                .iter()
                .map(|addr| addr.parse())
                .collect();
            let multiaddrs = multiaddrs
                .map_err(|e| anyhow::anyhow!("Invalid multiaddr: {}", e))?;

            // Store mappings
            verifying_key_to_peer_id.insert(verifying_key, peer_id);
            peer_id_to_verifying_key.insert(peer_id, verifying_key);
            peer_addresses.insert(peer_id, multiaddrs);
        }

        // Process listeners
        for listener in config.listeners {
            // Parse verifying key
            let vk_bytes = hex::decode(&listener.verifying_key)?;
            let verifying_key = VerifyingKey::try_from(vk_bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("Invalid listener verifying key: {:?}", e))?;

            // Parse peer ID
            let peer_id: PeerId = listener.peer_id.parse()
                .map_err(|e| anyhow::anyhow!("Invalid listener peer ID: {}", e))?;

            // Parse multiaddresses
            let multiaddrs: Result<Vec<Multiaddr>, _> = listener.multiaddrs
                .iter()
                .map(|addr| addr.parse())
                .collect();
            let multiaddrs = multiaddrs
                .map_err(|e| anyhow::anyhow!("Invalid listener multiaddr: {}", e))?;

            // Store mappings (same as validators)
            verifying_key_to_peer_id.insert(verifying_key, peer_id);
            peer_id_to_verifying_key.insert(peer_id, verifying_key);
            peer_addresses.insert(peer_id, multiaddrs);
        }

        // Parse listen addresses
        let listen_addresses: Result<Vec<Multiaddr>, _> = config.listen_addresses
            .iter()
            .map(|addr| addr.parse())
            .collect();
        let listen_addresses = listen_addresses
            .map_err(|e| anyhow::anyhow!("Invalid listen address: {}", e))?;

        Ok(Self {
            verifying_key_to_peer_id,
            peer_id_to_verifying_key,
            peer_addresses,
            listen_addresses,
            connection_timeout: Duration::from_secs(config.connection_timeout.unwrap_or(20)),
            max_connections_per_peer: config.max_connections_per_peer.unwrap_or(1),
            message_queue_size: config.message_queue_size.unwrap_or(1000),
            max_retry_attempts: config.max_retry_attempts.unwrap_or(3),
            retry_backoff_base: Duration::from_millis(config.retry_backoff_base_ms.unwrap_or(500)),
            substream_timeout: Duration::from_secs(config.substream_timeout.unwrap_or(10)),
            handshake_timeout: Duration::from_secs(config.handshake_timeout.unwrap_or(15)),
        })
    }

    /// Get peer ID for a verifying key
    pub fn get_peer_id(&self, verifying_key: &VerifyingKey) -> Option<PeerId> {
        self.verifying_key_to_peer_id.get(verifying_key).copied()
    }

    /// Get verifying key for a peer ID
    pub fn get_verifying_key(&self, peer_id: &PeerId) -> Option<VerifyingKey> {
        self.peer_id_to_verifying_key.get(peer_id).copied()
    }

    /// Get multiaddresses for a peer ID
    pub fn get_peer_addresses(&self, peer_id: &PeerId) -> Option<&[Multiaddr]> {
        self.peer_addresses.get(peer_id).map(|addrs| addrs.as_slice())
    }

    /// Get all known peer IDs (validators and listeners)
    pub fn all_peer_ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peer_id_to_verifying_key.keys().copied()
    }

    /// Get all peer IDs including listeners (same as all_peer_ids since listeners are now in the same map)
    /// This method exists for clarity when broadcasting to all peers
    pub fn all_peer_ids_including_listeners(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peer_id_to_verifying_key.keys().copied()
    }
}

/// Load network configuration from a TOML file
pub fn load_network_config(path: &str) -> anyhow::Result<NetworkConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: NetworkConfig = toml::from_str(&contents)?;
    Ok(config)
}

/// Save network configuration to a TOML file
pub fn save_network_config(config: &NetworkConfig, path: &str) -> anyhow::Result<()> {
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_serialization() {
        let config = NetworkConfig {
            validators: vec![
                ValidatorConfig {
                    verifying_key: "abcd1234".to_string(),
                    peer_id: "12D3KooWTest".to_string(),
                    multiaddrs: vec!["/ip4/127.0.0.1/udp/9000/quic-v1".to_string()],
                }
            ],
            listen_addresses: vec!["/ip4/0.0.0.0/udp/0/quic-v1".to_string()],
            ..Default::default()
        };

        let serialized = toml::to_string(&config).unwrap();
        let deserialized: NetworkConfig = toml::from_str(&serialized).unwrap();
        
        assert_eq!(config.validators.len(), deserialized.validators.len());
        assert_eq!(config.listen_addresses, deserialized.listen_addresses);
    }
}
