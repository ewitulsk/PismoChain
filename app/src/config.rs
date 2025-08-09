use serde::{Deserialize, Serialize};
use std::fs;
use std::env;
use multiaddr::Multiaddr;
use hotstuff_rs::types::crypto_primitives::VerifyingKey;

/// Main configuration structure for the PismoChain CounterApp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub sui: Sui,
    #[serde(default)]
    pub network: NetworkConfig,
}

/// Sui-specific configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sui {
    pub pismo_locker_address: String
}

/// Network configuration for libp2p
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Address to listen on (e.g., "/ip4/0.0.0.0/udp/30333/quic-v1")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    
    /// Bootstrap peers with their verifying keys and addresses
    #[serde(default)]
    pub bootstrap_peers: Vec<BootstrapPeer>,
    
    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    
    /// Enable single-node mode (uses MockNetwork instead of libp2p)
    #[serde(default = "default_single_node")]
    pub single_node_mode: bool,
}

/// Bootstrap peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapPeer {
    /// Hex-encoded verifying key (32 bytes)
    pub verifying_key: String,
    /// Multiaddr of the peer (e.g., "/ip4/192.168.1.1/udp/30333/quic-v1")
    pub address: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            bootstrap_peers: Vec::new(),
            max_message_size: default_max_message_size(),
            single_node_mode: default_single_node(),
        }
    }
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/udp/30333/quic-v1".to_string()
}

fn default_max_message_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_single_node() -> bool {
    true // Default to single-node mode for backward compatibility
}

impl NetworkConfig {
    /// Convert to libp2p network config
    pub fn to_libp2p_config(&self) -> anyhow::Result<crate::networking::libp2p_network::NetworkConfig> {
        let listen_addr: Multiaddr = self.listen_addr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid listen address: {}", e))?;
        
        let mut bootstrap_peers = Vec::new();
        for peer in &self.bootstrap_peers {
            let vk_bytes = hex::decode(&peer.verifying_key)
                .map_err(|e| anyhow::anyhow!("Invalid verifying key hex: {}", e))?;
            
            if vk_bytes.len() != 32 {
                return Err(anyhow::anyhow!("Verifying key must be 32 bytes"));
            }
            
            let mut vk_array = [0u8; 32];
            vk_array.copy_from_slice(&vk_bytes);
            // Create a temporary signing key from the bytes to derive the verifying key
            // In production, you would store the actual verifying key directly
            let temp_signing_key = hotstuff_rs::types::crypto_primitives::SigningKey::from(vk_array);
            let verifying_key = temp_signing_key.verifying_key();
            
            let addr: Multiaddr = peer.address.parse()
                .map_err(|e| anyhow::anyhow!("Invalid peer address: {}", e))?;
            
            bootstrap_peers.push((verifying_key, addr));
        }
        
        Ok(crate::networking::libp2p_network::NetworkConfig {
            listen_addr,
            bootstrap_peers,
            max_message_size: self.max_message_size,
        })
    }
}

pub fn load_config() -> anyhow::Result<Config> {
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config/testnet.toml".to_string());
    
    println!("📄 Loading configuration from: {}", config_path);
    
    let content = fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", config_path, e))?;
    
    let config: Config = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", config_path, e))?;
    
    println!("✅ Configuration loaded successfully");
    Ok(config)
} 