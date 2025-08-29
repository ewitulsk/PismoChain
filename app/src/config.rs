use serde::{Deserialize, Serialize};
use std::fs;
use std::env;

/// Main configuration structure for the PismoChain CounterApp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: u16,
    pub network: String,
    pub sui: Sui,
}

/// Sui-specific configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sui {
    pub pismo_locker_address: String
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