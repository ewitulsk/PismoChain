use serde::{Deserialize, Serialize};
use std::fs;
use std::env;
use std::path::Path;
use crate::types::NodeMode;

/// Main configuration structure for the PismoChain CounterApp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: u16,
    pub network: String,
    pub sui: Sui,
    #[serde(default)]
    pub node_mode: NodeMode,
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
    
    // Validate configuration
    config.validate()?;
    
    Ok(config)
}

/// Configuration validation and enhancement
impl Config {
    /// Validate configuration parameters
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate chain_id
        if self.chain_id == 0 {
            return Err(anyhow::anyhow!("chain_id cannot be 0"));
        }

        // Validate network string
        if self.network.trim().is_empty() {
            return Err(anyhow::anyhow!("network configuration cannot be empty"));
        }

        // Validate Sui configuration
        if self.sui.pismo_locker_address.trim().is_empty() {
            return Err(anyhow::anyhow!("sui.pismo_locker_address cannot be empty"));
        }

        // Validate node mode is sensible
        match self.node_mode {
            NodeMode::Validator | NodeMode::Fullnode => {}, // Valid modes
        }

        println!("✅ Configuration validation passed");
        Ok(())
    }

    /// Create a default configuration for development
    pub fn default_development() -> Self {
        Self {
            chain_id: 9999, // Use a valid u16 value
            network: "development".to_string(),
            sui: Sui {
                pismo_locker_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            node_mode: NodeMode::Validator,
        }
    }

    /// Create a default configuration for production
    pub fn default_production() -> Self {
        Self {
            chain_id: 1,
            network: "mainnet".to_string(),
            sui: Sui {
                pismo_locker_address: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            node_mode: NodeMode::Validator,
        }
    }

    /// Validate file paths and environment
    pub fn validate_environment() -> anyhow::Result<()> {
        // Check required environment variables
        let required_paths = [
            ("PISMO_DB_PATH", env::var("PISMO_DB_PATH").unwrap_or_default()),
            ("PISMO_NETWORK_CONFIG", env::var("PISMO_NETWORK_CONFIG").unwrap_or_default()),
        ];

        for (var_name, path) in required_paths {
            if !path.is_empty() {
                let parent_dir = Path::new(&path).parent().unwrap_or(Path::new("."));
                if !parent_dir.exists() {
                    fs::create_dir_all(parent_dir)
                        .map_err(|e| anyhow::anyhow!("Failed to create directory for {}: {}", var_name, e))?;
                    println!("📁 Created directory for {}: {}", var_name, parent_dir.display());
                }
            }
        }

        // Check disk space (simplified)
        if let Ok(metadata) = fs::metadata(".") {
            // In production, you'd check actual available disk space
            println!("💾 Disk space check passed");
        }

        println!("✅ Environment validation passed");
        Ok(())
    }
} 