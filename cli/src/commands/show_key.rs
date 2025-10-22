use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use pismo_chain::validator_keys::load_validator_keys;
use pismo_chain::networking::create_libp2p_keypair_from_validator;
use crate::types::{ValidatorKeysJson, KeyInfo};

pub fn show_key_command(input_path: &PathBuf) -> Result<()> {
    // Read and parse the JSON file to extract metadata
    let json_content = fs::read_to_string(input_path)
        .context("Failed to read validator keys file")?;
    
    let keys_json: ValidatorKeysJson = serde_json::from_str(&json_content)
        .context("Failed to parse validator keys JSON")?;
    
    // Load validator keypair from file (validates and constructs the keypair)
    let signing_key = load_validator_keys(input_path)
        .context("Failed to load validator keys")?;
    
    // Extract verifying key (public key) as hex
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();
    let verifying_key_hex = hex::encode(verifying_key_bytes);
    
    // Convert to libp2p keypair to get PeerId
    let libp2p_keypair = create_libp2p_keypair_from_validator(&signing_key)
        .context("Failed to create libp2p keypair")?;
    
    let peer_id = libp2p_keypair.public().to_peer_id().to_string();
    
    // Create output structure with metadata
    let key_info = KeyInfo {
        version: keys_json.version,
        algorithm: keys_json.algorithm,
        verifying_key: verifying_key_hex,
        peer_id,
    };
    
    // Output as JSON
    let json_output = serde_json::to_string_pretty(&key_info)
        .context("Failed to serialize key info")?;
    
    println!("{}", json_output);
    
    Ok(())
}

