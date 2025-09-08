//! Validator keypair persistence for HotStuff consensus
//! 
//! This module handles loading and saving Ed25519 keypairs used for validator
//! consensus operations. Keys are persisted to disk in JSON format to ensure
//! consistent validator identity across restarts.

use std::{fs, path::Path};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use hotstuff_rs::types::crypto_primitives::SigningKey;
use rand_core::OsRng;
use base64::Engine;

/// JSON structure for persisting validator keypairs
#[derive(Serialize, Deserialize)]
struct ValidatorKeysJson {
    /// Format version for future compatibility
    version: u32,
    /// Cryptographic algorithm identifier
    algorithm: String,
    /// Base64-encoded 32-byte Ed25519 private key
    private_key: String,
    /// Base64-encoded 32-byte Ed25519 public key
    public_key: String,
}

/// Generate a new Ed25519 keypair for validator consensus
pub fn generate_validator_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Save a validator keypair to a JSON file with restrictive permissions
pub fn save_validator_keys<P: AsRef<Path>>(path: P, signing_key: &SigningKey) -> Result<()> {
    let private_key_bytes = signing_key.to_bytes();
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    
    let keys_json = ValidatorKeysJson {
        version: 1,
        algorithm: "ed25519".to_string(),
        private_key: base64::engine::general_purpose::STANDARD.encode(&private_key_bytes),
        public_key: base64::engine::general_purpose::STANDARD.encode(&public_key_bytes),
    };
    
    let json_content = serde_json::to_string_pretty(&keys_json)
        .context("Failed to serialize keypair to JSON")?;
    
    // Write to file with restrictive permissions (owner read/write only)
    fs::write(&path, json_content)
        .context("Failed to write keypair to file")?;
    
    // Set file permissions to 0600 (owner read/write only) on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .context("Failed to get file metadata")?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)
            .context("Failed to set restrictive file permissions")?;
    }
    
    Ok(())
}

/// Load a validator keypair from a JSON file
pub fn load_validator_keys<P: AsRef<Path>>(path: P) -> Result<SigningKey> {
    let json_content = fs::read_to_string(&path)
        .context("Failed to read keypair file")?;
    
    let keys_json: ValidatorKeysJson = serde_json::from_str(&json_content)
        .context("Failed to parse keypair JSON")?;
    
    // Validate format version
    if keys_json.version != 1 {
        anyhow::bail!("Unsupported keypair file version: {}", keys_json.version);
    }
    
    // Validate algorithm
    if keys_json.algorithm != "ed25519" {
        anyhow::bail!("Unsupported algorithm: {}", keys_json.algorithm);
    }
    
    // Decode private key
    let private_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keys_json.private_key)
        .context("Failed to decode private key from base64")?;
    
    if private_key_bytes.len() != 32 {
        anyhow::bail!("Invalid private key length: expected 32 bytes, got {}", private_key_bytes.len());
    }
    
    let private_key_array: [u8; 32] = private_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert private key to fixed array"))?;
    
    // Create SigningKey from bytes
    let signing_key = SigningKey::from_bytes(&private_key_array);
    
    // Verify that the public key matches
    let expected_public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keys_json.public_key)
        .context("Failed to decode public key from base64")?;
    
    let actual_public_key_bytes = signing_key.verifying_key().to_bytes();
    
    if expected_public_key_bytes != actual_public_key_bytes {
        anyhow::bail!("Public key mismatch: keypair file may be corrupted");
    }
    
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hotstuff_rs::types::crypto_primitives::{Signer, Verifier};
    
    #[test]
    fn test_generate_keypair() {
        let keypair = generate_validator_keypair();
        
        // Verify the keypair works
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.verifying_key().verify(message, &signature).is_ok());
    }
    
    #[test]
    fn test_save_and_load_keypair() -> Result<()> {
        // Create a temporary file path
        let temp_path = std::env::temp_dir().join("test_validator.keys");
        
        let keypair = generate_validator_keypair();
        let original_public_key = keypair.verifying_key().to_bytes();
        
        // Save keypair
        save_validator_keys(&temp_path, &keypair)?;
        
        // Load keypair
        let loaded_keypair = load_validator_keys(&temp_path)?;
        let loaded_public_key = loaded_keypair.verifying_key().to_bytes();
        
        // Verify they match
        assert_eq!(original_public_key, loaded_public_key);
        
        // Verify the loaded keypair works
        let message = b"test message";
        let signature = loaded_keypair.sign(message);
        assert!(loaded_keypair.verifying_key().verify(message, &signature).is_ok());
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
        
        Ok(())
    }
    
    #[test]
    fn test_load_nonexistent_file() {
        let result = load_validator_keys("nonexistent_file.keys");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_load_invalid_json() -> Result<()> {
        let temp_path = std::env::temp_dir().join("test_invalid.keys");
        fs::write(&temp_path, "invalid json")?;
        
        let result = load_validator_keys(&temp_path);
        assert!(result.is_err());
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
        
        Ok(())
    }
    
    #[test]
    fn test_load_invalid_version() -> Result<()> {
        let temp_path = std::env::temp_dir().join("test_invalid_version.keys");
        let invalid_json = r#"{
            "version": 999,
            "algorithm": "ed25519",
            "private_key": "dGVzdA==",
            "public_key": "dGVzdA=="
        }"#;
        fs::write(&temp_path, invalid_json)?;
        
        let result = load_validator_keys(&temp_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported keypair file version"));
        
        // Clean up
        let _ = fs::remove_file(&temp_path);
        
        Ok(())
    }
}
