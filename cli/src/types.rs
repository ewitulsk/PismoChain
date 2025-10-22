use serde::{Deserialize, Serialize};

/// JSON structure for reading validator keypairs metadata
#[derive(Deserialize)]
pub struct ValidatorKeysJson {
    pub version: u32,
    pub algorithm: String,
    #[allow(dead_code)]
    pub private_key: String,
    #[allow(dead_code)]
    pub public_key: String,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub version: u32,
    pub algorithm: String,
    pub verifying_key: String,
    pub peer_id: String,
}

