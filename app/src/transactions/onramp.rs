use wormhole_vaas::{utils, Readable, Vaa, VaaBody, Writeable};
use base64::Engine;
use hex::FromHex;
use anyhow::{Result, anyhow};
// Serde imports are kept for potential future use with config serialization

/// Guardian set information with quorum calculation
#[derive(Debug, Clone)]
pub struct GuardianSetInfo {
    addresses: Vec<[u8; 20]>,
}

/// Parsed onramp message from VAA payload
#[derive(Debug, Clone)]
pub struct OnrampMessage {
    pub emitter_chain: u16,
    pub amount: u64,
    pub sender: String,      // hex string
    pub recipient: String,   // hex string
    pub token_address: String,
    pub timestamp: u64,
}

impl GuardianSetInfo {
    fn quorum(&self) -> usize {
        utils::quorum(self.addresses.len())
    }
}

/// Deserialize VAA payload into an OnrampMessage
/// Format: ONRAMP000amount_u64000sender000recipient000token_address000timestamp_u64
/// Where 000 represents 3 zero bytes (\x00\x00\x00)
fn deserialize_vaa_message(vaa_body: &VaaBody) -> Result<OnrampMessage> {
    let payload = vaa_body.payload.to_vec();
    let separator = [0u8, 0u8, 0u8]; // 3 zero bytes
    
    // Split the payload on the separator
    let mut parts = Vec::new();
    let mut start = 0;
    
    while start < payload.len() {
        // Find the next occurrence of the separator
        let mut found = false;
        for i in start..(payload.len() - 2) {
            if payload[i..i+3] == separator {
                parts.push(&payload[start..i]);
                start = i + 3;
                found = true;
                break;
            }
        }
        
        // If no separator found, this is the last part
        if !found {
            parts.push(&payload[start..]);
            break;
        }
    }
    
    if parts.len() != 6 {
        return Err(anyhow!("Invalid message format: expected 6 parts, got {}", parts.len()));
    }
    
    let prefix = String::from_utf8_lossy(parts[0]);
    if prefix != "ONRAMP" {
        return Err(anyhow!("Invalid message prefix: expected 'ONRAMP', got '{}'", prefix));
    }
    
    let amount_str = String::from_utf8_lossy(parts[1]);
    let amount = amount_str.parse::<u64>()
        .map_err(|e| anyhow!("Failed to parse amount '{}': {}", amount_str, e))?;
    
    let sender = hex::encode(parts[2]);
    
    let recipient = hex::encode(parts[3]);
    
    let token_address = String::from_utf8(parts[4].to_vec())
        .map_err(|e| anyhow!("Failed to parse token_address as UTF-8: {}", e))?;
    
    let timestamp_str = String::from_utf8_lossy(parts[5]);
    let timestamp = timestamp_str.parse::<u64>()
        .map_err(|e| anyhow!("Failed to parse timestamp '{}': {}", timestamp_str, e))?;
    
    let emitter_chain = vaa_body.emitter_chain;

    Ok(OnrampMessage {
        emitter_chain,
        amount,
        sender,
        recipient,
        token_address,
        timestamp,
    })
}

/// Get hardcoded guardian set for development/fallback
fn get_hardcoded_guardian_set(guardian_set_index: u64, network: &str) -> Result<GuardianSetInfo> {
    match (guardian_set_index, network) {
        (0, "mainnet") => {
            // Mainnet Guardian Set 0 - 19 guardians
            let addresses_hex = vec![
                "0x5893B5A76c3f739645648885bDCcC06cd70a3Cd3",
                "0xfF6CB952589BDE862c25Ef4392132fb9D4A42157",
                "0x114De8460193bdf3A2fCf81f86a09765F4762fD1",
                "0x107A0086b32d7A0977926A205131d8731D39cbEB",
                "0x8C82B2fd82FaeD2711d59AF0F2499D16e726f6b2",
                "0x11b39756C042441BE6D8650b69b54EbE715E2343",
                "0x54Ce5B4D348fb74B958e8966e2ec3dBd4958a7cd",
                "0x15e7cAF07C4e3DC8e7C469f92C8Cd88FB8005a20",
                "0x74a3bf913953D695260D88BC1aA25A4eeE363ef0",
                "0x000aC0076727b35FBea2dAc28fEE5cCB0fEA768e",
                "0xAF45Ced136b9D9e24903464AE889F5C8a723FC14",
                "0xf93124b7c738843CBB89E864c862c38cddCccF95",
                "0xD2CC37A4dc036a8D232b48f62cDD4731412f4890",
                "0xDA798F6896A3331F64b48c12D1D57Fd9cbe70811",
                "0x71AA1BE1D36CaFE3867910F99C09e347899C19C3",
                "0x8192b6E7387CCd768277c17DAb1b7a5027c0b3Cf",
                "0x178e21ad2E77AE06711549CFBB1f9c7a9d8096e8",
                "0x5E1487F35515d02A92753504a8D75471b9f49EdB",
                "0x6FbEBc898F403E4773E95feB15E80C9A99c8348d"
            ];
            
            let addresses: Result<Vec<[u8; 20]>, _> = addresses_hex
                .iter()
                .map(|addr| {
                    let clean_addr = addr.trim_start_matches("0x");
                    <[u8; 20]>::from_hex(clean_addr)
                        .map_err(|e| anyhow!("Failed to parse hardcoded guardian address '{}': {}", addr, e))
                })
                .collect();
            
            Ok(GuardianSetInfo { 
                addresses: addresses? 
            })
        },
        (0, "testnet") => {
            // Testnet Guardian Set 0 - Single guardian for testing
            let addresses_hex = vec![
                "0x13947Bd48b18E53fdAeEe77F3473391aC727C638",
            ];
            
            let addresses: Result<Vec<[u8; 20]>, _> = addresses_hex
                .iter()
                .map(|addr| {
                    let clean_addr = addr.trim_start_matches("0x");
                    <[u8; 20]>::from_hex(clean_addr)
                        .map_err(|e| anyhow!("Failed to parse hardcoded guardian address '{}': {}", addr, e))
                })
                .collect();
            
            Ok(GuardianSetInfo { 
                addresses: addresses? 
            })
        },
        _ => Err(anyhow!("No hardcoded guardian set available for index {} on network {}", guardian_set_index, network))
    }
}

/// Verify if a signature is valid for the given digest and guardian set
fn sig_is_valid(sig: &wormhole_vaas::GuardianSetSig, digest: &[u8; 32], guardians: &GuardianSetInfo) -> bool {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let recovery_id_byte = sig.recovery_id();
    let signature_bytes = sig.raw_sig();

    let recovery_id = match RecoveryId::try_from(recovery_id_byte) {
        Ok(id) => id,
        Err(_) => return false,
    };
    
    let signature = match Signature::from_bytes(&signature_bytes.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    let recovered_key = match VerifyingKey::recover_from_prehash(digest, &signature, recovery_id) {
        Ok(key) => key,
        Err(_) => return false,
    };
    
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_hash = utils::keccak256(&pubkey_bytes.as_bytes()[1..]);
    
    if let Ok(eth_address) = pubkey_hash[12..].try_into() {
        let eth_address: [u8; 20] = eth_address;
        return guardians.addresses.contains(&eth_address);
    }
    
    false
}

/// Main VAA verification function
pub fn verify_vaa_and_extract_message(vaa_raw: &str, guardian_set_index: u64) -> Result<OnrampMessage> {
    // Use testnet for now - this could be configurable
    let network = "testnet";
    
    let bytes = base64::prelude::BASE64_STANDARD.decode(vaa_raw)
        .map_err(|e| anyhow!("Failed to decode base64 VAA: {}", e))?;
    
    let vaa = Vaa::read(&mut &bytes[..])
        .map_err(|e| anyhow!("Failed to parse VAA: {}", e))?;
    
    let body_hash_1 = utils::keccak256(&vaa.body.to_vec());
    let body_hash = utils::keccak256(body_hash_1);
    let guardians = get_hardcoded_guardian_set(guardian_set_index, network)?;
    let needed = guardians.quorum();

    if vaa.header.guardian_set_index as u64 != guardian_set_index {
        return Err(anyhow!(
            "Guardian set index mismatch: VAA has {}, expected {}",
            vaa.header.guardian_set_index,
            guardian_set_index
        ));
    }

    let mut valid_count = 0;
    for sig in vaa.header.signatures.iter() {
        let is_valid = sig_is_valid(sig, &body_hash, &guardians);
        if is_valid {
            valid_count += 1;
        }
    }

    if valid_count >= needed {
        println!("✅ VAA verification successful! Valid signatures: {}/{}", valid_count, needed);
        let onramp_message = deserialize_vaa_message(&vaa.body)?;
        Ok(onramp_message)
    } else {
        Err(anyhow!(
            "VAA verification FAILED: Only {} valid signatures, {} required for quorum",
            valid_count,
            needed
        ))
    }
}
