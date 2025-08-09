use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify a Phantom `signMessage` signature
/// - `address`: base58 Solana public key (32 bytes)
/// - `message`: EXACT string the frontend asked Phantom to sign (identical bytes!)
/// - `signature_b64`: base64-encoded 64-byte ed25519 signature
pub fn verify_phantom_signature(address: &str, message: &str, signature_b64: &str) -> Result<bool> {
    // 1) Decode the public key (base58 -> 32 bytes)
    let pk_bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| anyhow!("invalid base58 pubkey: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes, got {}", pk_bytes.len()));
    }
    let verifying_key = VerifyingKey::from_bytes(
        &pk_bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow!("pubkey length mismatch"))?,
    )?;

    // 2) Decode the signature (base64 -> 64 bytes)
    let sig_bytes = base64::decode(signature_b64)
        .map_err(|e| anyhow!("invalid base64 signature: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(anyhow!("signature must be 64 bytes, got {}", sig_bytes.len()));
    }
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature length mismatch"))?;
    let signature = Signature::from_bytes(&sig_arr);

    // 3) Verify (ed25519 over the exact message bytes)
    let msg_bytes = message.as_bytes();
    Ok(verifying_key.verify(msg_bytes, &signature).is_ok())
}


