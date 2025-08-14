use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest as ShaDigestTrait, Sha256};
use blake2::digest::{consts::U32, Digest as BlakeDigest};
use blake2::Blake2b;
use bcs;

const ENVELOPE_APP: &str = "example.com";
const ENVELOPE_PURPOSE: &str = "session-key binding";

fn push_borsh_string(buf: &mut Vec<u8>, s: &str) {
    let len = s.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// Build the exact Phantom envelope string used for signing
pub fn build_signing_envelope(
    public_key_hex: &str,
    signer: &str,
    payload_bytes: &[u8],
    nonce: u64,
    chain_id: u16,
) -> String {
    // 1) DATA(b58) = base58(sha256(preimage)) per TypeScript buildCreateAccountPrehash
    let digest = compute_envelope_hash_bytes(public_key_hex, signer, payload_bytes, nonce, chain_id);
    let data_b58 = bs58::encode(digest).into_string();

    // 3) Envelope text
    format!(
        "APP: {}\nPURPOSE: {}\nDATA(b58): {}\nNONCE: {}",
        ENVELOPE_APP,
        ENVELOPE_PURPOSE,
        data_b58,
        nonce,
    )
}

/// Compute the sha256(preimage) used in the envelope's DATA(b58) field, returned as raw bytes.
/// The preimage matches the frontend exactly:
/// borsh(public_key_hex) | borsh(signer) | payload_bytes | nonce(le) | chain_id(le)
pub fn compute_envelope_hash_bytes(
    public_key_hex: &str,
    signer: &str,
    payload_bytes: &[u8],
    nonce: u64,
    chain_id: u16,
) -> Vec<u8> {
    let mut preimage: Vec<u8> = Vec::new();
    // Borsh-encoded strings
    push_borsh_string(&mut preimage, public_key_hex);
    push_borsh_string(&mut preimage, signer);
    // Raw payload bytes (already Borsh-encoded)
    preimage.extend_from_slice(payload_bytes);
    // Little-endian numbers
    preimage.extend_from_slice(&nonce.to_le_bytes());
    preimage.extend_from_slice(&chain_id.to_le_bytes());

    let digest = Sha256::digest(&preimage);
    digest[..].to_vec()
}

/// Extract an Ed25519 verifying key from a hex-encoded 32-byte public key
pub fn extract_ed25519_verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey> {
    let mut pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| anyhow!("invalid hex public key: {e}"))?;

    // Accept Sui-encoded public keys that include a 1-byte scheme prefix (0x00 for Ed25519)
    if pk_bytes.len() == 33 && pk_bytes[0] == 0x00 {
        pk_bytes = pk_bytes[1..].to_vec();
    }

    if pk_bytes.len() != 32 {
        return Err(anyhow!("pubkey must be 32 bytes, got {}", pk_bytes.len()));
    }

    let verifying_key = VerifyingKey::from_bytes(
        &pk_bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow!("pubkey length mismatch"))?,
    )?;
    Ok(verifying_key)
}

/// Verify a Sui PersonalMessage signature with Ed25519 using a hex-encoded public key.
///
/// The message is the textual envelope that the frontend constructed.
/// Sui signs blake2b256([3,0,0] || BCS(envelope_bytes)).
pub fn verify_ed25519_signature_with_public_key_hex(
    public_key_hex: &str,
    message: &str,
    signature_bytes: &[u8],
) -> Result<bool> {
    let verifying_key = extract_ed25519_verifying_key_from_hex(public_key_hex)?;

    // Accept raw 64-byte signatures, Sui scheme-prefixed 65-byte signatures,
    // or Sui serialized signatures (1 + 64 + 32 = 97 bytes)
    let sig_slice: &[u8] = match signature_bytes.len() {
        64 => signature_bytes,
        65 => {
            if signature_bytes[0] != 0x00 {
                return Err(anyhow!("unsupported signature scheme prefix: 0x{:02x}", signature_bytes[0]));
            }
            &signature_bytes[1..65]
        }
        97 => {
            if signature_bytes[0] != 0x00 {
                return Err(anyhow!("unsupported signature scheme prefix: 0x{:02x}", signature_bytes[0]));
            }
            &signature_bytes[1..65]
        }
        other => return Err(anyhow!("unsupported signature length: {}", other)),
    };

    // Compute Sui PersonalMessage signing digest = blake2b256([3,0,0] || BCS(envelope_bytes))
    let mut hasher: Blake2b<U32> = Blake2b::<U32>::new();
    hasher.update([3u8, 0u8, 0u8]);
    let bcs_envelope = bcs::to_bytes(message.as_bytes())
        .map_err(|e| anyhow!("failed to BCS-encode envelope: {e}"))?;
    hasher.update(&bcs_envelope);
    let digest = hasher.finalize();
    let digest_bytes: &[u8] = digest.as_slice();

    let sig_arr: [u8; 64] = sig_slice
        .try_into()
        .map_err(|_| anyhow!("signature length mismatch"))?;
    let signature = Signature::from_bytes(&sig_arr);

    Ok(verifying_key.verify(digest_bytes, &signature).is_ok())
}

/// Verify a Phantom signature provided as raw 64-byte ed25519 signature
pub fn verify_phantom_signature_bytes(address: &str, message: &str, signature_bytes: &[u8]) -> Result<bool> {
    // Expect 'sol:BASE58_PUBKEY' format
    let addr_no_prefix = address.strip_prefix("sol:").ok_or_else(|| anyhow!("address must start with 'sol:' prefix"))?;

    // Decode pubkey
    let pk_bytes = bs58::decode(addr_no_prefix)
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

    // Raw signature must be 64 bytes
    if signature_bytes.len() != 64 {
        return Err(anyhow!("signature must be 64 bytes, got {}", signature_bytes.len()));
    }
    let sig_arr: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow!("signature length mismatch"))?;
    let signature = Signature::from_bytes(&sig_arr);

    // Verify
    let msg_bytes = message.as_bytes();
    Ok(verifying_key.verify(msg_bytes, &signature).is_ok())
}


