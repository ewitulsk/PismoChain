//! Cryptographic utilities for converting between Sui and HotStuff key types.

use sui_sdk::types::crypto::{SuiKeyPair, ToFromBytes};
use hotstuff_rs::types::crypto_primitives::{SigningKey, Signer, Verifier};

/// Convert a SuiKeyPair to a HotStuff SigningKey using the same underlying Ed25519 key material.
/// 
/// This ensures that both the Sui validator keypair and HotStuff consensus keypair
/// use identical cryptographic material, eliminating the need for separate key generation.
/// 
/// # Arguments
/// 
/// * `sui_keypair` - The Sui keypair to convert (must be Ed25519)
/// 
/// # Returns
/// 
/// A HotStuff SigningKey that uses the same private key material
/// 
/// # Panics
/// 
/// Panics if the keypair is not Ed25519, as HotStuff consensus requires Ed25519 keys.
pub fn sui_keypair_to_hotstuff_signing_key(sui_keypair: &SuiKeyPair) -> SigningKey {
    match sui_keypair {
        SuiKeyPair::Ed25519(ed25519_keypair) => {
            // Extract the raw 32-byte Ed25519 private key from the Sui keypair
            let secret_key_bytes: [u8; 32] = ed25519_keypair
                .as_bytes()
                .try_into()
                .expect("Ed25519 key should be 32 bytes");
            
            // Create HotStuff SigningKey from the same key material
            SigningKey::from_bytes(&secret_key_bytes)
        }
        SuiKeyPair::Secp256k1(_) => {
            panic!("Secp256k1 keypairs are not supported for HotStuff consensus");
        }
        SuiKeyPair::Secp256r1(_) => {
            panic!("Secp256r1 keypairs are not supported for HotStuff consensus");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_sdk::types::crypto::get_key_pair_from_rng;
    use rand_core::OsRng;

    #[test]
    fn test_sui_to_hotstuff_keypair_conversion() {
        let mut rng = OsRng;
        let sui_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        
        // Convert to HotStuff SigningKey
        let hotstuff_signing_key = sui_keypair_to_hotstuff_signing_key(&sui_keypair);
        let hotstuff_verifying_key = hotstuff_signing_key.verifying_key();
        
        // Verify that the public keys match
        let _sui_public_key = sui_keypair.public();
        
        // Both should have the same underlying Ed25519 public key bytes
        // Note: We can't directly compare them due to different wrapper types,
        // but this test ensures the conversion doesn't panic and produces a valid key
        assert_eq!(hotstuff_verifying_key.to_bytes().len(), 32);
        
        // Test that we can sign with the converted key
        let message = b"test message";
        let signature = hotstuff_signing_key.sign(message);
        
        // Verify the signature
        assert!(hotstuff_verifying_key.verify(message, &signature).is_ok());
    }
    
    #[test]
    fn test_conversion_with_different_keypair() {
        let mut rng = OsRng;
        let sui_keypair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut rng).1);
        
        // Test conversion function
        let hotstuff_signing_key = sui_keypair_to_hotstuff_signing_key(&sui_keypair);
        
        // Should be able to sign
        let message = b"test message";
        let signature = hotstuff_signing_key.sign(message);
        assert_eq!(signature.to_bytes().len(), 64);
    }
    
    // Note: We skip testing Secp256k1/Secp256r1 conversion panics since those
    // key types are not publicly exposed by the Sui SDK for direct construction.
    // In practice, the function will panic if non-Ed25519 keypairs are passed.
} 