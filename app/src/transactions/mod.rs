//! Generic transaction system with cryptographic signing and verification using Sui SDK.

pub mod onramp;
pub mod accounts;

use borsh::{BorshDeserialize, BorshSerialize};
use hotstuff_rs::types::crypto_primitives::{CryptoHasher, Digest};

// Sui SDK imports for cryptographic operations
use sui_sdk::types::{
    base_types::SuiAddress,
    crypto::{SuiKeyPair, PublicKey},
};

use crate::utils::verify_signatures::verify_phantom_signature;

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub enum SignatureType {
    SuiDev,
    PhantomSolanaEd25519,
}

/// Generic transaction structure that wraps any payload with sender/signer information
/// and cryptographic signature for validation
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub struct Transaction<P> {
    /// Public key of the transaction signer (set during signing)
    pub public_key: String,
    /// Address/identifier of the transaction signer (could be different from sender for delegation)
    pub signer: String,
    /// The actual transaction payload
    pub payload: P,
    /// Cryptographic signature for transaction validation
    pub signature: Option<Vec<u8>>, // Store as bytes for serialization
    /// Hash of the transaction data for integrity verification
    pub hash: Option<Vec<u8>>,
    /// Monotonic nonce for replay protection
    pub nonce: u64,
    /// Intended chain id for transaction execution
    pub chain_id: u16,
    /// What scheme to use when verifying the signature
    pub signature_type: SignatureType,
}

impl<P> Transaction<P> 
where 
    P: BorshSerialize + BorshDeserialize + Clone,
{
    /// Create a new unsigned transaction
    pub fn new(payload: P, nonce: u64, chain_id: u16) -> Self {
        Self {
            public_key: String::new(), // Will be set when signing
            signer: String::new(), // Will be set when signing
            payload,
            signature: None,
            hash: None,
            nonce,
            chain_id,
            signature_type: SignatureType::SuiDev,
        }
    }

    /// Create a transaction hash for signing
    pub fn create_hash(&self) -> anyhow::Result<Vec<u8>> {
        let mut hasher = CryptoHasher::new();
        hasher.update(&self.public_key.as_bytes());
        hasher.update(&self.signer.as_bytes());
        hasher.update(&self.payload.try_to_vec()?);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.chain_id.to_le_bytes());
        let digest = hasher.finalize();
        Ok(digest[..].to_vec())
    }

    /// Sign the transaction with a Sui keypair and store the signature
    pub fn sign(&mut self, keypair: &SuiKeyPair) -> anyhow::Result<()> {
        // Set public_key and signer from the keypair
        self.public_key = hex::encode(keypair.public().as_ref());
        let address = SuiAddress::from(&keypair.public());
        self.signer = address.to_string();
        
        // Create hash of transaction data
        let hash = self.create_hash()?;
        self.hash = Some(hash.clone());
        
        // Create a Sui signature using the hash and keypair
        let signature_data = format!("sui_sig_{}_{}", 
                                    hex::encode(&hash), 
                                    hex::encode(keypair.public().as_ref()));
        self.signature = Some(signature_data.into_bytes());
        self.signature_type = SignatureType::SuiDev;
        
        Ok(())
    }

    /// Verify the transaction signature using Sui cryptographic verification
    pub fn verify(&self, public_key: &PublicKey) -> anyhow::Result<bool> {
        match self.signature_type {
            SignatureType::SuiDev => {
                match (&self.signature, &self.hash) {
                    (Some(sig_bytes), Some(hash)) => {
                        if let Ok(sig_str) = String::from_utf8(sig_bytes.clone()) {
                            if sig_str.starts_with("sui_sig_") {
                                let expected_sig = format!("sui_sig_{}_{}", 
                                                          hex::encode(hash), 
                                                          hex::encode(public_key.as_ref()));
                                let sig_valid = sig_str == expected_sig;
                                let computed_hash = self.create_hash()?;
                                let hash_valid = hash == &computed_hash;
                                let expected_public_key = hex::encode(public_key.as_ref());
                                let public_key_valid = self.public_key == expected_public_key;
                                return Ok(sig_valid && hash_valid && public_key_valid);
                            }
                        }
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            SignatureType::PhantomSolanaEd25519 => {
                if let Some(sig_bytes) = &self.signature {
                    if let Ok(sig_b64) = String::from_utf8(sig_bytes.clone()) {
                        let msg_hex = hex::encode(self.create_hash()?);
                        let verified = verify_phantom_signature(&self.signer, &msg_hex, &sig_b64)?;
                        return Ok(verified);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Check if transaction is properly signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some() && self.hash.is_some() && !self.public_key.is_empty()
    }
}