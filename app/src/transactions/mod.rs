//! Generic transaction system with cryptographic signing and verification using Sui SDK.

pub mod onramp;
pub mod offramp;
pub mod accounts;
pub mod noop;
pub mod coin;
pub mod orderbook;
pub mod book_executor;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::utils::verify_signatures::{
    build_signing_envelope,
    verify_phantom_signature_bytes,
    verify_ed25519_signature_with_public_key_hex,
    compute_envelope_hash_bytes,
};
use crate::standards::accounts::{
    Account,
    AccountAddr,
    derive_account_addr,
    get_account,
    get_account_from_signer,
};
use hotstuff_rs::block_tree::accessors::app::AppBlockTreeView;
use hotstuff_rs::block_tree::pluggables::KVStore;
use crate::pismo_app_jmt::PismoOperation;

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureType {
    SuiDev,
    PhantomSolanaEd25519,
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, serde::Serialize)]
pub enum SignerType {
    NewAccount,
    Linked,
    Temp,
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
    pub payload: P, //Vec<P>
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
    /// Type of signer (new account, linked account, or temporary)
    pub signer_type: SignerType,
}

impl<P> Transaction<P> 
where 
    P: BorshSerialize + BorshDeserialize + Clone,
{
    /// Create a transaction hash for signing
    pub fn create_hash(&self) -> anyhow::Result<Vec<u8>> {
        // For envelope hashing used across frontends, use the same preimage as the frontend
        let payload_bytes = self.payload.try_to_vec()?;
        let digest = compute_envelope_hash_bytes(
            &self.public_key,
            &self.signer,
            &payload_bytes,
            self.nonce,
            self.chain_id,
        );
        Ok(digest)
    }

    /// Verify the transaction with expected chain id and optional state (for nonce checks)
    ///
    /// - Always verifies signature and stored hash
    /// - Enforces `self.chain_id == expected_chain_id`
    /// - If state is provided, performs nonce checks per payload type
    pub fn verify(&self, expected_chain_id: u16) -> anyhow::Result<bool> {
        // Enforce chain id matches expectation
        if self.chain_id != expected_chain_id {
            return Ok(false);
        }

        match self.signature_type {
            SignatureType::SuiDev => {
                match &self.signature {
                    Some(sig_bytes) => {
                        // Rebuild the envelope exactly as frontend and verify using Sui PersonalMessage intent digest
                        let payload_bytes = self.payload.try_to_vec()?;
                        let envelope = build_signing_envelope(
                            &self.public_key,
                            &self.signer,
                            &payload_bytes,
                            self.nonce,
                            self.chain_id,
                        );

                        // Primary: Sui intent-digest verification
                        let sig_valid_intent = verify_ed25519_signature_with_public_key_hex(
                            &self.public_key,
                            &envelope,
                            sig_bytes,
                        )?;

                        // Also validate stored hash matches recomputed hash for integrity
                        let hash_valid = match &self.hash {
                            Some(stored) => stored == &self.create_hash()?,
                            None => false,
                        };

                        Ok(sig_valid_intent && hash_valid)
                    }
                    None => Ok(false),
                }
            }
            SignatureType::PhantomSolanaEd25519 => {
                if let Some(sig_bytes) = &self.signature {
                    // Rebuild the exact envelope string before verification
                    let payload_bytes = self.payload.try_to_vec()?;
                    let envelope = build_signing_envelope(
                        &self.public_key,
                        &self.signer,
                        &payload_bytes,
                        self.nonce,
                        self.chain_id,
                    );

                    // Prefer raw 64-byte signature if provided
                    if sig_bytes.len() == 64 {
                        let verified = verify_phantom_signature_bytes(&self.signer, &envelope, sig_bytes)?;
                        return Ok(verified);
                    }
                }
                Ok(false)
            }
        }
    }

    /// Verify with state: provided for specific payloads via specialization below
    /// (no default implementation for generic P)

    /// Check if transaction is properly signed
    pub fn is_signed(&self) -> bool {
        match self.signature_type {
            SignatureType::SuiDev => {
                self.signature.is_some()
                    && self.hash.is_some()
                    && self.signer.starts_with("sui:")
            }
            SignatureType::PhantomSolanaEd25519 => {
                self.signature.is_some()
                    && self.hash.is_some()
                    && self.signer.starts_with("sol:")
            }
        }
    }
}

impl Transaction<PismoOperation> {
    /// Verify with state: performs all checks in `verify` plus nonce checks.
    // This needs to be generalized. It can be basically the same thing every time.
    pub fn verify_with_state<K: KVStore>(
        &self,
        expected_chain_id: u16,
        block_tree: &AppBlockTreeView<'_, K>,
        _version: u64,
    ) -> anyhow::Result<bool> {
        // First, signature/hash + chain id check
        if !self.verify(expected_chain_id)? {
            return Ok(false);
        }

        println!("Passed initial verify_with_state verification");

        // Nonce checks per payload type
        let nonce_ok = match &self.payload {
            // For create, account must not yet exist and nonce must be 0
            PismoOperation::CreateAccount => {
                let derived_addr: AccountAddr = derive_account_addr(1, self.signature_type, &self.public_key);
                let existing: Option<Account> = get_account(block_tree, &derived_addr);
                existing.is_none() && self.nonce == 0
            }
            // For link, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::LinkAccount { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce //This seems like a sus way of incrementing the nonce...
                } else {
                    false
                }
            }
            // For onramp, check nonce matches current account nonce
            PismoOperation::Onramp(_, _) => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For NoOp, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::NoOp => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For NewCoin, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::NewCoin { .. } => {
                println!("Verifying new coin...");
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    println!("self.nonce: {:?}, account.current_nonce: {:?}, self.nonce == account.current_nonce: {:?}", self.nonce, account.current_nonce, self.nonce == account.current_nonce);
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For Mint, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::Mint { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For Transfer, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::Transfer { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For Offramp, check nonce matches current account nonce
            PismoOperation::Offramp { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For CreateOrderbook, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::CreateOrderbook { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
            // For NewLimitOrder, the account must exist and tx.nonce must equal current_nonce
            PismoOperation::NewLimitOrder { .. } => {
                if let Some(account) = get_account_from_signer(block_tree, &self.signer, self.signer_type, self.signature_type, &self.public_key) {
                    self.nonce == account.current_nonce
                } else {
                    false
                }
            }
        };

        Ok(nonce_ok)
    }
}