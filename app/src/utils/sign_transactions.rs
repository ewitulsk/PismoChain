
use std::sync::{Arc, Mutex};
use sui_sdk::types::crypto::SuiKeyPair;
use crate::pismo_app_jmt::{PismoOperation, PismoTransaction};
use crate::transactions::Transaction;
use crate::utils::submit_transactions::submit_transaction;

/// Create and sign a new counter transaction with Sui keypair
pub fn create_signed_transaction(
    keypair: &SuiKeyPair,
    operation: PismoOperation
) -> anyhow::Result<PismoTransaction> {
    let mut transaction = Transaction::new(operation);
    transaction.sign(keypair)?;
    Ok(transaction)
}

/// Helper function to submit a Sui-signed transaction with error handling
pub fn submit_sui_signed_transaction(
    tx_queue: Arc<Mutex<Vec<PismoTransaction>>>,
    keypair: &SuiKeyPair,
    operation: PismoOperation,
) -> anyhow::Result<()> {
    let transaction = create_signed_transaction(
        keypair,
        operation,
    )?;
    
    let public_key = keypair.public();
    submit_transaction(tx_queue, transaction, &public_key)?;
    Ok(())
}