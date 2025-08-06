use std::sync::{Arc, Mutex};
use sui_sdk::types::crypto::PublicKey;
use crate::pismo_app_jmt::PismoTransaction;

/// Submit a signed transaction to the transaction queue.
/// Returns an error if the transaction is not properly signed or fails validation.
pub fn submit_transaction(
    tx_queue: Arc<Mutex<Vec<PismoTransaction>>>,
    transaction: PismoTransaction, 
    public_key: &PublicKey
) -> anyhow::Result<()> {
    // Validate transaction signature with public key
    if !transaction.verify(public_key)? {
        return Err(anyhow::anyhow!("Invalid transaction signature"));
    }

    if !transaction.is_signed() {
        return Err(anyhow::anyhow!("Transaction must be signed"));
    }

    println!("✅ Transaction validated: {:?} from public_key {} (signer: {})", 
             transaction.payload, transaction.public_key, transaction.signer);

    tx_queue.lock().unwrap().push(transaction);
    Ok(())
}