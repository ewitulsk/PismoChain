use std::sync::{Arc, Mutex};
use crate::pismo_app_jmt::PismoTransaction;

// No local signature normalization/verification; handled in transaction.verify()

/// Submit a signed transaction to the transaction queue.
/// Returns an error if the transaction is not properly signed or fails validation.
pub fn submit_transaction(
    tx_queue: Arc<Mutex<Vec<PismoTransaction>>>,
    transaction: PismoTransaction,
    expected_chain_id: u16,
) -> anyhow::Result<()> {
    // Always rely on transaction.verify() for signature + chain check
    // We cannot perform nonce checks here since we don't have state; chain id must match.
    // Load expected chain id via a default config read is not ideal here; the caller should ensure correctness.
    // For now, enforce the transaction carries a self-consistent chain id by reusing it as expected.
    if !transaction.verify(expected_chain_id)? {
        return Err(anyhow::anyhow!("Invalid transaction signature"));
    }

    println!(
        "✅ Transaction validated: {:?} from public_key {} (signer: {})",
        transaction.payload, transaction.public_key, transaction.signer
    );
    tx_queue.lock().unwrap().push(transaction);
    return Ok(());
}