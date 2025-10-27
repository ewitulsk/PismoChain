use jmt::{KeyHash, OwnedValue};

use crate::jmt_state::StateReader;
use crate::standards::accounts::get_account_from_signer_state;
use crate::transactions::{SignerType, SignatureType};

/// Build writes and app-mirror inserts for a NoOp transaction
/// This function performs no state changes (nonce increment handled separately)
/// Returns (success, (jmt_writes, mirror_inserts, events))
pub fn build_noop_updates(
    signing_public_key: String,
    signer_address: &str,
    signer_type: SignerType,
    signature_type: SignatureType,
    state: &impl StateReader
) -> (bool, (Vec<(KeyHash, Option<OwnedValue>)>, Vec<(Vec<u8>, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    let jmt_writes: Vec<(KeyHash, Option<OwnedValue>)> = Vec::new();
    let mirror: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let events: Vec<(String, Vec<u8>)> = Vec::new();

    // Verify account exists
    if get_account_from_signer_state(state, &signer_address.to_string(), signer_type, signature_type, &signing_public_key).is_some() {
        (true, (jmt_writes, mirror, events))
    } else {
        (false, (jmt_writes, mirror, events))
    }
}
