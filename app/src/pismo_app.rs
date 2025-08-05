use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use borsh::{BorshDeserialize, BorshSerialize};
use hotstuff_rs::{
    app::{
        App, ProduceBlockRequest, ProduceBlockResponse, ValidateBlockRequest, ValidateBlockResponse,
    },
    block_tree::{accessors::{app::AppBlockTreeView, public::BlockTreeSnapshot}, pluggables::KVGet},
    types::{
        crypto_primitives::{CryptoHasher, Digest},
        data_types::{CryptoHash, Data, Datum},
        update_sets::AppStateUpdates,
    },
};

use sui_sdk::types::crypto::{PublicKey, SignatureScheme};

use crate::mem_db::MemDB;
use crate::transactions::Transaction;
use crate::transactions::onramp;
use crate::config::Config;



/// Counter-specific transaction operations that can be performed
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub enum PismoOperation {
    /// Increase the counter by 1
    Increment,
    /// Decrease the counter by 1
    Decrement,
    /// Set the counter to a specific value
    Set(i64),
    /// Process an onramp transaction with VAA verification
    Onramp(String, u64), // vaa string, guardian_set index
}

/// Type alias for counter transactions
pub type PismoTransaction = Transaction<PismoOperation>;

/// Token information stored for each locked token
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct Token {
    /// The token contract address (e.g., "0x2::sui::SUI")
    pub address: String,
    /// Last unlock checkpoint (0 if never unlocked)
    pub last_unlock: u64,
    /// User's token holdings
    pub amount: u128
}

/// User information containing their locked tokens across chains
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct User {
    /// Map of token_hash -> Token info
    /// token_hash = hash(token_address + chain_id)
    pub tokens: HashMap<String, Token>,
}

// The key in the app state where the counter value is stored.
const COUNTER_KEY: [u8; 1] = [0];

pub struct PismoApp {
    tx_queue: Arc<Mutex<Vec<PismoTransaction>>>,
    config: Config,
}

impl PismoApp {
    /// Create a new counter app that will pop and execute transactions from the provided `tx_queue`.
    ///
    /// Callers should clone a reference to the `tx_queue` before calling this constructor and use the
    /// reference to insert transactions to the `tx_queue` whenever needed.
    pub fn new(tx_queue: Arc<Mutex<Vec<PismoTransaction>>>, config: Config) -> PismoApp {
        Self { tx_queue, config }
    }

    /// Return an `AppStateUpdates` that when applied on an empty app state will produce a good "initial"
    /// app state for a counter app: one containing the counter value 0.
    pub fn initial_app_state() -> AppStateUpdates {
        let mut state = AppStateUpdates::new();
        state.insert(COUNTER_KEY.to_vec(), i64::to_le_bytes(0).to_vec());
        state
    }

    /// Get the counter value stored in a counter app's app state from the given block tree.
    pub fn get_counter<S: KVGet>(block_tree: BlockTreeSnapshot<S>) -> i64 {
        let bytes = block_tree.committed_app_state(&COUNTER_KEY).unwrap();
        i64::deserialize(&mut &*bytes).unwrap()
    }
}

impl App<MemDB> for PismoApp {
    fn produce_block(&mut self, request: ProduceBlockRequest<MemDB>) -> ProduceBlockResponse {
        // Reduced sleep time for faster consensus
        thread::sleep(Duration::from_millis(10));

        let mut tx_queue = self.tx_queue.lock().unwrap();

        let block_tree = request.block_tree();
        let app_state_updates = self.execute(&tx_queue, block_tree);
        let serialized_txs = (*tx_queue).try_to_vec().unwrap();
        let data = Data::new(vec![Datum::new(serialized_txs)]);
        let data_hash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        tx_queue.clear();

        ProduceBlockResponse {
            data_hash,
            data,
            app_state_updates,
            validator_set_updates: None, // Counter app doesn't modify validator set
        }
    }

    fn validate_block(&mut self, request: ValidateBlockRequest<MemDB>) -> ValidateBlockResponse {
        // Reduced sleep time for faster consensus
        thread::sleep(Duration::from_millis(10));

        self.validate_block_for_sync(request)
    }

    fn validate_block_for_sync(
        &mut self,
        request: ValidateBlockRequest<MemDB>,
    ) -> ValidateBlockResponse {
        let data = &request.proposed_block().data;
        let data_hash: CryptoHash = {
            let mut hasher = CryptoHasher::new();
            hasher.update(&data.vec()[0].bytes());
            let bytes = hasher.finalize().into();
            CryptoHash::new(bytes)
        };

        if request.proposed_block().data_hash != data_hash {
            ValidateBlockResponse::Invalid
        } else {

            let initial_block_tree = request.block_tree();

            if let Ok(transactions) = Vec::<PismoTransaction>::deserialize(
                &mut &*request.proposed_block().data.vec()[0].bytes().as_slice(),
            ) {
                // Validate all transactions in the block
                for transaction in &transactions {
                    // Check if transaction is signed
                    if !transaction.is_signed() {
                        println!("❌ Transaction validation failed: Transaction not signed");
                        return ValidateBlockResponse::Invalid;
                    }
                    
                    // Reconstruct public key from the transaction's stored public_key hex string
                    if let Ok(public_key_bytes) = hex::decode(&transaction.public_key) {
                        if let Ok(public_key) = PublicKey::try_from_bytes(SignatureScheme::ED25519, &public_key_bytes) {
                            match transaction.verify(&public_key) {
                                Ok(true) => {
                                    // Transaction is valid, continue
                                }
                                Ok(false) => {
                                    println!("❌ Transaction validation failed: Invalid signature for public_key {}", 
                                             transaction.public_key);
                                    return ValidateBlockResponse::Invalid;
                                }
                                Err(e) => {
                                    println!("❌ Transaction validation failed: Verification error: {}", e);
                                    return ValidateBlockResponse::Invalid;
                                }
                            }
                        } else {
                            println!("❌ Transaction validation failed: Invalid public key format");
                            return ValidateBlockResponse::Invalid;
                        }
                    } else {
                        println!("❌ Transaction validation failed: Could not decode public key hex");
                        return ValidateBlockResponse::Invalid;
                    }
                }

                let app_state_updates = self.execute(&transactions, initial_block_tree);
                ValidateBlockResponse::Valid {
                    app_state_updates,
                    validator_set_updates: None, // Counter app doesn't modify validator set
                }
            } else {
                ValidateBlockResponse::Invalid
            }
        }
    }
}

impl PismoApp {
    /// Given the `current_counter`, execute the given `transactions` and return the resulting
    /// `AppStateUpdates`.
    fn execute(
        &self,
        transactions: &Vec<PismoTransaction>,
        initial_block_tree: &AppBlockTreeView<'_, MemDB>,
    ) -> Option<AppStateUpdates> {
        let initial_counter = i64::from_le_bytes(
            initial_block_tree
                .app_state(&COUNTER_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let mut counter = initial_counter;
        let _user_modifications_in_block: HashMap<String, User> = HashMap::new();

        for transaction in transactions {
            match &transaction.payload {
                PismoOperation::Increment => {
                    counter += 1;
                }
                PismoOperation::Decrement => {
                    counter -= 1;
                }
                PismoOperation::Set(value) => {
                    counter = *value;
                }
                PismoOperation::Onramp(vaa, guardian_set_index) => {
                    // Verify VAA and extract onramp message
                    match onramp::verify_vaa_and_extract_message(vaa, *guardian_set_index) {
                        Ok(onramp_message) => {
                            println!("🚀 Successfully processed Onramp transaction!");
                            println!("OnrampMessage: {:#?}", onramp_message);
                        }
                        Err(e) => {
                            println!("❌ Failed to process Onramp transaction: {}", e);
                            // For now, we continue processing other transactions
                            // In a real system, you might want to reject the entire block
                        }
                    }
                }
            }
        }

        let mut updates = AppStateUpdates::new();
        let mut has_updates = false;

        if counter != initial_counter {
            updates.insert(COUNTER_KEY.to_vec(), counter.try_to_vec().unwrap());
            has_updates = true;
        }

        // Write user modifications back to app state
        for (sui_address, updated_user) in _user_modifications_in_block {
            let sui_address_as_bytes = sui_address.as_bytes();
            let serialized_user = updated_user.try_to_vec().unwrap();
            updates.insert(sui_address_as_bytes.to_vec(), serialized_user);
            has_updates = true;
        }

        if has_updates {
            Some(updates)
        } else {
            None
        }    
    }
} 