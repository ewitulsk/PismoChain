//! Simple example showing how to stream events from a PismoChain listener
//!
//! This example demonstrates the basic usage of the event client SDK.
//!
//! Run with:
//! ```bash
//! cargo run --example simple_stream -- <grpc_endpoint> <start_version>
//! ```
//!
//! Example:
//! ```bash
//! cargo run --example simple_stream -- http://127.0.0.1:50051 0
//! ```

use pismo_event_client::{EventStreamClient, Event, Result};
use futures::StreamExt;
use std::env;
use borsh::{BorshDeserialize, BorshSerialize};

/// Transfer event emitted for mint and transfer operations
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct TransferEvent {
    pub from_coinstore: [u8; 32],
    pub to_coinstore: [u8; 32],
    pub coin_address: [u8; 32],
    pub amount: u128,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    let endpoint = if args.len() >= 2 {
        args[1].clone()
    } else {
        "http://127.0.0.1:50051".to_string()
    };
    
    let start_version: u64 = if args.len() >= 3 {
        args[2].parse().expect("start_version must be a valid u64")
    } else {
        0
    };
    
    println!("Connecting to listener: {}", endpoint);
    println!("Starting from version: {}", start_version);
    println!();
    
    // Connect to the listener node
    let mut client = EventStreamClient::connect(&endpoint).await?;
    
    println!("Successfully connected! Streaming events...");
    println!("Press Ctrl+C to stop");
    println!();
    
    // Subscribe to events
    let mut event_stream = client.subscribe(start_version, None).await?;
    
    // Stream and print events
    let mut event_count = 0;
    while let Some(result) = event_stream.next().await {
        match result {
            Ok(event) => {
                print_event(&event);
                event_count += 1;
                
                // Print a summary every 100 events
                if event_count % 100 == 0 {
                    println!("--- Received {} events so far ---", event_count);
                }
            }
            Err(e) => {
                eprintln!("Error receiving event: {}", e);
                eprintln!("Stream ended after {} events", event_count);
                break;
            }
        }
    }
    
    println!();
    println!("Stream completed. Total events received: {}", event_count);
    
    Ok(())
}

/// Pretty print an event
fn print_event(event: &Event) {
    println!("┌─ Event {}.{} (version: {})",
        event.version,
        event.event_index,
        event.version
    );
    println!("│  Type: {}", event.event_type);
    println!("│  Data size: {} bytes", event.event_data.len());
    
    // Deserialize Transfer events
    if event.event_type == "Transfer" {
        match TransferEvent::try_from_slice(&event.event_data) {
            Ok(transfer) => {
                let is_mint = transfer.from_coinstore == [0u8; 32];
                println!("│");
                if is_mint {
                    println!("│  [MINT]");
                } else {
                    println!("│  From: {}", hex::encode(transfer.from_coinstore));
                }
                println!("│  To:   {}", hex::encode(transfer.to_coinstore));
                println!("│  Coin: {}", hex::encode(transfer.coin_address));
                println!("│  Amount: {}", transfer.amount);
            }
            Err(e) => {
                println!("│  Error deserializing Transfer event: {}", e);
            }
        }
    } else {
        // Show hex preview for unknown event types
        if !event.event_data.is_empty() {
            let preview_len = event.event_data.len().min(32);
            let preview = &event.event_data[..preview_len];
            let hex: String = preview.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            
            println!("│  Data preview: {}{}", 
                hex,
                if event.event_data.len() > 32 { "..." } else { "" }
            );
        }
    }
    
    println!("└─");
}
