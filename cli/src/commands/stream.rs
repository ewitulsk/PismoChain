use anyhow::{Context, Result};
use pismo_event_client::{EventStreamClient, Event};
use futures::StreamExt;
use borsh::BorshDeserialize;
use pismo_chain::events::TransferEvent;

pub async fn stream_events_command(endpoint: &str, start_version: u64, end_version: Option<u64>) -> Result<()> {
    eprintln!("Connecting to listener: {}", endpoint);
    eprintln!("Starting from version: {}", start_version);
    if let Some(end) = end_version {
        eprintln!("Ending at version: {}", end);
    }
    eprintln!();
    
    // Connect to the listener node
    let mut client = EventStreamClient::connect(endpoint).await
        .context("Failed to connect to listener node")?;
    
    eprintln!("Successfully connected! Streaming events...");
    eprintln!("Press Ctrl+C to stop");
    eprintln!();
    
    // Subscribe to events
    let mut event_stream = client.subscribe(start_version, end_version).await
        .context("Failed to subscribe to events")?;
    
    // Stream and print events
    let mut event_count = 0;
    while let Some(result) = event_stream.next().await {
        match result {
            Ok(event) => {
                print_event(&event);
                event_count += 1;
                
                // Print a summary every 100 events
                if event_count % 100 == 0 {
                    eprintln!("--- Received {} events so far ---", event_count);
                }
            }
            Err(e) => {
                eprintln!("Error receiving event: {}", e);
                eprintln!("Stream ended after {} events", event_count);
                break;
            }
        }
    }
    
    eprintln!();
    eprintln!("Stream completed. Total events received: {}", event_count);
    
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
        match <TransferEvent as BorshDeserialize>::try_from_slice(&event.event_data) {
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

