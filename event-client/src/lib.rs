//! PismoChain Event Client SDK
//!
//! This crate provides a simple, lightweight client for streaming events from
//! PismoChain listener nodes via gRPC.
//!
//! # Features
//!
//! - Simple API: Just `connect()` and `subscribe()`
//! - Async streaming using `futures::Stream`
//! - No complex setup required
//! - Raw event data (no automatic deserialization)
//!
//! # Example
//!
//! ```no_run
//! use pismo_event_client::EventStreamClient;
//! use futures::StreamExt;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to listener node
//!     let mut client = EventStreamClient::connect("http://127.0.0.1:50051").await?;
//!     
//!     // Subscribe to events starting from version 0
//!     let mut stream = client.subscribe(0, None).await?;
//!     
//!     // Process events as they arrive
//!     while let Some(event) = stream.next().await {
//!         let event = event?;
//!         println!("Event {}: {}", event.version, event.event_type);
//!         
//!         // Deserialize event_data based on event_type
//!         // (see examples/deserialize_events.rs)
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Event Deserialization
//!
//! The SDK returns raw `event_data` bytes to keep it lightweight. You are
//! responsible for deserializing based on the `event_type`:
//!
//! ```rust
//! use borsh::BorshDeserialize;
//!
//! #[derive(BorshDeserialize)]
//! struct TransferEvent {
//!     from: [u8; 32],
//!     to: [u8; 32],
//!     amount: u128,
//! }
//!
//! fn deserialize_transfer(event_data: &[u8]) -> Result<TransferEvent, std::io::Error> {
//!     TransferEvent::try_from_slice(event_data)
//! }
//! ```
//!
//! See `examples/deserialize_events.rs` for a complete example.

pub mod client;
pub mod error;

// Re-export the generated protobuf types
pub mod proto {
    tonic::include_proto!("pismo.events.v1");
}

pub use client::EventStreamClient;
pub use error::{Error, Result};
pub use proto::{Event, EventBatch, SubscribeRequest};

/// Convenience function to connect to a listener node
///
/// This is a shorthand for `EventStreamClient::connect(endpoint).await`.
///
/// # Example
/// ```no_run
/// # use pismo_event_client;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = pismo_event_client::connect("http://127.0.0.1:50051").await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect(endpoint: impl Into<String>) -> Result<EventStreamClient> {
    EventStreamClient::connect(endpoint).await
}
