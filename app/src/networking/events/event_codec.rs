use std::io;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::events::Event;

/// Protocol name for event streaming
#[derive(Debug, Clone)]
pub struct EventStreamProtocol;

impl AsRef<str> for EventStreamProtocol {
    fn as_ref(&self) -> &str {
        "/pismo/events/1.0.0"
    }
}

/// Configuration constants for event streaming
pub const MAX_BATCH_SIZE: usize = 100;        // Max events per batch
pub const BATCH_TIMEOUT_MS: u64 = 500;        // Max wait before sending partial batch
pub const MAX_BUFFER_SIZE: usize = 10000;     // Drop client if buffer exceeds
pub const MAX_CONCURRENT_STREAMS: usize = 100; // Max simultaneous clients
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB max message size

/// Request from client to subscribe to event stream
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct EventStreamRequest {
    /// Start version (inclusive)
    pub start_version: u64,
    /// Optional end version (inclusive). None = stream forever
    pub end_version: Option<u64>,
}

/// Response to client containing batched events
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct EventStreamResponse {
    /// Batch of events
    pub events: Vec<Event>,
    /// Whether this batch contains live events (vs historic)
    pub is_live: bool,
    /// Latest version available on the server
    pub current_version: u64,
}

/// Codec for event stream messages
#[derive(Debug, Clone, Default)]
pub struct EventStreamCodec;

impl EventStreamCodec {
    pub fn new() -> Self {
        Self
    }
    
    /// Read an event stream request from the wire
    pub async fn read_request<T>(&mut self, io: &mut T) -> io::Result<EventStreamRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read message length (4 bytes, little-endian)
        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Request too large: {} bytes", len),
            ));
        }

        // Read message data
        let mut buffer = vec![0u8; len];
        io.read_exact(&mut buffer).await?;

        // Deserialize request using Borsh
        <EventStreamRequest as BorshDeserialize>::try_from_slice(&buffer).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to deserialize request: {}", e),
            )
        })
    }

    /// Write an event stream response to the wire
    pub async fn write_response<T>(&mut self, io: &mut T, response: EventStreamResponse) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize response using Borsh
        let data = <EventStreamResponse as BorshSerialize>::try_to_vec(&response).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize response: {}", e),
            )
        })?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Response too large: {} bytes", data.len()),
            ));
        }

        // Write message length (4 bytes, little-endian)
        let len = data.len() as u32;
        io.write_all(&len.to_le_bytes()).await?;

        // Write message data
        io.write_all(&data).await?;
        io.flush().await?;

        Ok(())
    }
}

