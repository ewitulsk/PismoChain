use std::io;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use hotstuff_rs::networking::messages::Message;

/// Protocol name for hotstuff messages
#[derive(Debug, Clone)]
pub struct HotstuffProtocol;

impl AsRef<str> for HotstuffProtocol {
    fn as_ref(&self) -> &str {
        "/hotstuff/1.0.0"
    }
}

/// Maximum message size (16MB) to handle large block sync responses
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Codec for hotstuff messages using bincode serialization
#[derive(Debug, Clone, Default)]
pub struct HotstuffCodec;

impl HotstuffCodec {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl request_response::Codec for HotstuffCodec {
    type Protocol = HotstuffProtocol;
    type Request = Message;
    type Response = ();

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
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
                format!("Message too large: {} bytes", len),
            ));
        }

        // Read message data
        let mut buffer = vec![0u8; len];
        io.read_exact(&mut buffer).await?;

        // Deserialize message using Borsh (HotStuff messages use Borsh, not Serde)
        <Message as borsh::BorshDeserialize>::try_from_slice(&buffer).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to deserialize message: {}", e),
            )
        })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // We don't use responses in the hotstuff protocol
        // All communication is one-way requests
        Ok(())
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize message using Borsh (HotStuff messages use Borsh, not Serde)
        let data = <Message as borsh::BorshSerialize>::try_to_vec(&req).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize message: {}", e),
            )
        })?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Serialized message too large: {} bytes", data.len()),
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

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // We don't use responses in the hotstuff protocol
        Ok(())
    }
}

/// Helper function to estimate serialized message size
pub fn estimate_message_size(message: &Message) -> usize {
    // This is a rough estimate - actual size may vary
    // Used for queue management and memory planning
    match message {
        Message::ProgressMessage(_) => 2048,      // ~2KB for consensus messages
        Message::BlockSyncMessage(_) => 65536,    // ~64KB (can be large for responses)
    }
}


