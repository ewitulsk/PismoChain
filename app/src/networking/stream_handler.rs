use std::{
    collections::VecDeque,
    io,
    task::{Context, Poll},
};
use futures::{AsyncReadExt, AsyncWriteExt, future::BoxFuture, FutureExt, future::{Ready, ready}};
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
    swarm::{
        handler::{ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound, ListenUpgradeError},
        ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol,
    },
    Stream,
};
use hotstuff_rs::networking::messages::Message;
use tracing::{debug, error, warn, info};

/// Protocol name for hotstuff messages
#[derive(Debug, Clone)]
pub struct HotstuffStreamProtocol;

impl AsRef<str> for HotstuffStreamProtocol {
    fn as_ref(&self) -> &str {
        "/hotstuff/stream/1.0.0"
    }
}

impl UpgradeInfo for HotstuffStreamProtocol {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/hotstuff/stream/1.0.0")
    }
}

impl InboundUpgrade<libp2p::Stream> for HotstuffStreamProtocol {
    type Output = libp2p::Stream;
    type Error = std::io::Error;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: libp2p::Stream, _info: Self::Info) -> Self::Future {
        // For a simple stream protocol, just return the stream as-is
        ready(Ok(socket))
    }
}

impl OutboundUpgrade<libp2p::Stream> for HotstuffStreamProtocol {
    type Output = libp2p::Stream;
    type Error = std::io::Error;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: libp2p::Stream, _info: Self::Info) -> Self::Future {
        // For a simple stream protocol, just return the stream as-is
        ready(Ok(socket))
    }
}

/// Events sent to the handler
pub enum HandlerInEvent {
    /// Send a message on this connection
    SendMessage(Message),
}

/// Events emitted by the handler
pub enum HandlerOutEvent {
    /// Received a message
    MessageReceived(Message),
    /// Successfully sent a message
    MessageSent,
    /// Failed to send a message
    SendError(io::Error),
    /// Failed to receive a message
    ReceiveError(io::Error),
}

// Manual Debug implementation to work around Message not implementing Debug
impl std::fmt::Debug for HandlerInEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerInEvent::SendMessage(_) => write!(f, "HandlerInEvent::SendMessage(Message)"),
        }
    }
}

impl std::fmt::Debug for HandlerOutEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerOutEvent::MessageReceived(_) => write!(f, "HandlerOutEvent::MessageReceived(Message)"),
            HandlerOutEvent::MessageSent => write!(f, "HandlerOutEvent::MessageSent"),
            HandlerOutEvent::SendError(e) => write!(f, "HandlerOutEvent::SendError({:?})", e),
            HandlerOutEvent::ReceiveError(e) => write!(f, "HandlerOutEvent::ReceiveError({:?})", e),
        }
    }
}

/// State of an active stream
enum StreamState {
    /// Waiting to send a message
    PendingSend {
        message: Message,
        stream: Stream,
    },
    /// Currently sending a message
    Sending {
        future: BoxFuture<'static, Result<Stream, io::Error>>,
    },
    /// Waiting to receive a message
    PendingReceive {
        stream: Stream,
    },
    /// Currently receiving a message
    Receiving {
        future: BoxFuture<'static, Result<(Stream, Message), io::Error>>,
    },
    /// Stream is idle
    Idle(Stream),
    /// Stream has failed
    Failed,
}

/// Connection handler for HotStuff stream protocol
pub struct HotstuffStreamHandler {
    /// Outbound messages queue
    outbound_queue: VecDeque<Message>,
    /// Inbound stream state
    inbound_stream: Option<StreamState>,
    /// Outbound stream state
    outbound_stream: Option<StreamState>,
    /// Events to emit
    pending_events: VecDeque<HandlerOutEvent>,
    /// Whether we're currently requesting an outbound stream
    requesting_outbound: bool,
    /// Keep connection alive
    keep_alive: bool,
}

impl HotstuffStreamHandler {
    pub fn new() -> Self {
        Self {
            outbound_queue: VecDeque::new(),
            inbound_stream: None,
            outbound_stream: None,
            pending_events: VecDeque::new(),
            requesting_outbound: false,
            keep_alive: true,
        }
    }
    
    /// Send a message on the stream
    async fn send_message(mut stream: Stream, message: Message) -> Result<Stream, io::Error> {
        // Serialize message using Borsh
        let data = <Message as borsh::BorshSerialize>::try_to_vec(&message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        // Write message length (4 bytes, little-endian)
        let len = data.len() as u32;
        stream.write_all(&len.to_le_bytes()).await?;
        
        // Write message data
        stream.write_all(&data).await?;
        stream.flush().await?;
        
        Ok(stream)
    }
    
    /// Receive a message from the stream
    async fn receive_message(mut stream: Stream) -> Result<(Stream, Message), io::Error> {
        // Read message length (4 bytes, little-endian)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        
        // Sanity check message size
        const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB
        if len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Message too large: {} bytes", len),
            ));
        }
        
        // Read message data
        let mut buffer = vec![0u8; len];
        stream.read_exact(&mut buffer).await?;
        
        // Deserialize message using Borsh
        let message = <Message as borsh::BorshDeserialize>::try_from_slice(&buffer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        Ok((stream, message))
    }
}

impl ConnectionHandler for HotstuffStreamHandler {
    type FromBehaviour = HandlerInEvent;
    type ToBehaviour = HandlerOutEvent;
    type InboundProtocol = HotstuffStreamProtocol;
    type OutboundProtocol = HotstuffStreamProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();
    
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(HotstuffStreamProtocol, ())
    }
    
    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            HandlerInEvent::SendMessage(message) => {
                //info!("🚀 StreamHandler::on_behaviour_event - SendMessage");
                //info!("🚀 Message type: {:?}", std::mem::discriminant(&message));
                //info!("🚀 Outbound queue size before: {}", self.outbound_queue.len());
                self.outbound_queue.push_back(message);
                //info!("🚀 Outbound queue size after: {}", self.outbound_queue.len());
            }
        }
    }
    
    fn connection_keep_alive(&self) -> bool {
        self.keep_alive || !self.outbound_queue.is_empty() || self.inbound_stream.is_some() || self.outbound_stream.is_some()
    }
    
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>> {
        // Emit pending events
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        
        // Poll inbound stream
        if let Some(state) = self.inbound_stream.take() {
            match state {
                StreamState::PendingReceive { stream } => {
                    let future = Self::receive_message(stream).boxed();
                    self.inbound_stream = Some(StreamState::Receiving { future });
                    cx.waker().wake_by_ref();
                }
                StreamState::Receiving { mut future } => {
                    match future.poll_unpin(cx) {
                        Poll::Ready(Ok((stream, message))) => {
                            //info!("📨 StreamHandler: Successfully received and decoded message");
                            //info!("📨 Received message type: {:?}", std::mem::discriminant(&message));
                            self.pending_events.push_back(HandlerOutEvent::MessageReceived(message));
                            self.inbound_stream = Some(StreamState::PendingReceive { stream });
                            cx.waker().wake_by_ref();
                        }
                        Poll::Ready(Err(e)) => {
                            self.pending_events.push_back(HandlerOutEvent::ReceiveError(e));
                            self.inbound_stream = None;
                        }
                        Poll::Pending => {
                            self.inbound_stream = Some(StreamState::Receiving { future });
                        }
                    }
                }
                other => self.inbound_stream = Some(other),
            }
        }
        
        // Poll outbound stream
        if let Some(state) = self.outbound_stream.take() {
            match state {
                StreamState::Idle(stream) => {
                    if let Some(message) = self.outbound_queue.pop_front() {
                        self.outbound_stream = Some(StreamState::PendingSend { message, stream });
                        cx.waker().wake_by_ref();
                    } else {
                        self.outbound_stream = Some(StreamState::Idle(stream));
                    }
                }
                StreamState::PendingSend { message, stream } => {
                    let future = Self::send_message(stream, message).boxed();
                    self.outbound_stream = Some(StreamState::Sending { future });
                    cx.waker().wake_by_ref();
                }
                StreamState::Sending { mut future } => {
                    match future.poll_unpin(cx) {
                        Poll::Ready(Ok(stream)) => {
                            //info!("📤 StreamHandler: Successfully sent message over wire");
                            self.pending_events.push_back(HandlerOutEvent::MessageSent);
                            self.outbound_stream = Some(StreamState::Idle(stream));
                            cx.waker().wake_by_ref();
                        }
                        Poll::Ready(Err(e)) => {
                            self.pending_events.push_back(HandlerOutEvent::SendError(e));
                            self.outbound_stream = None;
                            
                            // Request new outbound stream if we have more messages and not already requesting
                            if !self.outbound_queue.is_empty() && !self.requesting_outbound {
                                self.requesting_outbound = true;
                                return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                                    protocol: SubstreamProtocol::new(HotstuffStreamProtocol, ()),
                                });
                            }
                        }
                        Poll::Pending => {
                            self.outbound_stream = Some(StreamState::Sending { future });
                        }
                    }
                }
                other => self.outbound_stream = Some(other),
            }
        } else if !self.outbound_queue.is_empty() && !self.requesting_outbound {
            // Request new outbound stream only if we're not already requesting one
            self.requesting_outbound = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(HotstuffStreamProtocol, ()),
            });
        }
        
        Poll::Pending
    }
    
    fn on_connection_event(&mut self, event: ConnectionEvent<'_, Self::InboundProtocol, Self::OutboundProtocol, Self::InboundOpenInfo, Self::OutboundOpenInfo>) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound { protocol, .. }) => {
                self.inbound_stream = Some(StreamState::PendingReceive { stream: protocol });
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound { protocol, .. }) => {
                self.requesting_outbound = false; // Reset the requesting flag
                self.outbound_stream = Some(StreamState::Idle(protocol));
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => {
                self.requesting_outbound = false; // Reset the requesting flag on error
                self.pending_events.push_back(HandlerOutEvent::SendError(
                    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
                ));
            },
            ConnectionEvent::ListenUpgradeError(ListenUpgradeError { error, .. }) => {
                error!("❌ Inbound substream upgrade failed: {}", error);
                self.pending_events.push_back(HandlerOutEvent::ReceiveError(
                    io::Error::new(io::ErrorKind::ConnectionAborted, error.to_string())
                ));
            }
            _ => {
                debug!("Other connection event: {:?}", std::mem::discriminant(&event));
            }
        }
    }
}
