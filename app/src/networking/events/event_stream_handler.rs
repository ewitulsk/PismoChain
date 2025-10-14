use std::{
    collections::VecDeque,
    io,
    task::{Context, Poll},
};
use futures::{future::BoxFuture, FutureExt, future::{Ready, ready}};
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade, UpgradeInfo},
    swarm::{
        handler::{ConnectionEvent, FullyNegotiatedInbound},
        ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol,
    },
    Stream,
};
use tracing::{debug, error, warn};

use super::event_codec::{EventStreamProtocol, EventStreamRequest, EventStreamResponse, EventStreamCodec};

/// Events sent to the handler (from behaviour)
#[derive(Debug)]
pub enum HandlerInEvent {
    /// Send a batch of events to the client
    SendBatch(EventStreamResponse),
    /// Close the stream
    CloseStream,
}

/// Events emitted by the handler (to behaviour)
#[derive(Debug)]
pub enum HandlerOutEvent {
    /// Received a subscription request from client
    RequestReceived(EventStreamRequest),
    /// Successfully sent a batch
    BatchSent,
    /// Stream was closed
    StreamClosed,
    /// Error occurred
    Error(String),
}

impl UpgradeInfo for EventStreamProtocol {
    type Info = &'static str;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once("/pismo/events/1.0.0")
    }
}

impl InboundUpgrade<Stream> for EventStreamProtocol {
    type Output = Stream;
    type Error = io::Error;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: Stream, _info: Self::Info) -> Self::Future {
        ready(Ok(socket))
    }
}

impl OutboundUpgrade<Stream> for EventStreamProtocol {
    type Output = Stream;
    type Error = io::Error;
    type Future = Ready<Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: Stream, _info: Self::Info) -> Self::Future {
        ready(Ok(socket))
    }
}

/// State of the event stream
enum StreamState {
    /// Reading the initial request from client
    ReadingRequest {
        future: BoxFuture<'static, Result<(EventStreamRequest, Stream), io::Error>>,
    },
    /// Idle, waiting for batches to send
    Idle,
    /// Sending a batch to the client
    SendingBatch {
        future: BoxFuture<'static, Result<Stream, io::Error>>,
    },
    /// Stream is closed
    Closed,
}

/// Connection handler for event streaming
pub struct EventStreamHandler {
    /// The active stream (if any)
    stream: Option<Stream>,
    /// Current state of the stream
    state: StreamState,
    /// Queue of pending responses to send
    pending_responses: VecDeque<EventStreamResponse>,
    /// Pending events to emit to behaviour
    pending_events: VecDeque<HandlerOutEvent>,
}

impl EventStreamHandler {
    pub fn new() -> Self {
        Self {
            stream: None,
            state: StreamState::Closed,
            pending_responses: VecDeque::new(),
            pending_events: VecDeque::new(),
        }
    }

    /// Start reading the request from the stream
    fn start_reading_request(&mut self, stream: Stream) {
        let mut codec = EventStreamCodec::new();
        let future = async move {
            let mut stream = stream;
            let request = codec.read_request(&mut stream).await?;
            Ok((request, stream))
        }.boxed();
        
        self.state = StreamState::ReadingRequest { future };
    }

    /// Start sending a batch on the stream
    fn start_sending_batch(&mut self, batch: EventStreamResponse) {
        if let Some(stream) = self.stream.take() {
            let mut codec = EventStreamCodec::new();
            let future = async move {
                let mut stream = stream;
                codec.write_response(&mut stream, batch).await?;
                Ok(stream)
            }.boxed();
            
            self.state = StreamState::SendingBatch { future };
        } else {
            warn!("Attempted to send batch but no stream available");
            self.pending_events.push_back(HandlerOutEvent::Error("No stream available".to_string()));
        }
    }
}

impl ConnectionHandler for EventStreamHandler {
    type FromBehaviour = HandlerInEvent;
    type ToBehaviour = HandlerOutEvent;
    type InboundProtocol = EventStreamProtocol;
    type OutboundProtocol = EventStreamProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(EventStreamProtocol, ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            HandlerInEvent::SendBatch(batch) => {
                // Queue the batch if we're busy, otherwise send immediately
                match &self.state {
                    StreamState::Idle => {
                        self.start_sending_batch(batch);
                    }
                    _ => {
                        self.pending_responses.push_back(batch);
                    }
                }
            }
            HandlerInEvent::CloseStream => {
                self.state = StreamState::Closed;
                self.stream = None;
                self.pending_events.push_back(HandlerOutEvent::StreamClosed);
            }
        }
    }

    fn connection_keep_alive(&self) -> bool {
        // Keep connection alive while we have an active stream or pending responses
        !matches!(self.state, StreamState::Closed) || !self.pending_responses.is_empty()
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>> {
        // First, emit any pending events
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }

        // Poll the current state
        match &mut self.state {
            StreamState::ReadingRequest { future } => {
                match future.poll_unpin(cx) {
                    Poll::Ready(Ok((request, stream))) => {
                        debug!("Received event stream request: start={}, end={:?}", 
                            request.start_version, request.end_version);
                        self.stream = Some(stream);
                        self.state = StreamState::Idle;
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            HandlerOutEvent::RequestReceived(request)
                        ));
                    }
                    Poll::Ready(Err(e)) => {
                        error!("Failed to read event stream request: {}", e);
                        self.state = StreamState::Closed;
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            HandlerOutEvent::Error(format!("Failed to read request: {}", e))
                        ));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            StreamState::SendingBatch { future } => {
                match future.poll_unpin(cx) {
                    Poll::Ready(Ok(stream)) => {
                        debug!("Successfully sent event batch");
                        self.stream = Some(stream);
                        self.state = StreamState::Idle;
                        
                        // Emit success event
                        self.pending_events.push_back(HandlerOutEvent::BatchSent);
                        
                        // Check if we have more batches to send
                        if let Some(next_batch) = self.pending_responses.pop_front() {
                            self.start_sending_batch(next_batch);
                        }
                        
                        // Return the batch sent event
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(HandlerOutEvent::BatchSent));
                    }
                    Poll::Ready(Err(e)) => {
                        error!("Failed to send event batch: {}", e);
                        self.state = StreamState::Closed;
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            HandlerOutEvent::Error(format!("Failed to send batch: {}", e))
                        ));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            StreamState::Idle => {
                // If we have pending responses, start sending
                if let Some(batch) = self.pending_responses.pop_front() {
                    self.start_sending_batch(batch);
                    cx.waker().wake_by_ref(); // Wake immediately to poll the send
                }
                return Poll::Pending;
            }
            StreamState::Closed => {
                return Poll::Pending;
            }
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                debug!("Event stream fully negotiated (inbound)");
                self.start_reading_request(stream);
            }
            ConnectionEvent::DialUpgradeError(_) => {
                warn!("Event stream dial upgrade error");
                self.state = StreamState::Closed;
            }
            ConnectionEvent::ListenUpgradeError(_) => {
                warn!("Event stream listen upgrade error");
                self.state = StreamState::Closed;
            }
            _ => {}
        }
    }
}

