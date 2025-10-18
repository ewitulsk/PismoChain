//! gRPC event stream client implementation

use futures::StreamExt as FuturesStreamExt;
use tokio_stream::Stream;
use tonic::transport::Channel;

use crate::error::{Error, Result};
use crate::proto::{event_stream_client::EventStreamClient as GrpcClient, Event, SubscribeRequest};

/// Event stream client that connects to a PismoChain listener via gRPC
///
/// This client provides a simple interface for subscribing to blockchain events
/// from a listener node. Events are streamed in real-time, starting from a
/// specified version.
///
/// # Example
/// ```no_run
/// use pismo_event_client::EventStreamClient;
/// use futures::StreamExt;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = EventStreamClient::connect("http://127.0.0.1:50051").await?;
/// let mut stream = client.subscribe(0, None).await?;
///
/// while let Some(event) = stream.next().await {
///     let event = event?;
///     println!("Event: {:?}", event);
/// }
/// # Ok(())
/// # }
/// ```
pub struct EventStreamClient {
    inner: GrpcClient<Channel>,
}

impl EventStreamClient {
    /// Connect to a PismoChain listener node via gRPC
    ///
    /// # Arguments
    /// * `endpoint` - The gRPC endpoint (e.g., "http://127.0.0.1:50051")
    ///
    /// # Example
    /// ```no_run
    /// # use pismo_event_client::EventStreamClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = EventStreamClient::connect("http://127.0.0.1:50051").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self> {
        let endpoint_str = endpoint.into();
        let channel = Channel::from_shared(endpoint_str.clone())
            .map_err(|e| Error::Connection(format!("Invalid endpoint '{}': {}", endpoint_str, e)))?
            .connect()
            .await
            .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", endpoint_str, e)))?;

        Ok(Self {
            inner: GrpcClient::new(channel),
        })
    }

    /// Subscribe to events starting from a specific version
    ///
    /// Returns a stream of events that can be consumed using the `futures::Stream` trait.
    /// Events are yielded one at a time as they arrive from the server.
    ///
    /// # Arguments
    /// * `start_version` - First version to stream (inclusive)
    /// * `end_version` - Optional last version to stream (inclusive). None = stream forever
    ///
    /// # Example
    /// ```no_run
    /// # use pismo_event_client::EventStreamClient;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut client = EventStreamClient::connect("http://127.0.0.1:50051").await?;
    /// 
    /// // Stream all events starting from version 0
    /// let mut stream = client.subscribe(0, None).await?;
    /// 
    /// while let Some(event) = stream.next().await {
    ///     let event = event?;
    ///     println!("Event {}: {}", event.version, event.event_type);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn subscribe(
        &mut self,
        start_version: u64,
        end_version: Option<u64>,
    ) -> Result<impl Stream<Item = Result<Event>>> {
        let request = SubscribeRequest {
            start_version,
            end_version,
        };

        let response = self
            .inner
            .subscribe(request)
            .await
            .map_err(|e| Error::Connection(format!("Subscribe request failed: {}", e)))?;

        let stream = response.into_inner();

        // Flatten event batches into individual events
        let event_stream = stream.flat_map(|result| {
            match result {
                Ok(batch) => {
                    // Convert batch.events into an iterator of Results
                    futures::stream::iter(
                        batch.events.into_iter()
                            .map(|e| Ok::<Event, Error>(e))
                            .collect::<Vec<_>>()
                    )
                }
                Err(e) => {
                    // Convert gRPC error to our error type and emit it once
                    futures::stream::iter(vec![Err(Error::Connection(format!("Stream error: {}", e)))])
                }
            }
        });
        
        Ok(event_stream)
    }
}
