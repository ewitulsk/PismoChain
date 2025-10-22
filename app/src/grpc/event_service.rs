use std::pin::Pin;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tonic::{Request, Response, Status};
use tracing::{info, error, warn};

use crate::database::rocks_db::RocksDBStore;
use crate::events::{get_events_range, CommittedEvents};

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("pismo.events.v1");
}

use proto::{
    event_stream_server::EventStream,
    Event, EventBatch, SubscribeRequest,
};

const BATCH_SIZE: usize = 100;
const BATCH_TIMEOUT: Duration = Duration::from_millis(500);

pub struct EventStreamService {
    kv_store: RocksDBStore,
    event_broadcast: broadcast::Sender<CommittedEvents>,
}

impl EventStreamService {
    pub fn new(
        kv_store: RocksDBStore,
        event_broadcast: broadcast::Sender<CommittedEvents>,
    ) -> Self {
        Self {
            kv_store,
            event_broadcast,
        }
    }

    /// Convert our internal Event type to protobuf Event
    fn convert_event(event: crate::events::Event) -> Event {
        Event {
            version: event.version,
            event_index: event.event_index,
            event_type: event.event_type,
            event_data: event.event_data,
        }
    }

    /// Get the current version from the KV store
    fn get_current_version(&self) -> u64 {
        use hotstuff_rs::block_tree::pluggables::KVGet;
        use crate::jmt_state::LATEST_VERSION_KEY;
        
        // HotStuff stores committed app state with a prefix byte (3)
        const COMMITTED_APP_STATE: u8 = 3;
        let mut key = Vec::new();
        key.push(COMMITTED_APP_STATE);
        key.extend_from_slice(LATEST_VERSION_KEY);
        
        if let Some(version_bytes) = self.kv_store.get(&key) {
            if version_bytes.len() >= 8 {
                let version = u64::from_le_bytes(version_bytes[..8].try_into().unwrap_or([0u8; 8]));
                return version;
            }
        }
        warn!("⚠️ Could not read current version from storage, defaulting to 0");
        0
    }
}

#[tonic::async_trait]
impl EventStream for EventStreamService {
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<EventBatch, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        let start_version = req.start_version;
        let end_version = req.end_version;

        info!(
            "New event subscription: start={}, end={:?}",
            start_version, end_version
        );

        let current_version = self.get_current_version();
        let kv_store = self.kv_store.clone();
        let kv_store_for_live = kv_store.clone();
        let live_receiver = self.event_broadcast.subscribe();

        // Create the stream
        let stream = async_stream::stream! {
            // Helper to get current version from within the stream
            let get_version = |kv: &RocksDBStore| -> u64 {
                use hotstuff_rs::block_tree::pluggables::KVGet;
                use crate::jmt_state::LATEST_VERSION_KEY;
                
                // HotStuff stores committed app state with a prefix byte (3)
                const COMMITTED_APP_STATE: u8 = 3;
                let mut key = Vec::new();
                key.push(COMMITTED_APP_STATE);
                key.extend_from_slice(LATEST_VERSION_KEY);
                
                if let Some(version_bytes) = kv.get(&key) {
                    if version_bytes.len() >= 8 {
                        return u64::from_le_bytes(version_bytes[..8].try_into().unwrap_or([0u8; 8]));
                    }
                }
                0
            };
            // Phase 1: Historic events
            let mut next_version = start_version;
            
            if next_version <= current_version {
                info!("Fetching historic events from {} to {}", next_version, current_version);
                
                // Fetch historic events in batches
                loop {
                    let batch_end = std::cmp::min(next_version + BATCH_SIZE as u64, current_version + 1);
                    
                    match get_events_range(&kv_store, next_version, batch_end) {
                        Ok(events) if !events.is_empty() => {
                            let proto_events: Vec<Event> = events.into_iter()
                                .map(Self::convert_event)
                                .collect();
                            
                            yield Ok(EventBatch {
                                events: proto_events,
                                is_live: false,
                                current_version,
                            });
                            
                            next_version = batch_end;
                            
                            if next_version > current_version {
                                break;
                            }
                        }
                        Ok(_) => {
                            // No events in this range, move forward
                            next_version = batch_end;
                            if next_version > current_version {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("❌ Error fetching historic events: {}", e);
                            yield Err(Status::internal(format!("Failed to fetch events: {}", e)));
                            return;
                        }
                    }
                    
                    // Check if we've reached the end_version
                    if let Some(end) = end_version {
                        if next_version > end {
                            info!("Reached end_version {}, stopping stream", end);
                            return;
                        }
                    }
                }
                
            }

            // Phase 2: Live events
            if end_version.is_none() || end_version.unwrap() > current_version {
                let mut live_stream = BroadcastStream::new(live_receiver);
                let mut batch_buffer: Vec<Event> = Vec::new();
                let mut last_flush = tokio::time::Instant::now();
                
                loop {
                    tokio::select! {
                        // Receive new committed events
                        Some(result) = live_stream.next() => {
                            match result {
                                Ok(committed) => {
                                    // Check if we should include these events
                                    let should_include = if let Some(end) = end_version {
                                        committed.version <= end
                                    } else {
                                        true
                                    };
                                    
                                    if should_include {
                                        // Convert and buffer events
                                        for event in committed.events {
                                            batch_buffer.push(Self::convert_event(event));
                                        }
                                        
                                        // Flush if buffer is full
                                        if batch_buffer.len() >= BATCH_SIZE {
                                            let events = std::mem::take(&mut batch_buffer);
                                            let current = get_version(&kv_store_for_live);
                                            yield Ok(EventBatch {
                                                events,
                                                is_live: true,
                                                current_version: current,
                                            });
                                            last_flush = tokio::time::Instant::now();
                                        }
                                        
                                        // Check if we've reached end_version
                                        if let Some(end) = end_version {
                                            if committed.version >= end {
                                                // Flush any remaining buffered events
                                                if !batch_buffer.is_empty() {
                                                    let events = std::mem::take(&mut batch_buffer);
                                                    let current = get_version(&kv_store_for_live);
                                                    yield Ok(EventBatch {
                                                        events,
                                                        is_live: true,
                                                        current_version: current,
                                                    });
                                                }
                                                info!("Reached end_version {}, stopping stream", end);
                                                return;
                                            }
                                        }
                                    } else {
                                        // Reached end_version, flush and exit
                                        if !batch_buffer.is_empty() {
                                            let events = std::mem::take(&mut batch_buffer);
                                            let current = get_version(&kv_store_for_live);
                                            yield Ok(EventBatch {
                                                events,
                                                is_live: true,
                                                current_version: current,
                                            });
                                        }
                                        return;
                                    }
                                }
                                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                                    warn!("Event stream lagged by {} events, client too slow", n);
                                    yield Err(Status::resource_exhausted("Client too slow, events lagging"));
                                    return;
                                }
                            }
                        }
                        // Timeout for batching
                        _ = tokio::time::sleep_until(last_flush + BATCH_TIMEOUT) => {
                            if !batch_buffer.is_empty() {
                                let events = std::mem::take(&mut batch_buffer);
                                let current = get_version(&kv_store_for_live);
                                yield Ok(EventBatch {
                                    events,
                                    is_live: true,
                                    current_version: current,
                                });
                                last_flush = tokio::time::Instant::now();
                            }
                        }
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

