# PismoChain Event Client SDK

A lightweight Rust client library for streaming events from PismoChain listener nodes via gRPC.

## Features

- **Simple API**: Just `connect()` and `subscribe()`
- **Async Streaming**: Built on `futures::Stream` for efficient event processing
- **No Complex Setup**: No need to manage libp2p swarms or connections
- **Raw Event Data**: Lightweight design - you handle deserialization
- **Multi-language Support**: gRPC enables easy client generation for other languages

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pismo-event-client = { path = "../event-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
futures = "0.3"
```

## Quick Start

```rust
use pismo_event_client::EventStreamClient;
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to listener node
    let mut client = EventStreamClient::connect("http://127.0.0.1:50051").await?;
    
    // Subscribe to events starting from version 0
    let mut stream = client.subscribe(0, None).await?;
    
    // Process events as they arrive
    while let Some(event) = stream.next().await {
        let event = event?;
        println!("Event {}: {}", event.version, event.event_type);
    }
    
    Ok(())
}
```

## API Reference

### `EventStreamClient::connect(endpoint)`

Connect to a PismoChain listener node.

**Parameters:**
- `endpoint` - gRPC endpoint URL (e.g., `"http://127.0.0.1:50051"`)

**Returns:** `Result<EventStreamClient>`

### `client.subscribe(start_version, end_version)`

Subscribe to a stream of events.

**Parameters:**
- `start_version: u64` - First version to stream (inclusive)
- `end_version: Option<u64>` - Optional last version (inclusive), `None` = stream forever

**Returns:** `Result<impl Stream<Item = Result<Event>>>`

## Event Structure

Events returned by the stream have the following structure:

```rust
pub struct Event {
    pub version: u64,        // JMT version when event was emitted
    pub event_index: u32,    // Index within the version
    pub event_type: String,  // Event type identifier (e.g., "Transfer")
    pub event_data: Vec<u8>, // Borsh-serialized event data
}
```

## Event Deserialization

The SDK returns raw `event_data` bytes. You deserialize based on `event_type`:

```rust
use borsh::BorshDeserialize;

#[derive(BorshDeserialize)]
struct TransferEvent {
    from: [u8; 32],
    to: [u8; 32],
    coin: [u8; 32],
    amount: u128,
}

fn deserialize_transfer(event: &Event) -> Result<TransferEvent> {
    TransferEvent::try_from_slice(&event.event_data)
        .map_err(|e| Error::Serialization(e.to_string()))
}

// Use it:
match event.event_type.as_str() {
    "Transfer" => {
        let transfer = deserialize_transfer(&event)?;
        println!("Transfer: {} tokens from {} to {}", 
            transfer.amount, 
            hex::encode(transfer.from),
            hex::encode(transfer.to)
        );
    }
    _ => {}
}
```

See `examples/deserialize_events.rs` for a complete example.

## Examples

### Basic Streaming

```bash
cargo run --example simple_stream -- http://127.0.0.1:50051 0
```

Stream events from a listener node starting at version 0.

### Event Deserialization

```bash
cargo run --example deserialize_events
```

Demonstrates how to deserialize different event types.

## Configuration

### Listener Node Setup

To run a listener node with gRPC event streaming:

```bash
# Start a listener node
PISMO_NODE_ROLE=listener \
PISMO_GRPC_PORT=50051 \
PISMO_INIT_STORAGE=true \
cargo run --release
```

Environment variables:
- `PISMO_NODE_ROLE=listener` - Run as listener (read-only)
- `PISMO_GRPC_PORT` - gRPC port (default: 50051)
- `PISMO_INIT_STORAGE=true` - Initialize storage on first run

## Error Handling

The client provides detailed error information:

```rust
use pismo_event_client::Error;

match client.subscribe(0, None).await {
    Ok(stream) => { /* ... */ }
    Err(Error::Connection(msg)) => {
        eprintln!("Connection failed: {}", msg);
    }
    Err(Error::Serialization(msg)) => {
        eprintln!("Serialization failed: {}", msg);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Multi-language Support

Since this SDK uses gRPC, you can generate clients for other languages:

### TypeScript/JavaScript

```bash
# Generate TypeScript client
npm install @grpc/grpc-js @grpc/proto-loader
npx grpc_tools_node_protoc \
  --js_out=import_style=commonjs,binary:./generated \
  --grpc_out=grpc_js:./generated \
  --proto_path=../app/proto \
  events.proto
```

### Python

```bash
# Generate Python client
pip install grpcio grpcio-tools
python -m grpc_tools.protoc \
  --python_out=./generated \
  --grpc_python_out=./generated \
  --proto_path=../app/proto \
  events.proto
```

### Go

```bash
# Generate Go client
protoc --go_out=. --go-grpc_out=. \
  --proto_path=../app/proto \
  events.proto
```

## Performance

- **Batching**: Events are automatically batched (up to 100 events or 500ms timeout)
- **Backpressure**: Slow clients are disconnected if they lag too much
- **Historic + Live**: Efficiently streams historic events then switches to live streaming

## Architecture

The event streaming system:

1. **Storage**: Events stored in RocksDB column family with version-based keys
2. **Distribution**: Broadcast channel distributes live events to subscribers
3. **gRPC**: Standard HTTP/2-based streaming for broad compatibility
4. **Consensus**: Listener nodes replicate via libp2p but serve events via gRPC

## Troubleshooting

### Connection Refused

Ensure the listener node is running and `PISMO_GRPC_PORT` is accessible:

```bash
# Check if gRPC port is listening
lsof -i :50051
```

### No Events Received

Events are only emitted when transactions execute. Check:
- Listener is syncing blocks
- Transactions are being submitted to validators
- Events are actually emitted by your transaction types

### Slow Streaming

If events are arriving slowly:
- Check network latency to listener node
- Verify listener node is not overloaded
- Consider reducing `start_version` to catch up faster

## License

MIT
