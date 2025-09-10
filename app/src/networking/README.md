# PismoChain LibP2P Networking Implementation

This directory contains the libp2p + QUIC networking layer implementation for PismoChain's HotStuff consensus.

## Architecture

The implementation follows a modular design with clear separation between networking and consensus:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HotStuff-rs   │◄──►│  Network Trait   │◄──►│  LibP2PNetwork  │
│   Consensus     │    │   (Abstract)     │    │  (Concrete)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │ LibP2P + QUIC   │
                                               │   Transport     │
                                               └─────────────────┘
```

## Components

### 1. Configuration (`config.rs`)
- **NetworkConfig**: TOML-serializable configuration for validator network topology
- **NetworkRuntimeConfig**: Runtime configuration with parsed types and mappings
- **ValidatorConfig**: Per-validator configuration (keys, addresses)

### 2. Message Codec (`codec.rs`)
- **HotstuffCodec**: Bincode serialization for HotStuff messages
- **HotstuffProtocol**: Protocol identifier `/hotstuff/1.0.0`
- Length-prefixed framing for stream demultiplexing
- 16MB message size limit for large block sync responses

### 3. Network Behavior (`behaviour.rs`)
- **HotstuffBehaviour**: Custom libp2p NetworkBehaviour
- Composites RequestResponse + Identify protocols
- Connection state tracking and retry logic
- Message queuing for disconnected peers
- Exponential backoff for failed connections

### 4. Network Implementation (`libp2p_network.rs`)
- **LibP2PNetwork**: Implements HotStuff's Network trait
- Async/sync bridge using command channels
- QUIC + TCP transport with TLS encryption
- Automatic peer discovery and connection management

## Key Features

### Transport Layer
- **QUIC**: Primary transport for low-latency, multiplexed connections
- **TCP**: Fallback transport with Yamux multiplexing
- **TLS 1.3**: Automatic encryption via QUIC and Noise protocol
- **Connection pooling**: Automatic reconnection with exponential backoff

### Message Handling
- **Request/Response**: Directed messaging for consensus protocols
- **Reliable delivery**: Built-in retry logic and delivery confirmation
- **Backpressure**: Queue limits prevent memory exhaustion
- **Serialization**: Efficient bincode encoding for performance

### Security
- **Identity mapping**: Cryptographic VerifyingKey ↔ PeerId mapping
- **Signature verification**: HotStuff-level signature validation
- **Transport encryption**: TLS 1.3 via QUIC/Noise
- **Peer authentication**: Only known validators accepted

## Usage

### Basic Setup
```rust
use networking::{LibP2PNetwork, NetworkConfig, load_network_config};

// Load configuration
let config = load_network_config("config/network.toml")?;
let runtime_config = NetworkRuntimeConfig::from_network_config(config)?;

// Create libp2p keypair from validator keypair
let libp2p_keypair = create_libp2p_keypair_from_validator(&validator_keypair)?;

// Initialize network
let network = LibP2PNetwork::new(libp2p_keypair, runtime_config).await?;

// Use with HotStuff
let replica = ReplicaSpec::builder()
    .app(app)
    .network(network)
    .kv_store(kv_store)
    .configuration(config)
    .build()
    .start();
```

### Configuration Format
```toml
# config/network.toml
listen_addresses = ["/ip4/0.0.0.0/udp/9000/quic-v1"]
connection_timeout = 30
max_connections_per_peer = 1

[[validators]]
verifying_key = "abcd1234..."  # hex-encoded Ed25519 public key
peer_id = "12D3KooW..."        # libp2p peer ID
multiaddrs = ["/ip4/127.0.0.1/udp/9000/quic-v1"]
```

## Implementation Status

- ✅ **Configuration system**: TOML-based validator topology
- ✅ **Message codec**: Bincode serialization with framing
- ✅ **Transport layer**: QUIC + TCP with TLS encryption
- ✅ **Network behavior**: Connection management and retry logic
- ✅ **Integration interface**: HotStuff Network trait implementation
- ⚠️  **Compilation**: Some libp2p API compatibility issues to resolve
- ❌ **Testing**: Integration tests needed
- ❌ **Documentation**: API docs and examples needed

## Next Steps

1. **Fix compilation issues**: Resolve libp2p version compatibility
2. **Integration testing**: Multi-node consensus testing
3. **Performance tuning**: Optimize for consensus message patterns
4. **Production hardening**: Error handling, monitoring, logging
5. **Dynamic validator sets**: Support for validator set updates

## Design Decisions

### Why QUIC?
- **Low latency**: Reduced connection establishment time
- **Multiplexing**: Multiple streams per connection without head-of-line blocking
- **Built-in encryption**: TLS 1.3 integrated into transport
- **Mobile-friendly**: Connection migration support

### Why Request/Response?
- **Directed messaging**: HotStuff uses point-to-point communication
- **Delivery confirmation**: Important for consensus reliability
- **Backpressure**: Natural flow control mechanism
- **Simpler than gossip**: No need for pub/sub semantics

### Why Fixed Validator Sets?
- **Simplicity**: Avoids complex peer discovery protocols
- **Security**: Explicit allowlist of known validators
- **Performance**: No overhead from dynamic membership
- **Deterministic**: Consistent network topology across nodes

This implementation provides a solid foundation for production HotStuff deployment while maintaining the flexibility to add advanced features like dynamic validator sets and gossip protocols in the future.
