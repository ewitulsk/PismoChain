# PismoChain CLI

A command-line interface tool for managing PismoChain validator keys and streaming blockchain events.

## Overview

`pismo-cli` provides essential utilities for PismoChain validators and developers:
- Generate and manage validator keypairs
- Extract public key information and peer IDs
- Stream and monitor blockchain events in real-time

## Installation

Build the CLI tool from source using Cargo:

```bash
cd cli
cargo build --release
```

The binary will be available at `../target/release/pismo-cli`.

Optionally, install it to your local Cargo bin directory:

```bash
cargo install --path .
```

## Commands

### `keygen` - Generate Validator Keypair

Generate a new Ed25519 validator keypair for running a PismoChain validator node.

#### Usage

```bash
pismo-cli keygen [OPTIONS]
```

#### Options

- `-o, --output <PATH>` - Output path for the validator.keys file (default: `./validator.keys`)

#### Examples

Generate a keypair with the default filename:
```bash
pismo-cli keygen
```

Generate a keypair with a custom filename:
```bash
pismo-cli keygen --output ./my-validator.keys
```

#### Output

The command creates a JSON file containing the keypair:

```json
{
  "version": 1,
  "algorithm": "Ed25519",
  "private_key": "hex_encoded_private_key",
  "public_key": "hex_encoded_public_key"
}
```

The command also prints a confirmation message to stderr:
```
Successfully generated validator keypair at: ./validator.keys
```

---

### `show-key` - Display Public Key Information

Extract and display the public key (verifying key) and libp2p peer ID from a validator keypair file.

#### Usage

```bash
pismo-cli show-key [OPTIONS]
```

#### Options

- `-i, --input <PATH>` - Input path to the validator.keys file (default: `./validator.keys`)

#### Examples

Show key information from the default file:
```bash
pismo-cli show-key
```

Show key information from a specific file:
```bash
pismo-cli show-key --input ./my-validator.keys
```

#### Output

The command outputs JSON to stdout:

```json
{
  "version": 1,
  "algorithm": "Ed25519",
  "verifying_key": "a1b2c3d4e5f6...",
  "peer_id": "12D3KooW..."
}
```

**Fields:**
- `version` - Key format version number
- `algorithm` - Cryptographic algorithm used (Ed25519)
- `verifying_key` - Public key in hexadecimal format
- `peer_id` - libp2p peer ID derived from the public key

**Use Cases:**
- Configure validator sets in network configuration
- Share your peer ID with other network participants
- Verify which validator key a file contains

---

### `stream` - Stream Blockchain Events

Connect to a PismoChain listener node and stream blockchain events in real-time.

#### Usage

```bash
pismo-cli stream [OPTIONS]
```

#### Options

- `-e, --endpoint <URL>` - gRPC endpoint of the listener node (default: `http://127.0.0.1:50051`)
- `-s, --start-version <VERSION>` - First version to stream from, inclusive (default: `0`)
- `--end-version <VERSION>` - Optional last version to stream, inclusive. If not provided, streams forever

#### Examples

Stream all events from the beginning:
```bash
pismo-cli stream
```

Stream events from version 100 onwards:
```bash
pismo-cli stream --start-version 100
```

Stream a specific range of versions:
```bash
pismo-cli stream --start-version 100 --end-version 200
```

Connect to a remote listener:
```bash
pismo-cli stream --endpoint http://192.168.1.100:50051
```

#### Output Format

The command displays connection information on stderr:
```
Connecting to listener: http://127.0.0.1:50051
Starting from version: 0

Successfully connected! Streaming events...
Press Ctrl+C to stop
```

Each event is formatted with a box-drawing border:

**Transfer Event Example:**
```
┌─ Event 42.0 (version: 42)
│  Type: Transfer
│  Data size: 96 bytes
│
│  From: a1b2c3d4e5f6...
│  To:   f6e5d4c3b2a1...
│  Coin: 0000000000000000000000000000000000000000000000000000000000000001
│  Amount: 1000000
└─
```

**Mint Event Example (from address is all zeros):**
```
┌─ Event 5.0 (version: 5)
│  Type: Transfer
│  Data size: 96 bytes
│
│  [MINT]
│  To:   a1b2c3d4e5f6...
│  Coin: 0000000000000000000000000000000000000000000000000000000000000001
│  Amount: 1000000000
└─
```

**Unknown Event Type:**
```
┌─ Event 10.1 (version: 10)
│  Type: CustomEvent
│  Data size: 64 bytes
│  Data preview: a1 b2 c3 d4 e5 f6 07 08 09 0a 0b 0c 0d 0e 0f 10...
└─
```

**Progress Indicators:**

Every 100 events, a progress message is printed to stderr:
```
--- Received 100 events so far ---
--- Received 200 events so far ---
```

When the stream completes (either by reaching `end-version` or connection loss):
```
Stream completed. Total events received: 250
```

#### Use Cases

- Monitor blockchain activity in real-time
- Debug transaction processing and event emission
- Build external indexers and analytics tools
- Audit historical blockchain events

---

## Getting Help

Display help for the CLI tool:
```bash
pismo-cli --help
```

Display help for a specific command:
```bash
pismo-cli keygen --help
pismo-cli show-key --help
pismo-cli stream --help
```

## Examples

### Complete Validator Setup Workflow

1. Generate a new validator keypair:
```bash
pismo-cli keygen --output validator1.keys
```

2. Extract the public information to share with the network:
```bash
pismo-cli show-key --input validator1.keys > validator1-public.json
```

3. Review the public information:
```bash
cat validator1-public.json
```

### Event Monitoring Workflow

1. Start a PismoChain listener node (see main PismoChain documentation)

2. Stream events from the beginning:
```bash
pismo-cli stream
```

3. Or stream recent events only:
```bash
pismo-cli stream --start-version 1000
```

4. Save events to a file for analysis:
```bash
pismo-cli stream --start-version 0 --end-version 1000 > events.log 2>/dev/null
```

## Technical Details

- **Cryptography**: Uses Ed25519 signature scheme for validator keys
- **Networking**: Uses libp2p for peer-to-peer communication (peer IDs derived from Ed25519 keys)
- **Event Streaming**: Connects via gRPC to listener nodes
- **Serialization**: Events are serialized using Borsh format
- **Error Handling**: All commands use proper error handling with descriptive messages

## License

See the main PismoChain repository for license information.

