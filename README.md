# PismoChain

A blockchain implementation using the HotStuff consensus algorithm.

## Project Structure

This is a Rust workspace (mono repo) containing:

- **`app/`** - Main PismoChain application
- **`hotstuff_rs/`** - HotStuff consensus algorithm library

## Getting Started

### Prerequisites

- Rust 1.70+ 
- Cargo

### Building

Build the entire workspace:

```bash
cargo build
```

Build specific packages:

```bash
# Build the main application
cargo build -p PismoChain

# Build the library
cargo build -p hotstuff_rs
```

### Running

Run the main application:

```bash
cargo run --bin pismochain
```

### Testing

Run all tests:

```bash
cargo test
```

Run tests for a specific package:

```bash
cargo test -p hotstuff_rs
```

## Development

The main application (`app/`) depends on the `hotstuff_rs` library as a local path dependency. This allows for rapid development and testing of both components together.

## License

Apache-2.0 