use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod types;
mod commands;

use commands::{keygen, show_key, stream};

/// PismoChain CLI tool for managing validator keys
#[derive(Parser)]
#[command(name = "pismo-cli")]
#[command(about = "CLI tool for PismoChain validator key management", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new validator keypair
    Keygen {
        /// Output path for the validator.keys file
        #[arg(short, long, default_value = "./validator.keys")]
        output: PathBuf,
    },
    /// Show verifying key and peer ID from a validator.keys file
    ShowKey {
        /// Input path to the validator.keys file
        #[arg(short, long, default_value = "./validator.keys")]
        input: PathBuf,
    },
    /// Stream events from a PismoChain listener node
    Stream {
        /// gRPC endpoint of the listener node
        #[arg(short, long, default_value = "http://127.0.0.1:50051")]
        endpoint: String,
        /// First version to stream (inclusive)
        #[arg(short, long, default_value = "0")]
        start_version: u64,
        /// Optional last version to stream (inclusive). If not provided, streams forever
        #[arg(long)]
        end_version: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            keygen::keygen_command(&output)?;
        }
        Commands::ShowKey { input } => {
            show_key::show_key_command(&input)?;
        }
        Commands::Stream { endpoint, start_version, end_version } => {
            stream::stream_events_command(&endpoint, start_version, end_version).await?;
        }
    }

    Ok(())
}
