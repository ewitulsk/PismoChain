use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// Import from the app crate
use pismo_chain::validator_keys::{generate_validator_keypair, load_validator_keys, save_validator_keys};
use pismo_chain::networking::create_libp2p_keypair_from_validator;

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
}

/// JSON structure for reading validator keypairs metadata
#[derive(Deserialize)]
struct ValidatorKeysJson {
    version: u32,
    algorithm: String,
    #[allow(dead_code)]
    private_key: String,
    #[allow(dead_code)]
    public_key: String,
}

#[derive(Serialize)]
struct KeyInfo {
    version: u32,
    algorithm: String,
    verifying_key: String,
    peer_id: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            keygen_command(&output)?;
        }
        Commands::ShowKey { input } => {
            show_key_command(&input)?;
        }
    }

    Ok(())
}

fn keygen_command(output_path: &PathBuf) -> Result<()> {
    // Generate new validator keypair
    let keypair = generate_validator_keypair();
    
    // Save to file
    save_validator_keys(output_path, &keypair)
        .context("Failed to save validator keys")?;
    
    eprintln!("Successfully generated validator keypair at: {}", output_path.display());
    
    Ok(())
}

fn show_key_command(input_path: &PathBuf) -> Result<()> {
    // Read and parse the JSON file to extract metadata
    let json_content = fs::read_to_string(input_path)
        .context("Failed to read validator keys file")?;
    
    let keys_json: ValidatorKeysJson = serde_json::from_str(&json_content)
        .context("Failed to parse validator keys JSON")?;
    
    // Load validator keypair from file (validates and constructs the keypair)
    let signing_key = load_validator_keys(input_path)
        .context("Failed to load validator keys")?;
    
    // Extract verifying key (public key) as hex
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();
    let verifying_key_hex = hex::encode(verifying_key_bytes);
    
    // Convert to libp2p keypair to get PeerId
    let libp2p_keypair = create_libp2p_keypair_from_validator(&signing_key)
        .context("Failed to create libp2p keypair")?;
    
    let peer_id = libp2p_keypair.public().to_peer_id().to_string();
    
    // Create output structure with metadata
    let key_info = KeyInfo {
        version: keys_json.version,
        algorithm: keys_json.algorithm,
        verifying_key: verifying_key_hex,
        peer_id,
    };
    
    // Output as JSON
    let json_output = serde_json::to_string_pretty(&key_info)
        .context("Failed to serialize key info")?;
    
    println!("{}", json_output);
    
    Ok(())
}

