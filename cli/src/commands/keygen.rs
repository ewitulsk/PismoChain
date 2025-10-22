use anyhow::{Context, Result};
use std::path::PathBuf;
use pismo_chain::validator_keys::{generate_validator_keypair, save_validator_keys};

pub fn keygen_command(output_path: &PathBuf) -> Result<()> {
    // Generate new validator keypair
    let keypair = generate_validator_keypair();
    
    // Save to file
    save_validator_keys(output_path, &keypair)
        .context("Failed to save validator keys")?;
    
    eprintln!("Successfully generated validator keypair at: {}", output_path.display());
    
    Ok(())
}

