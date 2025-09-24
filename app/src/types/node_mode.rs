//! Node mode configuration for PismoChain
//! 
//! Defines whether a node operates as a validator (participating in consensus)
//! or as a fullnode (following the chain without consensus participation).

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Node operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeMode {
    /// Validator node - participates in consensus
    Validator,
    /// Fullnode - follows the chain without consensus participation
    Fullnode,
}

impl Default for NodeMode {
    fn default() -> Self {
        NodeMode::Validator
    }
}

impl FromStr for NodeMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "validator" => Ok(NodeMode::Validator),
            "fullnode" => Ok(NodeMode::Fullnode),
            _ => Err(format!("Invalid node mode: {}. Use 'validator' or 'fullnode'", s)),
        }
    }
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeMode::Validator => write!(f, "validator"),
            NodeMode::Fullnode => write!(f, "fullnode"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_mode_from_str() {
        assert_eq!("validator".parse::<NodeMode>().unwrap(), NodeMode::Validator);
        assert_eq!("fullnode".parse::<NodeMode>().unwrap(), NodeMode::Fullnode);
        assert_eq!("VALIDATOR".parse::<NodeMode>().unwrap(), NodeMode::Validator);
        assert_eq!("FULLNODE".parse::<NodeMode>().unwrap(), NodeMode::Fullnode);
        
        assert!("invalid".parse::<NodeMode>().is_err());
    }

    #[test]
    fn test_node_mode_display() {
        assert_eq!(NodeMode::Validator.to_string(), "validator");
        assert_eq!(NodeMode::Fullnode.to_string(), "fullnode");
    }
}
