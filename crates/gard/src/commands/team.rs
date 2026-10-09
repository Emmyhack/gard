//! Team command - manage the trusted signer roster
//!
//! The roster lives in policy.toml under `[team]`, so distributing one
//! policy file to every member also distributes the trust anchors used
//! by 'gard verify' and 'gard fleet status'.

use crate::cli::TeamSubcommand;
use crate::config;
use crate::error::{GardError, Result};
use crate::types::TeamSigner;
use std::fs;

pub async fn execute(subcommand: TeamSubcommand) -> Result<i32> {
    match subcommand {
        TeamSubcommand::Add { name, key } => add(&name, &key),
        TeamSubcommand::List => list(),
        TeamSubcommand::Remove { name } => remove(&name),
    }
}

fn add(name: &str, key: &str) -> Result<i32> {
    let key = key.trim().strip_prefix("ed25519 ").unwrap_or(key.trim());

    let decoded = hex::decode(key).map_err(|_| {
        GardError::PolicyValidationError(
            "Key must be hex (64 characters), as printed by 'gard report --export-key'".to_string(),
        )
    })?;
    if decoded.len() != 32 {
        return Err(GardError::PolicyValidationError(format!(
            "Key must decode to 32 bytes, got {}",
            decoded.len()
        )));
    }

    let mut policy = config::load_policy(None)?;
    if policy.team.signers.iter().any(|s| s.name == name) {
        return Err(GardError::PolicyValidationError(format!(
            "Signer '{}' already registered; remove first to replace the key",
            name
        )));
    }
    if policy
        .team
        .signers
        .iter()
        .any(|s| s.public_key.eq_ignore_ascii_case(key))
    {
        return Err(GardError::PolicyValidationError(
            "This key is already registered under another name".to_string(),
        ));
    }

    policy.team.signers.push(TeamSigner {
        name: name.to_string(),
        public_key: key.to_lowercase(),
    });
    save_policy(&policy)?;
    println!("Registered signer '{}'", name);
    Ok(0)
}

fn list() -> Result<i32> {
    let policy = config::load_policy(None)?;
    if policy.team.signers.is_empty() {
        println!("No team signers registered. Add with 'gard team add <name> --key <hex>'.");
        return Ok(0);
    }
    println!("{:<20} PUBLIC KEY", "NAME");
    for signer in &policy.team.signers {
        println!("{:<20} {}", signer.name, signer.public_key);
    }
    Ok(0)
}

fn remove(name: &str) -> Result<i32> {
    let mut policy = config::load_policy(None)?;
    let before = policy.team.signers.len();
    policy.team.signers.retain(|s| s.name != name);
    if policy.team.signers.len() == before {
        println!("No signer named '{}'", name);
        return Ok(1);
    }
    save_policy(&policy)?;
    println!("Removed signer '{}'", name);
    Ok(0)
}

fn save_policy(policy: &crate::types::Policy) -> Result<()> {
    let path = config::get_default_policy_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rendered = toml::to_string_pretty(policy)
        .map_err(|e| GardError::PolicyValidationError(e.to_string()))?;
    fs::write(&path, rendered)?;
    Ok(())
}
