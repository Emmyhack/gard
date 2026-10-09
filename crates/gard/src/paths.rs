//! Filesystem locations for Gard state.
//!
//! Every location resolves in priority order: the CLI flag (which main
//! exports as an environment variable so library code stays flag-free),
//! then the environment variable, then the default under the home
//! directory. Nothing else in the crate hardcodes `~/.gard`.

use crate::error::{GardError, Result};
use std::path::PathBuf;

/// Overrides the data directory (`--data-dir`)
pub const DATA_DIR_ENV: &str = "GARD_DATA_DIR";

/// Overrides the policy file (`--config`)
pub const CONFIG_ENV: &str = "GARD_CONFIG";

/// Root directory for keys, cache, and logs
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::home_dir().map(|h| h.join(".gard")).ok_or_else(|| {
        GardError::Internal(format!(
            "Could not determine home directory; set {} explicitly",
            DATA_DIR_ENV
        ))
    })
}

/// Policy file location
pub fn policy_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(CONFIG_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    Ok(data_dir()?.join("policy.toml"))
}

pub fn keys_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("keys"))
}

pub fn private_key_path() -> Result<PathBuf> {
    Ok(keys_dir()?.join("ed25519"))
}

pub fn public_key_path() -> Result<PathBuf> {
    Ok(keys_dir()?.join("ed25519.pub"))
}

pub fn last_scan_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cache").join("last_scan.json"))
}

pub fn override_log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("override.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_layout_under_data_dir() {
        let root = data_dir().expect("data dir resolves");
        assert_eq!(policy_path().unwrap(), root.join("policy.toml"));
        assert_eq!(
            private_key_path().unwrap(),
            root.join("keys").join("ed25519")
        );
        assert_eq!(
            last_scan_path().unwrap(),
            root.join("cache").join("last_scan.json")
        );
        assert_eq!(override_log_path().unwrap(), root.join("override.log"));
    }
}
