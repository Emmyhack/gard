/// Policy configuration loading and validation
use crate::error::Result;
use crate::types::Policy;
use std::path::PathBuf;

pub fn load_policy(path: Option<&str>) -> Result<Policy> {
    let policy_path = if let Some(p) = path {
        PathBuf::from(p)
    } else {
        get_default_policy_path()?
    };

    if policy_path.exists() {
        let content = std::fs::read_to_string(&policy_path)
            .map_err(|_| crate::error::GardError::ConfigurationError {
                path: policy_path.to_string_lossy().to_string(),
                reason: "Could not read policy file".to_string(),
            })?;

        toml::from_str(&content).map_err(|e| crate::error::GardError::TomlError(e))
    } else {
        Ok(Policy::default())
    }
}

pub fn get_default_policy_path() -> Result<PathBuf> {
    let gard_dir = dirs::home_dir()
        .ok_or_else(|| crate::error::GardError::Internal(
            "Could not determine home directory".to_string(),
        ))?
        .join(".gard");

    Ok(gard_dir.join("policy.toml"))
}

impl Default for Policy {
    fn default() -> Self {
        let mut checks = std::collections::HashMap::new();
        
        // Default: all checks enforced
        checks.insert("vscode-workspace-trust".to_string(), "enforce".to_string());
        checks.insert("vscode-extension-audit".to_string(), "enforce".to_string());
        checks.insert("clipboard-monitor-detection".to_string(), "enforce".to_string());
        checks.insert("env-key-leakage".to_string(), "enforce".to_string());
        checks.insert("ssh-key-hygiene".to_string(), "enforce".to_string());
        checks.insert("open-ports-remote-access".to_string(), "enforce".to_string());
        checks.insert("unsigned-binaries-in-path".to_string(), "enforce".to_string());
        checks.insert("solana-cli-config".to_string(), "enforce".to_string());
        checks.insert("solana-durable-nonce-verify".to_string(), "enforce".to_string());
        checks.insert("software-wallet-detection".to_string(), "warn".to_string());
        checks.insert("browser-crypto-extension".to_string(), "warn".to_string());
        checks.insert("hardware-wallet-verify".to_string(), "warn".to_string());

        Policy {
            checks,
            suppressions: Vec::new(),
            hardware_wallet: Default::default(),
            solana: Default::default(),
            nonce: Default::default(),
            metadata: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert!(!policy.checks.is_empty());
        assert!(policy.checks.contains_key("env-key-leakage"));
    }
}
