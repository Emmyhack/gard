//! Check module registry
//!
//! Manages registration and execution of all security checks.

use super::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of all available checks
pub struct CheckRegistry {
    checks: HashMap<String, Arc<dyn CheckModule>>,
}

impl CheckRegistry {
    /// Create a new check registry with all built-in checks
    pub fn new() -> Self {
        let mut registry = CheckRegistry {
            checks: HashMap::new(),
        };

        registry.register(Arc::new(super::vscode_workspace::VscodeWorkspaceCheck));
        registry.register(Arc::new(super::vscode_extension::VscodeExtensionCheck));
        registry.register(Arc::new(super::clipboard_monitor::ClipboardMonitorCheck));
        registry.register(Arc::new(super::env_variables::EnvVariablesCheck));
        registry.register(Arc::new(super::ssh_hygiene::SshHygieneCheck));
        registry.register(Arc::new(super::open_ports::OpenPortsCheck));
        registry.register(Arc::new(super::software_wallets::SoftwareWalletsCheck));
        registry.register(Arc::new(super::unsigned_binaries::UnsignedBinariesCheck));
        registry.register(Arc::new(super::solana_config::SolanaConfigCheck));
        registry.register(Arc::new(super::solana_nonce::SolanaNonceCheck));
        registry.register(Arc::new(super::hardware_wallet::HardwareWalletCheck));
        registry.register(Arc::new(super::browser_extensions::BrowserExtensionsCheck));
        registry.register(Arc::new(super::testflight_apps::TestflightAppsCheck));

        registry
    }

    /// Register a check module
    pub fn register(&mut self, check: Arc<dyn CheckModule>) {
        self.checks.insert(check.id().to_string(), check);
    }

    /// Get a check by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn CheckModule>> {
        self.checks.get(id).cloned()
    }

    /// Get all registered checks
    pub fn all(&self) -> Vec<Arc<dyn CheckModule>> {
        self.checks.values().cloned().collect()
    }

    /// Get checks for a specific platform
    pub fn for_platform(&self, platform: Platform) -> Vec<Arc<dyn CheckModule>> {
        self.checks
            .values()
            .filter(|check| check.platforms().contains(&platform))
            .cloned()
            .collect()
    }

    /// Run all checks
    pub fn run_all(&self) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for check in self.all() {
            match check.run() {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    tracing::warn!(check_id = check.id(), error = ?e, "Check failed");
                },
            }
        }

        Ok(all_findings)
    }

    /// Run checks matching a filter
    pub fn run_matching<F>(&self, predicate: F) -> Result<Vec<Finding>>
    where
        F: Fn(&dyn CheckModule) -> bool,
    {
        let mut all_findings = Vec::new();

        for check in self.all() {
            if predicate(check.as_ref()) {
                match check.run() {
                    Ok(findings) => all_findings.extend(findings),
                    Err(e) => {
                        tracing::warn!(check_id = check.id(), error = ?e, "Check failed");
                    },
                }
            }
        }

        Ok(all_findings)
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_registry_registers_all_checks() {
        let registry = CheckRegistry::new();
        assert_eq!(registry.all().len(), 13);
        assert!(registry.get("env-key-leakage").is_some());
        assert!(registry.get("vscode-workspace-trust").is_some());
        assert!(registry.get("solana-durable-nonce-verify").is_some());
    }
}
