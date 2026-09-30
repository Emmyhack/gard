//! Check modules for Gard security checks
//!
//! Each module implements the CheckModule trait and performs a specific
//! security check on the local machine.

pub mod browser_extensions;
pub mod clipboard_monitor;
pub mod env_variables;
pub mod hardware_wallet;
pub mod open_ports;
pub mod registry;
pub mod software_wallets;
pub mod solana_config;
pub mod solana_nonce;
pub mod ssh_hygiene;
pub mod unsigned_binaries;
pub mod vscode_extension;
pub mod vscode_workspace;

use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use std::fmt;

/// Trait that all check modules must implement
pub trait CheckModule: Send + Sync {
    /// Check module identifier
    fn id(&self) -> &str;

    /// Human-readable check name
    fn name(&self) -> &str;

    /// Detailed description of what this check detects
    fn description(&self) -> &str;

    /// Severity level of findings from this check
    fn severity(&self) -> Severity;

    /// Whether this finding blocks preflight
    fn blocking_in_preflight(&self) -> bool;

    /// Platforms this check supports
    fn platforms(&self) -> &[Platform];

    /// Remediation recommendation
    fn remediation(&self) -> &str;

    /// Execute the check and return findings
    fn run(&self) -> Result<Vec<Finding>>;
}

static FINDING_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

/// Generate a unique finding identifier for this scan run
pub fn next_finding_id() -> String {
    let n = FINDING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("f_{:06}", n)
}

/// Build a Finding from a check module with the standard fields populated
pub fn build_finding(
    check: &dyn CheckModule,
    description: String,
    details: serde_json::Value,
) -> Finding {
    Finding {
        id: next_finding_id(),
        check_id: check.id().to_string(),
        check_name: check.name().to_string(),
        severity: check.severity(),
        platform: crate::types::current_platform(),
        description,
        remediation: check.remediation().to_string(),
        blocking: check.blocking_in_preflight(),
        timestamp: chrono::Utc::now(),
        details,
    }
}

impl fmt::Debug for dyn CheckModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckModule")
            .field("id", &self.id())
            .field("name", &self.name())
            .finish()
    }
}

pub use registry::CheckRegistry;

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_finding_ids_are_unique() {
        let a = next_finding_id();
        let b = next_finding_id();
        assert_ne!(a, b);
    }
}
