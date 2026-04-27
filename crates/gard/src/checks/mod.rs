/// Check modules for Gard security checks
///
/// Each module implements the CheckModule trait and performs a specific
/// security check on the local machine.

pub mod registry;
pub mod vscode_workspace;
pub mod vscode_extension;
pub mod clipboard_monitor;
pub mod env_variables;
pub mod ssh_hygiene;
pub mod open_ports;
pub mod software_wallets;
pub mod unsigned_binaries;
pub mod solana_config;
pub mod solana_nonce;
pub mod hardware_wallet;
pub mod browser_extensions;

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
    fn test_check_trait_exists() {
        // Verify that the CheckModule trait is properly defined
        fn assert_check_module<T: CheckModule>(_: &T) {}
        
        // This is verified at compile time
    }
}
