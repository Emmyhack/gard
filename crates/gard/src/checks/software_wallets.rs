//! Software wallet detection
//!
//! Detects desktop wallet applications and wallet data directories on the
//! machine. Software wallets hold key material in files a compromised
//! process can read, so they should not coexist with signing operations.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::path::PathBuf;

pub struct SoftwareWalletsCheck;

impl CheckModule for SoftwareWalletsCheck {
    fn id(&self) -> &str {
        "software-wallet-detection"
    }

    fn name(&self) -> &str {
        "Software Wallet Detection"
    }

    fn description(&self) -> &str {
        "Detects installed desktop wallet applications and wallet data directories \
        that store key material on disk where malware can reach it."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn blocking_in_preflight(&self) -> bool {
        false
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn remediation(&self) -> &str {
        "Move funds to a hardware wallet and remove software wallets from signing \
        machines. If a software wallet is operationally required, isolate it on a \
        dedicated non-signing machine and record a policy suppression."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (name, path) in self.wallet_locations() {
            if path.exists() {
                findings.push(build_finding(
                    self,
                    format!("Software wallet detected: {} at {}", name, path.display()),
                    json!({
                        "wallet": name,
                        "path": path.to_string_lossy()
                    }),
                ));
            }
        }

        Ok(findings)
    }
}

impl SoftwareWalletsCheck {
    fn wallet_locations(&self) -> Vec<(&'static str, PathBuf)> {
        let mut locations = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return locations;
        };

        #[cfg(target_os = "macos")]
        {
            let apps = PathBuf::from("/Applications");
            let app_support = home.join("Library/Application Support");
            locations.extend([
                ("Exodus", apps.join("Exodus.app")),
                ("Electrum", apps.join("Electrum.app")),
                ("Atomic Wallet", apps.join("Atomic Wallet.app")),
                ("Trust Wallet", apps.join("Trust Wallet.app")),
                ("Exodus data", app_support.join("Exodus")),
                ("Electrum data", home.join(".electrum")),
            ]);
        }

        #[cfg(target_os = "linux")]
        {
            locations.extend([
                ("Exodus data", home.join(".config/Exodus")),
                ("Electrum data", home.join(".electrum")),
                ("Atomic Wallet data", home.join(".config/atomic")),
            ]);
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(config) = dirs::config_dir() {
                locations.extend([
                    ("Exodus data", config.join("Exodus")),
                    ("Electrum data", config.join("Electrum")),
                    ("Atomic Wallet data", config.join("atomic")),
                ]);
            }
        }

        locations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = SoftwareWalletsCheck;
        assert_eq!(check.id(), "software-wallet-detection");
        assert!(!check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::Medium);
    }

    #[test]
    fn test_run_does_not_error() {
        let check = SoftwareWalletsCheck;
        assert!(check.run().is_ok());
    }
}
