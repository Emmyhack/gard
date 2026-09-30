//! Hardware wallet presence verification
//!
//! When policy requires a hardware wallet, verifies a Ledger or Trezor
//! device is connected via USB before signing ceremonies proceed.

use crate::checks::{build_finding, CheckModule};
use crate::config;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;

pub struct HardwareWalletCheck;

impl CheckModule for HardwareWalletCheck {
    fn id(&self) -> &str {
        "hardware-wallet-verify"
    }

    fn name(&self) -> &str {
        "Hardware Wallet Presence Verification"
    }

    fn description(&self) -> &str {
        "Verifies that a hardware wallet (Ledger, Trezor) is connected when policy \
        requires one for signing operations."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn blocking_in_preflight(&self) -> bool {
        false
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux]
    }

    fn remediation(&self) -> &str {
        "Connect and unlock the hardware wallet before running preflight. If your \
        team does not require hardware wallets, set [hardware_wallet] required = \
        false in policy (not recommended for mainnet authorities)."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let policy = config::load_policy(None).unwrap_or_default();
        if !policy.hardware_wallet.required {
            return Ok(findings);
        }

        let detected = detect_usb_wallets();
        if detected.is_empty() {
            let mut finding = build_finding(
                self,
                "Policy requires a hardware wallet but no Ledger or Trezor device is \
                connected."
                    .to_string(),
                json!({
                    "required": true,
                    "detected_devices": [],
                    "minimum_type": policy.hardware_wallet.minimum_type
                }),
            );
            // Policy-required hardware wallet absence blocks signing
            finding.blocking = true;
            finding.severity = Severity::High;
            findings.push(finding);
        }

        Ok(findings)
    }
}

/// Detect connected hardware wallets by USB vendor listing
#[cfg(target_os = "macos")]
fn detect_usb_wallets() -> Vec<String> {
    let output = std::process::Command::new("/usr/sbin/system_profiler")
        .args(["SPUSBDataType", "-json"])
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();

    let mut detected = Vec::new();
    for vendor in ["ledger", "trezor", "keystone", "grid+"] {
        if text.contains(vendor) {
            detected.push(vendor.to_string());
        }
    }
    detected
}

#[cfg(target_os = "linux")]
fn detect_usb_wallets() -> Vec<String> {
    // Ledger vendor id 2c97, Trezor 534c/1209
    let output = std::process::Command::new("lsusb").output();
    let Ok(output) = output else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout).to_lowercase();

    let mut detected = Vec::new();
    if text.contains("2c97") || text.contains("ledger") {
        detected.push("ledger".to_string());
    }
    if text.contains("534c") || text.contains("1209") || text.contains("trezor") {
        detected.push("trezor".to_string());
    }
    detected
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_usb_wallets() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = HardwareWalletCheck;
        assert_eq!(check.id(), "hardware-wallet-verify");
        assert!(!check.blocking_in_preflight());
    }

    #[test]
    fn test_run_does_not_error() {
        let check = HardwareWalletCheck;
        assert!(check.run().is_ok());
    }
}
