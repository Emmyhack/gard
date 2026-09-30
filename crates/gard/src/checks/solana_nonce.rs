//! Durable nonce configuration validation
//!
//! Durable nonce accounts allow transactions to be signed long before
//! submission — the mechanism abused in the Drift Protocol attack.
//! This check validates that a nonce authority expectation is configured
//! in policy whenever nonce accounts are in use, and flags nonce keypair
//! files stored alongside regular keypairs.

use crate::checks::{build_finding, CheckModule};
use crate::config;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;

pub struct SolanaNonceCheck;

impl CheckModule for SolanaNonceCheck {
    fn id(&self) -> &str {
        "solana-durable-nonce-verify"
    }

    fn name(&self) -> &str {
        "Solana Durable Nonce Configuration Validation"
    }

    fn description(&self) -> &str {
        "Validates durable nonce hygiene: policy must declare the expected nonce \
        authority, and nonce account keypairs must not be stored in the default \
        Solana keypair directory where any local process can read them."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn remediation(&self) -> &str {
        "Set [nonce] expected_authority in ~/.gard/policy.toml to your multisig \
        authority address, move nonce account keypairs off signing machines, and \
        verify on-chain nonce authority with 'solana nonce-account <ADDRESS>' before \
        every signing ceremony."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let policy = config::load_policy(None).unwrap_or_default();
        let nonce_keypairs = self.find_local_nonce_keypairs();

        // Nonce accounts in use without a declared authority expectation
        if !nonce_keypairs.is_empty() && policy.nonce.expected_authority.is_none() {
            findings.push(build_finding(
                self,
                "Nonce account keypair(s) present on this machine but policy does not \
                declare an expected nonce authority. Authority mismatches cannot be \
                detected without this baseline."
                    .to_string(),
                json!({
                    "nonce_keypairs": nonce_keypairs,
                    "issue": "no_expected_authority"
                }),
            ));
        }

        for keypair in &nonce_keypairs {
            let mut finding = build_finding(
                self,
                format!(
                    "Durable nonce keypair stored locally: {}. A stolen nonce keypair \
                    lets an attacker redirect the nonce authority and replay withheld \
                    transactions.",
                    keypair
                ),
                json!({
                    "keypair_path": keypair,
                    "issue": "local_nonce_keypair"
                }),
            );
            finding.severity = Severity::Medium;
            finding.blocking = false;
            findings.push(finding);
        }

        Ok(findings)
    }
}

impl SolanaNonceCheck {
    /// Look for keypair files whose names suggest nonce accounts
    fn find_local_nonce_keypairs(&self) -> Vec<String> {
        let mut found = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return found;
        };

        let solana_dir = home.join(".config/solana");
        if !solana_dir.exists() {
            return found;
        }

        let Ok(entries) = fs::read_dir(&solana_dir) else {
            return found;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if path.is_file()
                && name.contains("nonce")
                && path.extension().map(|e| e == "json").unwrap_or(false)
            {
                found.push(path.to_string_lossy().to_string());
            }
        }

        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = SolanaNonceCheck;
        assert_eq!(check.id(), "solana-durable-nonce-verify");
        assert!(check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::High);
    }

    #[test]
    fn test_run_does_not_error() {
        let check = SolanaNonceCheck;
        assert!(check.run().is_ok());
    }
}
