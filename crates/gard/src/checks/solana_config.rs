//! Solana CLI configuration audit
//!
//! Parses the Solana CLI config (~/.config/solana/cli/config.yml) and
//! audits the keypair path permissions, keypair location, and RPC
//! endpoint against the trusted list in policy.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct SolanaConfigCheck;

impl CheckModule for SolanaConfigCheck {
    fn id(&self) -> &str {
        "solana-cli-config"
    }

    fn name(&self) -> &str {
        "Solana CLI Configuration Audit"
    }

    fn description(&self) -> &str {
        "Audits the Solana CLI configuration for unsafe keypair storage (permissive \
        file modes, plaintext keypairs on signing machines) and non-standard RPC \
        endpoints."
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
        "Set keypair files to mode 0600, prefer hardware wallet keypair URLs \
        (usb://ledger) over file keypairs for mainnet operations, and point the CLI \
        at a trusted RPC endpoint (solana config set --url)."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return Ok(findings);
        };

        let config_path = home.join(".config/solana/cli/config.yml");
        if !config_path.exists() {
            return Ok(findings);
        }

        let Ok(content) = fs::read_to_string(&config_path) else {
            return Ok(findings);
        };

        let keypair_path = yaml_value(&content, "keypair_path");
        let rpc_url = yaml_value(&content, "json_rpc_url");

        if let Some(ref kp) = keypair_path {
            findings.extend(self.audit_keypair(kp, &config_path));
        }

        if let Some(ref url) = rpc_url {
            let policy = crate::config::load_policy(None).unwrap_or_default();
            findings.extend(self.audit_rpc_url(
                url,
                &config_path,
                &policy.solana.trusted_rpc_endpoints,
            ));
        }

        Ok(findings)
    }
}

impl SolanaConfigCheck {
    fn audit_keypair(&self, keypair_path: &str, config_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Hardware wallet URLs are the safe configuration
        if keypair_path.starts_with("usb://") {
            return findings;
        }

        let path = PathBuf::from(keypair_path);
        if !path.exists() {
            return findings;
        }

        let mut finding = build_finding(
            self,
            format!(
                "Solana CLI uses a file-based keypair: {}. File keypairs on a signing \
                machine can be exfiltrated by any process running as this user.",
                keypair_path
            ),
            json!({
                "config_file": config_path.to_string_lossy(),
                "keypair_path": keypair_path,
                "issue": "file_keypair"
            }),
        );
        finding.severity = Severity::Medium;
        finding.blocking = false;
        findings.push(finding);

        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(&path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                findings.push(build_finding(
                    self,
                    format!(
                        "Solana keypair file {} has permissive mode {:o}; expected 0600.",
                        keypair_path, mode
                    ),
                    json!({
                        "keypair_path": keypair_path,
                        "mode": format!("{:o}", mode),
                        "issue": "permissive_mode"
                    }),
                ));
            }
        }

        findings
    }

    fn audit_rpc_url(&self, url: &str, config_path: &Path, trusted: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let known_endpoints = [
            "https://api.mainnet-beta.solana.com",
            "https://api.devnet.solana.com",
            "https://api.testnet.solana.com",
            "http://localhost:8899",
            "http://127.0.0.1:8899",
        ];

        if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
            findings.push(build_finding(
                self,
                format!(
                    "Solana CLI RPC endpoint uses unencrypted HTTP: {}. Transactions \
                    and queries can be observed or tampered with in transit.",
                    url
                ),
                json!({
                    "config_file": config_path.to_string_lossy(),
                    "rpc_url": url,
                    "issue": "plaintext_rpc"
                }),
            ));
        } else if !known_endpoints.contains(&url)
            && !trusted
                .iter()
                .any(|t| t.trim_end_matches('/') == url.trim_end_matches('/'))
        {
            let mut finding = build_finding(
                self,
                format!(
                    "Solana CLI points at a non-standard RPC endpoint: {}. Verify this \
                    endpoint is operated by your team or a trusted provider.",
                    url
                ),
                json!({
                    "config_file": config_path.to_string_lossy(),
                    "rpc_url": url,
                    "issue": "unrecognized_rpc"
                }),
            );
            finding.severity = Severity::Low;
            finding.blocking = false;
            findings.push(finding);
        }

        findings
    }
}

/// Minimal YAML scalar extraction for `key: value` lines
fn yaml_value(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            if let Some(value) = rest.trim_start().strip_prefix(':') {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = SolanaConfigCheck;
        assert_eq!(check.id(), "solana-cli-config");
        assert!(check.blocking_in_preflight());
    }

    #[test]
    fn test_yaml_value_extraction() {
        let content = "json_rpc_url: https://api.mainnet-beta.solana.com\nkeypair_path: /home/u/.config/solana/id.json\n";
        assert_eq!(
            yaml_value(content, "json_rpc_url").as_deref(),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(
            yaml_value(content, "keypair_path").as_deref(),
            Some("/home/u/.config/solana/id.json")
        );
        assert_eq!(yaml_value(content, "missing"), None);
    }

    #[test]
    fn test_plaintext_rpc_blocks() {
        let check = SolanaConfigCheck;
        let findings = check.audit_rpc_url(
            "http://rpc.example.com",
            &PathBuf::from("/tmp/config.yml"),
            &[],
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].blocking);
    }

    #[test]
    fn test_known_https_rpc_passes() {
        let check = SolanaConfigCheck;
        let findings = check.audit_rpc_url(
            "https://api.mainnet-beta.solana.com",
            &PathBuf::from("/tmp/config.yml"),
            &[],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_policy_trusted_rpc_passes() {
        let check = SolanaConfigCheck;
        let trusted = vec!["https://rpc.myteam.dev/".to_string()];
        let findings = check.audit_rpc_url(
            "https://rpc.myteam.dev",
            &PathBuf::from("/tmp/config.yml"),
            &trusted,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hardware_wallet_keypair_passes() {
        let check = SolanaConfigCheck;
        let findings = check.audit_keypair("usb://ledger", &PathBuf::from("/tmp/config.yml"));
        assert!(findings.is_empty());
    }
}
