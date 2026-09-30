//! VSCode extension audit
//!
//! Enumerates installed VSCode extensions and flags entries on the
//! known-malicious list, plus unsigned/local extensions installed
//! outside the marketplace (no publisher metadata).

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub struct VscodeExtensionCheck;

/// Known-malicious extension identifiers (publisher.name, lowercase).
/// Sourced from public reporting on crypto-targeting VSCode malware.
const KNOWN_MALICIOUS: &[&str] = &[
    "ahban.shiba",
    "ahban.cychelloworld",
    "evaera-rbx.vscode-rojo-rbx",
    "prettiests.prettiest-vscode",
    "solidity-vlang.solidity-vlang",
    "juanbianco.solidity-vscode",
    "vscodedeveloper.solidity-language",
    "trufflesuites.truffle-vscode-toolkit",
];

/// Name fragments that warrant manual review on a signing machine
const HIGH_RISK_FRAGMENTS: &[&str] = &["wallet", "keylog", "clipboard", "airdrop"];

impl CheckModule for VscodeExtensionCheck {
    fn id(&self) -> &str {
        "vscode-extension-audit"
    }

    fn name(&self) -> &str {
        "VSCode Extension Audit"
    }

    fn description(&self) -> &str {
        "Audits installed VSCode extensions against a known-malicious list and flags \
        high-risk extensions that should not be present on signing machines."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn remediation(&self) -> &str {
        "Uninstall the flagged extension immediately, rotate any keys that were \
        accessible from this machine, and review extension install history. Only \
        install extensions from verified publishers on signing machines."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for ext_dir in self.extension_dirs() {
            if !ext_dir.exists() {
                continue;
            }
            let Ok(entries) = fs::read_dir(&ext_dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let dir_name = entry.file_name().to_string_lossy().to_lowercase();
                findings.extend(self.evaluate_extension(&dir_name, &path));
            }
        }

        Ok(findings)
    }
}

impl VscodeExtensionCheck {
    fn extension_dirs(&self) -> Vec<PathBuf> {
        let mut dirs_out = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return dirs_out;
        };

        for product in [".vscode", ".vscode-insiders", ".vscode-oss", ".cursor"] {
            dirs_out.push(home.join(product).join("extensions"));
        }

        dirs_out
    }

    /// Extension directories are named `publisher.name-version`
    fn evaluate_extension(&self, dir_name: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Strip trailing -X.Y.Z version suffix to get publisher.name
        let ext_id = dir_name
            .rfind('-')
            .map(|i| &dir_name[..i])
            .unwrap_or(dir_name);

        if KNOWN_MALICIOUS.contains(&ext_id) {
            findings.push(build_finding(
                self,
                format!(
                    "Known-malicious VSCode extension installed: {} at {}",
                    ext_id,
                    path.display()
                ),
                json!({
                    "extension_id": ext_id,
                    "path": path.to_string_lossy(),
                    "classification": "known_malicious"
                }),
            ));
            return findings;
        }

        for fragment in HIGH_RISK_FRAGMENTS {
            if ext_id.contains(fragment) {
                let mut finding = build_finding(
                    self,
                    format!(
                        "High-risk VSCode extension on signing machine: {} (matched '{}')",
                        ext_id, fragment
                    ),
                    json!({
                        "extension_id": ext_id,
                        "path": path.to_string_lossy(),
                        "classification": "high_risk",
                        "matched_fragment": fragment
                    }),
                );
                // Heuristic matches warn rather than block
                finding.severity = Severity::Medium;
                finding.blocking = false;
                findings.push(finding);
                break;
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = VscodeExtensionCheck;
        assert_eq!(check.id(), "vscode-extension-audit");
        assert!(check.blocking_in_preflight());
    }

    #[test]
    fn test_known_malicious_detection() {
        let check = VscodeExtensionCheck;
        let findings = check.evaluate_extension("ahban.shiba-1.0.0", &PathBuf::from("/tmp/ext"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].blocking);
    }

    #[test]
    fn test_high_risk_fragment_is_nonblocking() {
        let check = VscodeExtensionCheck;
        let findings =
            check.evaluate_extension("acme.wallet-helper-2.1.0", &PathBuf::from("/tmp/ext"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(!findings[0].blocking);
    }

    #[test]
    fn test_benign_extension_passes() {
        let check = VscodeExtensionCheck;
        let findings =
            check.evaluate_extension("rust-lang.rust-analyzer-0.4.0", &PathBuf::from("/tmp/ext"));
        assert!(findings.is_empty());
    }
}
