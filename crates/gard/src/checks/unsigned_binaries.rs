//! Unsigned and recently-installed binary detection
//!
//! Audits user-writable PATH directories for binaries installed in the
//! last 7 days (supply-chain risk window) and, on macOS, verifies code
//! signatures on those recent binaries.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct UnsignedBinariesCheck;

/// Only audit user-writable prefixes; system dirs are package-manager managed
const AUDITED_PREFIXES: &[&str] = &["/usr/local/bin", "/opt/homebrew/bin"];

const RECENT_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

impl CheckModule for UnsignedBinariesCheck {
    fn id(&self) -> &str {
        "unsigned-binaries-in-path"
    }

    fn name(&self) -> &str {
        "Unsigned and Recently-Installed Binary Detection"
    }

    fn description(&self) -> &str {
        "Flags binaries installed into user-writable PATH directories within the \
        last 7 days, and on macOS verifies their code signatures. Recently dropped \
        unsigned binaries in PATH are a common persistence and hijack technique."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux]
    }

    fn remediation(&self) -> &str {
        "Verify each flagged binary was installed intentionally (check package \
        manager receipts or install history). Remove anything unrecognized and \
        re-scan. On macOS, prefer signed and notarized tooling on signing machines."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = SystemTime::now();

        let mut dirs_to_scan: Vec<PathBuf> =
            AUDITED_PREFIXES.iter().map(|p| PathBuf::from(*p)).collect();
        if let Some(home) = dirs::home_dir() {
            dirs_to_scan.push(home.join("bin"));
            dirs_to_scan.push(home.join(".local/bin"));
            dirs_to_scan.push(home.join(".cargo/bin"));
        }

        for dir in dirs_to_scan {
            if !dir.exists() {
                continue;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                let Ok(modified) = metadata.modified() else {
                    continue;
                };
                let age = now.duration_since(modified).unwrap_or_default();
                if age > RECENT_WINDOW {
                    continue;
                }

                let signature_status = signature_status(&path);
                let is_unsigned = signature_status.as_deref() == Some("unsigned");

                let mut finding = build_finding(
                    self,
                    format!(
                        "Recently installed binary in PATH: {} ({} days ago{})",
                        path.display(),
                        age.as_secs() / 86400,
                        if is_unsigned { ", unsigned" } else { "" }
                    ),
                    json!({
                        "binary": path.to_string_lossy(),
                        "age_days": age.as_secs() / 86400,
                        "signature": signature_status
                    }),
                );

                // Recency alone is informational; unsigned + recent blocks
                if !is_unsigned {
                    finding.severity = Severity::Low;
                    finding.blocking = false;
                }
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

/// On macOS, run `codesign --verify` on the binary. Returns
/// Some("signed"|"unsigned") or None when verification is unavailable.
#[cfg(target_os = "macos")]
fn signature_status(path: &Path) -> Option<String> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg(path)
        .output()
        .ok()?;
    Some(if output.status.success() {
        "signed".to_string()
    } else {
        "unsigned".to_string()
    })
}

#[cfg(not(target_os = "macos"))]
fn signature_status(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = UnsignedBinariesCheck;
        assert_eq!(check.id(), "unsigned-binaries-in-path");
        assert!(check.blocking_in_preflight());
    }

    #[test]
    fn test_run_does_not_error() {
        let check = UnsignedBinariesCheck;
        assert!(check.run().is_ok());
    }
}
