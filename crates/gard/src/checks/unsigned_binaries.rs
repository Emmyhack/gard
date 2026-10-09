//! Recently-installed binary audit
//!
//! Looks at user-writable PATH directories for binaries that changed in
//! the last 7 days. Installs that came through a package manager (Homebrew
//! Cellar links, `cargo install`) are summarized in one informational
//! finding; a recent binary that is neither package-managed nor
//! code-signed is reported individually and blocks preflight.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct UnsignedBinariesCheck;

/// Only audit user-writable prefixes; system dirs are OS managed
const AUDITED_PREFIXES: &[&str] = &["/usr/local/bin", "/opt/homebrew/bin"];

const RECENT_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Cap on names listed in the informational summary
const SUMMARY_LIST_LIMIT: usize = 12;

impl CheckModule for UnsignedBinariesCheck {
    fn id(&self) -> &str {
        "unsigned-binaries-in-path"
    }

    fn name(&self) -> &str {
        "Unsigned and Recently-Installed Binary Detection"
    }

    fn description(&self) -> &str {
        "Flags binaries dropped into user-writable PATH directories within the last \
        7 days that are neither package-manager managed nor code-signed. Package \
        manager installs are summarized for awareness without blocking."
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
        "Confirm each flagged binary was installed intentionally and from a trusted \
        source; remove anything unrecognized. Prefer signed, package-managed tooling \
        on signing machines."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = SystemTime::now();
        let home = dirs::home_dir();

        let mut dirs_to_scan: Vec<PathBuf> =
            AUDITED_PREFIXES.iter().map(|p| PathBuf::from(*p)).collect();
        if let Some(home) = &home {
            dirs_to_scan.push(home.join("bin"));
            dirs_to_scan.push(home.join(".local/bin"));
            dirs_to_scan.push(home.join(".cargo/bin"));
        }

        let mut managed_recent: Vec<String> = Vec::new();

        for dir in dirs_to_scan {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Resolve symlinks (Homebrew links bin/ into Cellar/)
                let Ok(target) = fs::canonicalize(&path) else {
                    continue;
                };
                if !target.is_file() {
                    continue;
                }
                let Ok(metadata) = fs::metadata(&target) else {
                    continue;
                };
                let Ok(modified) = metadata.modified() else {
                    continue;
                };
                let age = now.duration_since(modified).unwrap_or_default();
                if age > RECENT_WINDOW {
                    continue;
                }

                if is_package_managed(&target, home.as_deref()) {
                    managed_recent.push(path.to_string_lossy().to_string());
                    continue;
                }

                // Scripts cannot carry a code signature; report them as
                // such rather than as "unsigned" executables
                let signature = if is_script(&target) {
                    Some("script".to_string())
                } else {
                    signature_status(&target)
                };
                let unsigned = signature.as_deref() == Some("unsigned");
                let age_days = age.as_secs() / 86400;

                let mut finding = build_finding(
                    self,
                    format!(
                        "Recently installed binary outside package management: {} ({} day(s) ago{})",
                        path.display(),
                        age_days,
                        match signature.as_deref() {
                            Some("unsigned") => ", not code-signed",
                            Some("script") => ", script",
                            _ => "",
                        }
                    ),
                    json!({
                        "binary": path.to_string_lossy(),
                        "resolved": target.to_string_lossy(),
                        "age_days": age_days,
                        "signature": signature,
                        "package_managed": false
                    }),
                );
                // Only an unsigned, unmanaged, recent binary blocks signing;
                // a signed one is worth knowing about but not stopping for
                if !unsigned {
                    finding.severity = Severity::Low;
                    finding.blocking = false;
                }
                findings.push(finding);
            }
        }

        if !managed_recent.is_empty() {
            managed_recent.sort();
            managed_recent.dedup();
            let shown: Vec<&String> = managed_recent.iter().take(SUMMARY_LIST_LIMIT).collect();
            let mut finding = build_finding(
                self,
                format!(
                    "{} package-managed binar{} updated in the last 7 days (e.g. {}).",
                    managed_recent.len(),
                    if managed_recent.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    shown
                        .iter()
                        .map(|p| {
                            Path::new(p)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default()
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                json!({
                    "count": managed_recent.len(),
                    "binaries": managed_recent,
                    "package_managed": true
                }),
            );
            finding.severity = Severity::Info;
            finding.blocking = false;
            findings.push(finding);
        }

        Ok(findings)
    }
}

/// Whether a resolved binary path lives under a package manager's tree
fn is_package_managed(resolved: &Path, home: Option<&Path>) -> bool {
    let text = resolved.to_string_lossy();
    if text.contains("/Cellar/") || text.contains("/homebrew/Caskroom/") {
        return true;
    }
    // Command-line shims that resolve into an installed application bundle
    // (e.g. VS Code's `code`) are governed by Gatekeeper, not by PATH hygiene
    if text.starts_with("/Applications/") && text.contains(".app/") {
        return true;
    }
    if let Some(home) = home {
        for managed in [
            ".cargo/bin",
            ".local/pipx",
            ".npm-global",
            ".nvm",
            ".rustup",
            "go/bin",
        ] {
            if resolved.starts_with(home.join(managed)) {
                return true;
            }
        }
    }
    text.starts_with("/nix/store/")
}

/// Whether the file starts with a shebang (an interpreter script)
fn is_script(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 2];
    matches!(file.read(&mut head), Ok(2)) && &head == b"#!"
}

/// On macOS, run `codesign --verify`. Returns Some("signed"|"unsigned") or
/// None when verification is unavailable.
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
    fn test_package_managed_detection() {
        let home = PathBuf::from("/Users/u");
        assert!(is_package_managed(
            Path::new("/opt/homebrew/Cellar/ripgrep/14.0/bin/rg"),
            Some(&home)
        ));
        assert!(is_package_managed(
            Path::new("/Users/u/.cargo/bin/cargo-deny"),
            Some(&home)
        ));
        assert!(is_package_managed(
            Path::new("/nix/store/abc-hello/bin/hello"),
            None
        ));
        assert!(!is_package_managed(
            Path::new("/usr/local/bin/mystery"),
            Some(&home)
        ));
    }

    #[test]
    fn test_app_bundle_shims_are_managed() {
        assert!(is_package_managed(
            Path::new("/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"),
            None
        ));
    }

    #[test]
    fn test_script_detection() {
        let dir = std::env::temp_dir();
        let script = dir.join(format!("gard-script-{}", std::process::id()));
        fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        assert!(is_script(&script));
        let binary = dir.join(format!("gard-bin-{}", std::process::id()));
        fs::write(&binary, [0xcf, 0xfa, 0xed, 0xfe]).unwrap();
        assert!(!is_script(&binary));
        fs::remove_file(script).ok();
        fs::remove_file(binary).ok();
    }

    #[test]
    fn test_run_does_not_error() {
        let check = UnsignedBinariesCheck;
        assert!(check.run().is_ok());
    }
}
