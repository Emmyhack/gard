//! Clipboard monitoring and address hijacking process detection
//!
//! Scans the process table for processes whose names match known
//! clipboard-stealer families or generic clipboard-monitoring patterns.
//! Address-swap malware watches the clipboard for wallet addresses and
//! replaces them with attacker-controlled ones at paste time.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use sysinfo::System;

pub struct ClipboardMonitorCheck;

/// Process name fragments associated with clipboard interception (lowercase)
const SUSPICIOUS_NAMES: &[&str] = &[
    "clipbanker",
    "clipminer",
    "clipboardwalletprotector",
    "cliphijack",
    "clipgrab-daemon",
    "xclipmon",
];

/// Legitimate clipboard managers we do not flag
const KNOWN_BENIGN: &[&str] = &[
    "pboard", // macOS system pasteboard server
    "clipy", "maccy", "flycut", "copyq", "gpaste", "klipper", "raycast", "alfred", "pastebot",
];

impl CheckModule for ClipboardMonitorCheck {
    fn id(&self) -> &str {
        "clipboard-monitor-detection"
    }

    fn name(&self) -> &str {
        "Clipboard Monitor and Address Hijack Detection"
    }

    fn description(&self) -> &str {
        "Scans running processes for known clipboard-stealing malware families and \
        unrecognized clipboard-monitoring processes that could swap wallet addresses."
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
        "Terminate the flagged process, identify its binary path and launch mechanism \
        (launchd, systemd, autostart), remove persistence, and treat all addresses \
        copied on this machine as potentially tampered. Verify receiving addresses \
        on a hardware wallet display before signing."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut system = System::new();
        system.refresh_processes();

        for (pid, process) in system.processes() {
            let name = process.name().to_lowercase();

            if KNOWN_BENIGN.iter().any(|b| name.contains(b)) {
                continue;
            }

            if let Some(matched) = SUSPICIOUS_NAMES.iter().find(|s| name.contains(*s)) {
                findings.push(build_finding(
                    self,
                    format!(
                        "Suspicious clipboard-monitoring process running: {} (pid {})",
                        process.name(),
                        pid
                    ),
                    json!({
                        "process_name": process.name(),
                        "pid": pid.as_u32(),
                        "exe": process.exe().map(|p| p.to_string_lossy().to_string()),
                        "matched_pattern": matched
                    }),
                ));
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = ClipboardMonitorCheck;
        assert_eq!(check.id(), "clipboard-monitor-detection");
        assert!(check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::Critical);
    }

    #[test]
    fn test_run_does_not_error() {
        let check = ClipboardMonitorCheck;
        assert!(check.run().is_ok());
    }
}
