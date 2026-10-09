//! TestFlight application detection on macOS
//!
//! TestFlight builds skip App Store review and can differ from the
//! production app without any visible change in name or icon, which is
//! how the Drift Protocol signer application was swapped. A TestFlight
//! build is identified by its embedded beta provisioning profile. Any
//! TestFlight app is reported; wallet or signing apps block preflight.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub struct TestflightAppsCheck;

/// Name fragments (lowercase) of applications that touch keys or signing
const SIGNING_APP_FRAGMENTS: &[&str] = &[
    "wallet", "ledger", "trezor", "phantom", "solflare", "backpack", "squads", "safe", "metamask",
    "exodus", "keystone", "signer",
];

/// Marker present in beta (TestFlight) provisioning profiles
const BETA_MARKER: &str = "beta-reports-active";

impl CheckModule for TestflightAppsCheck {
    fn id(&self) -> &str {
        "macos-testflight-apps"
    }

    fn name(&self) -> &str {
        "TestFlight Application Detection"
    }

    fn description(&self) -> &str {
        "Detects applications installed as TestFlight beta builds. Beta builds bypass \
        App Store review and can be swapped for compromised versions without any \
        visible change; wallet and signing apps delivered this way block preflight."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS]
    }

    fn remediation(&self) -> &str {
        "Remove TestFlight builds of wallet or signing applications from signing \
        machines and reinstall from the App Store or the vendor's verified release. \
        Keep beta software on machines that never hold authority keys."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for dir in self.application_dirs() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let app = entry.path();
                if app.extension().map(|e| e == "app").unwrap_or(false) {
                    if let Some(finding) = self.evaluate_app(&app) {
                        findings.push(finding);
                    }
                }
            }
        }
        Ok(findings)
    }
}

impl TestflightAppsCheck {
    fn application_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = vec![PathBuf::from("/Applications")];
        if let Some(home) = dirs::home_dir() {
            dirs.push(home.join("Applications"));
        }
        dirs
    }

    /// Report an app bundle if it carries a beta provisioning profile
    fn evaluate_app(&self, app: &Path) -> Option<Finding> {
        let profile = app.join("Contents").join("embedded.provisionprofile");
        let bytes = fs::read(&profile).ok()?;
        // Profiles are CMS-wrapped plists; the plist text is readable in place
        let text = String::from_utf8_lossy(&bytes);
        if !text.contains(BETA_MARKER) {
            return None;
        }

        let app_name = app
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let lower = app_name.to_lowercase();
        let signing_related = SIGNING_APP_FRAGMENTS.iter().any(|f| lower.contains(f));

        let mut finding = build_finding(
            self,
            format!(
                "TestFlight beta build installed: {}{}",
                app_name,
                if signing_related {
                    " (wallet or signing application)"
                } else {
                    ""
                }
            ),
            json!({
                "application": app.to_string_lossy(),
                "provisioning_profile": profile.to_string_lossy(),
                "signing_related": signing_related
            }),
        );
        if !signing_related {
            finding.severity = Severity::Medium;
            finding.blocking = false;
        }
        Some(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_app(name: &str, profile: Option<&str>) -> PathBuf {
        let root = std::env::temp_dir().join(format!("gard-tf-{}-{}", std::process::id(), name));
        let app = root.join(format!("{}.app", name));
        fs::create_dir_all(app.join("Contents")).unwrap();
        if let Some(p) = profile {
            fs::write(app.join("Contents").join("embedded.provisionprofile"), p).unwrap();
        }
        app
    }

    #[test]
    fn test_check_metadata() {
        let check = TestflightAppsCheck;
        assert_eq!(check.id(), "macos-testflight-apps");
        assert!(check.blocking_in_preflight());
        assert_eq!(check.platforms(), &[Platform::MacOS]);
    }

    #[test]
    fn test_app_store_build_passes() {
        let check = TestflightAppsCheck;
        let app = fake_app("Notes", Some("<key>application-identifier</key>"));
        assert!(check.evaluate_app(&app).is_none());
        let plain = fake_app("Plain", None);
        assert!(check.evaluate_app(&plain).is_none());
    }

    #[test]
    fn test_testflight_wallet_blocks_and_other_warns() {
        let check = TestflightAppsCheck;
        let wallet = fake_app(
            "Phantom Wallet",
            Some("<key>beta-reports-active</key><true/>"),
        );
        let f = check.evaluate_app(&wallet).expect("flagged");
        assert!(f.blocking);
        assert_eq!(f.severity, Severity::High);

        let game = fake_app("Chess", Some("<key>beta-reports-active</key><true/>"));
        let f = check.evaluate_app(&game).expect("flagged");
        assert!(!f.blocking);
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn test_run_does_not_error() {
        assert!(TestflightAppsCheck.run().is_ok());
    }
}
