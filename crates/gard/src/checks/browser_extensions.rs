//! Browser cryptocurrency extension detection
//!
//! Scans Chrome-family and Firefox profiles for installed crypto wallet
//! extensions. Browser wallets on a signing machine expand the phishing
//! and drainer attack surface.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

pub struct BrowserExtensionsCheck;

/// Chrome Web Store extension IDs for popular crypto wallets
const WALLET_EXTENSION_IDS: &[(&str, &str)] = &[
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("fhbohimaelbohpjbbldcngcnapndodjp", "Binance Wallet"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
    ("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
    ("aflkmfhebedbjioipglgcbcmnbpgliof", "Backpack"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask (Edge)"),
];

impl CheckModule for BrowserExtensionsCheck {
    fn id(&self) -> &str {
        "browser-crypto-extension"
    }

    fn name(&self) -> &str {
        "Browser Cryptocurrency Extension Detection"
    }

    fn description(&self) -> &str {
        "Detects cryptocurrency wallet extensions installed in Chrome-family and \
        Firefox browsers on this machine."
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
        "Remove browser wallet extensions from signing machines. Keep browser \
        wallets on a separate machine or browser profile that never touches \
        protocol authority keys."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (browser, ext_root) in self.chrome_extension_roots() {
            if !ext_root.exists() {
                continue;
            }
            let Ok(entries) = fs::read_dir(&ext_root) else {
                continue;
            };
            for entry in entries.flatten() {
                let id = entry.file_name().to_string_lossy().to_string();
                if let Some((_, wallet)) = WALLET_EXTENSION_IDS
                    .iter()
                    .find(|(ext_id, _)| *ext_id == id)
                {
                    findings.push(build_finding(
                        self,
                        format!(
                            "Crypto wallet extension installed in {}: {}",
                            browser, wallet
                        ),
                        json!({
                            "browser": browser,
                            "wallet": wallet,
                            "extension_id": id,
                            "path": entry.path().to_string_lossy()
                        }),
                    ));
                }
            }
        }

        Ok(findings)
    }
}

impl BrowserExtensionsCheck {
    /// Default-profile extension directories for Chrome-family browsers
    fn chrome_extension_roots(&self) -> Vec<(&'static str, PathBuf)> {
        let mut roots = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return roots;
        };

        #[cfg(target_os = "macos")]
        {
            let app_support = home.join("Library/Application Support");
            roots.extend([
                (
                    "Google Chrome",
                    app_support.join("Google/Chrome/Default/Extensions"),
                ),
                (
                    "Brave",
                    app_support.join("BraveSoftware/Brave-Browser/Default/Extensions"),
                ),
                (
                    "Microsoft Edge",
                    app_support.join("Microsoft Edge/Default/Extensions"),
                ),
                ("Arc", app_support.join("Arc/User Data/Default/Extensions")),
            ]);
        }

        #[cfg(target_os = "linux")]
        {
            roots.extend([
                (
                    "Google Chrome",
                    home.join(".config/google-chrome/Default/Extensions"),
                ),
                ("Chromium", home.join(".config/chromium/Default/Extensions")),
                (
                    "Brave",
                    home.join(".config/BraveSoftware/Brave-Browser/Default/Extensions"),
                ),
            ]);
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(local) = dirs::data_local_dir() {
                roots.extend([
                    (
                        "Google Chrome",
                        local.join("Google/Chrome/User Data/Default/Extensions"),
                    ),
                    (
                        "Microsoft Edge",
                        local.join("Microsoft/Edge/User Data/Default/Extensions"),
                    ),
                ]);
            }
        }

        roots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = BrowserExtensionsCheck;
        assert_eq!(check.id(), "browser-crypto-extension");
        assert!(!check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::Medium);
    }

    #[test]
    fn test_run_does_not_error() {
        let check = BrowserExtensionsCheck;
        assert!(check.run().is_ok());
    }
}
