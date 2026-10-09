//! Environment variable audit for leaked key material
//!
//! Detects keypair material and keypair file paths exposed through the
//! process environment, shell profiles, and CI configuration. Variable
//! *names* alone are only trusted when they unambiguously denote key
//! material; generic names such as `*_TOKEN` are reported only when the
//! value itself is shaped like a key, so routine tooling credentials do
//! not block signing ceremonies.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

pub struct EnvVariablesCheck;

/// Names that denote signing-key material regardless of value
const STRONG_NAME_FRAGMENTS: &[&str] = &[
    "SOLANA_KEYPAIR",
    "KEYPAIR_PATH",
    "KEYPAIR",
    "PRIVATE_KEY",
    "SECRET_KEY",
    "MNEMONIC",
    "SEED_PHRASE",
    "WALLET_SECRET",
];

/// Names that are credential-ish but routinely hold harmless tooling
/// tokens; flagged only when the value looks like key material
const GENERIC_NAME_FRAGMENTS: &[&str] = &["TOKEN", "API_KEY", "SECRET", "PASSWORD"];

fn base58_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Full base58 alphabet; a 64-byte Solana secret key encodes to 86-88 chars
    RE.get_or_init(|| Regex::new(r"\b[1-9A-HJ-NP-Za-km-z]{86,88}\b").expect("valid regex"))
}

fn hex_key_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[0-9a-fA-F]{64}\b").expect("valid regex"))
}

fn keypair_name_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(SOLANA_KEYPAIR|KEYPAIR_PATH|PRIVATE_KEY|SECRET_KEY|MNEMONIC|SEED_PHRASE)\b",
        )
        .expect("valid regex")
    })
}

/// Whether a value is shaped like signing-key material. Never logs the value.
fn looks_like_key_material(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    if base58_key_regex().is_match(v) || hex_key_regex().is_match(v) {
        return true;
    }
    if v.starts_with("-----BEGIN") && v.contains("PRIVATE KEY") {
        return true;
    }
    // Solana JSON keypair: an array of 64 byte values
    if v.starts_with('[') && v.ends_with(']') {
        let count = v[1..v.len() - 1]
            .split(',')
            .filter(|s| s.trim().parse::<u8>().is_ok())
            .count();
        return count == 64;
    }
    false
}

impl CheckModule for EnvVariablesCheck {
    fn id(&self) -> &str {
        "env-key-leakage"
    }

    fn name(&self) -> &str {
        "Environment Variable Audit for Leaked Key Material"
    }

    fn description(&self) -> &str {
        "Audits the process environment, shell profiles, and CI configuration for \
        signing-key material and keypair file paths. Generic credential variables are \
        reported only when their values are shaped like keys."
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
        "Remove key material and keypair paths from the environment and shell \
        profiles; load keys through a hardware wallet or an agent at signing time. \
        Keep CI secrets in the CI provider's secret store, never in checked-in files."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        findings.extend(self.scan_environment_variables());
        findings.extend(self.scan_shell_profiles());
        findings.extend(self.scan_ci_configuration());
        Ok(findings)
    }
}

impl EnvVariablesCheck {
    fn scan_environment_variables(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (key, value) in std::env::vars() {
            match self.classify_variable(&key, &value) {
                VariableRisk::None => {},
                VariableRisk::KeypairFile => findings.push(build_finding(
                    self,
                    format!(
                        "Environment variable {} points at a keypair file on disk. Any \
                        process running as this user can read it.",
                        key
                    ),
                    json!({
                        "variable_name": key,
                        "variable_value_redacted": true,
                        "classification": "keypair_file_path",
                        "source": "process_environment"
                    }),
                )),
                VariableRisk::KeyMaterial => findings.push(build_finding(
                    self,
                    format!("Environment variable {} holds signing-key material.", key),
                    json!({
                        "variable_name": key,
                        "variable_value_redacted": true,
                        "classification": "key_material",
                        "source": "process_environment"
                    }),
                )),
                VariableRisk::CredentialShaped => {
                    let mut finding = build_finding(
                        self,
                        format!(
                            "Environment variable {} holds a value shaped like a secret \
                            key. Verify it is not wallet key material.",
                            key
                        ),
                        json!({
                            "variable_name": key,
                            "variable_value_redacted": true,
                            "classification": "credential_shaped",
                            "source": "process_environment"
                        }),
                    );
                    finding.severity = Severity::Medium;
                    finding.blocking = false;
                    findings.push(finding);
                },
            }
        }

        findings
    }

    /// Decide how risky a variable is from its name and value shape
    fn classify_variable(&self, key: &str, value: &str) -> VariableRisk {
        let upper = key.to_uppercase();
        let strong = STRONG_NAME_FRAGMENTS.iter().any(|f| upper.contains(f));
        let generic = GENERIC_NAME_FRAGMENTS.iter().any(|f| upper.contains(f));

        if strong {
            let path = Path::new(value.trim());
            if path.is_absolute() && path.is_file() {
                return VariableRisk::KeypairFile;
            }
            if looks_like_key_material(value) {
                return VariableRisk::KeyMaterial;
            }
            // Strong name, but the value is neither a key nor a file: treat
            // as credential-shaped so it warns without blocking
            return VariableRisk::CredentialShaped;
        }

        if generic && looks_like_key_material(value) {
            return VariableRisk::CredentialShaped;
        }

        VariableRisk::None
    }

    fn scan_shell_profiles(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return findings;
        };

        for name in [
            ".bashrc",
            ".zshrc",
            ".bash_profile",
            ".profile",
            ".zprofile",
        ] {
            let profile = home.join(name);
            if let Ok(content) = fs::read_to_string(&profile) {
                findings.extend(self.scan_file_content(&content, &profile));
            }
        }

        findings
    }

    fn scan_ci_configuration(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(cwd) = std::env::current_dir() else {
            return findings;
        };

        let workflows = cwd.join(".github/workflows");
        if let Ok(entries) = fs::read_dir(&workflows) {
            for entry in entries.flatten() {
                let path = entry.path();
                let is_yaml = path
                    .extension()
                    .map(|e| e == "yml" || e == "yaml")
                    .unwrap_or(false);
                if is_yaml {
                    if let Ok(content) = fs::read_to_string(&path) {
                        findings.extend(self.scan_file_content(&content, &path));
                    }
                }
            }
        }

        for name in [".gitlab-ci.yml", ".circleci/config.yml"] {
            let path = cwd.join(name);
            if let Ok(content) = fs::read_to_string(&path) {
                findings.extend(self.scan_file_content(&content, &path));
            }
        }

        findings
    }

    /// Scan a text file for exported key material or keypair assignments
    fn scan_file_content(&self, content: &str, source_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // An assignment to a keypair-denoting variable, e.g. `export SOLANA_KEYPAIR=...`
            let assigns_keypair = keypair_name_regex().is_match(line) && line.contains('=');
            if assigns_keypair {
                findings.push(build_finding(
                    self,
                    format!(
                        "Keypair variable assigned in {} (line {}).",
                        source_path.display(),
                        idx + 1
                    ),
                    json!({
                        "source_file": source_path.to_string_lossy(),
                        "line_number": idx + 1,
                        "pattern_matched": "keypair_variable"
                    }),
                ));
                continue;
            }

            if line.len() < 400 && base58_key_regex().is_match(line) {
                findings.push(build_finding(
                    self,
                    format!(
                        "Base58 value the length of a Solana secret key found in {} (line {}).",
                        source_path.display(),
                        idx + 1
                    ),
                    json!({
                        "source_file": source_path.to_string_lossy(),
                        "line_number": idx + 1,
                        "pattern_matched": "base58_secret_key"
                    }),
                ));
            }
        }

        findings
    }
}

enum VariableRisk {
    None,
    CredentialShaped,
    KeyMaterial,
    KeypairFile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_check_creation() {
        let check = EnvVariablesCheck;
        assert_eq!(check.id(), "env-key-leakage");
        assert!(check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::Critical);
    }

    #[test]
    fn test_generic_token_with_opaque_value_is_ignored() {
        let check = EnvVariablesCheck;
        assert!(matches!(
            check.classify_variable("GITHUB_TOKEN", "ghp_abc123"),
            VariableRisk::None
        ));
        assert!(matches!(
            check.classify_variable("EDITOR_SESSION_TOKEN", "a1b2c3"),
            VariableRisk::None
        ));
    }

    #[test]
    fn test_generic_token_with_key_shaped_value_warns() {
        let check = EnvVariablesCheck;
        let hex64 = "ab".repeat(32);
        assert!(matches!(
            check.classify_variable("DEPLOY_SECRET", &hex64),
            VariableRisk::CredentialShaped
        ));
    }

    #[test]
    fn test_strong_name_with_key_material_is_key_material() {
        let check = EnvVariablesCheck;
        let json_keypair = format!("[{}]", vec!["7"; 64].join(","));
        assert!(matches!(
            check.classify_variable("SOLANA_PRIVATE_KEY", &json_keypair),
            VariableRisk::KeyMaterial
        ));
    }

    #[test]
    fn test_looks_like_key_material_shapes() {
        assert!(looks_like_key_material(&"5".repeat(88)));
        assert!(looks_like_key_material(&"0f".repeat(32)));
        assert!(looks_like_key_material("-----BEGIN PRIVATE KEY-----\nabc"));
        assert!(!looks_like_key_material("hunter2"));
        assert!(!looks_like_key_material("[1,2,3]"));
        // Base58 excludes 0, O, I, l
        assert!(!looks_like_key_material(&"0".repeat(88)));
    }

    #[test]
    fn test_file_scan_skips_comments_and_flags_assignments() {
        let check = EnvVariablesCheck;
        let content = "# export SOLANA_KEYPAIR=/tmp/x\nexport SOLANA_KEYPAIR=/home/u/id.json\nexport PATH=$PATH\n";
        let findings = check.scan_file_content(content, Path::new("/tmp/.zshrc"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].details["line_number"], 2);
    }
}
