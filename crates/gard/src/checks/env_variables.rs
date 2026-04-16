/// Environment variable audit for leaked key material
///
/// Detects keypair paths and secret environment variables in shell
/// profiles, process environment, and CI configuration files.

use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use regex::Regex;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

pub struct EnvVariablesCheck;

static FINDING_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

fn next_finding_id() -> String {
    let n = FINDING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("f_{:06}", n)
}

impl CheckModule for EnvVariablesCheck {
    fn id(&self) -> &str {
        "env-key-leakage"
    }

    fn name(&self) -> &str {
        "Environment Variable Audit for Leaked Key Material"
    }

    fn description(&self) -> &str {
        "Audits environment variables for patterns indicating leaked key material or sensitive paths. \
        Checks shell profiles, process environment, and CI configuration for keypair paths, private key exports, \
        and credential environment variables."
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
        "Remove all keypair paths from shell environment, use secure key loading mechanisms \
        (SSH agent, hardware wallet), configure CI/CD to not expose secrets in environment, \
        audit shell history for accidental key exposure."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Scan shell profiles
        if let Ok(shell_findings) = self.scan_shell_profiles() {
            findings.extend(shell_findings);
        }

        // Scan environment variables
        if let Ok(env_findings) = self.scan_environment_variables() {
            findings.extend(env_findings);
        }

        // Scan CI/CD configuration
        if let Ok(ci_findings) = self.scan_ci_configuration() {
            findings.extend(ci_findings);
        }

        Ok(findings)
    }
}

impl EnvVariablesCheck {
    fn scan_shell_profiles(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let home = dirs::home_dir().ok_or_else(|| {
            crate::error::GardError::CheckExecutionError {
                check_name: "env-key-leakage".to_string(),
                reason: "Could not determine home directory".to_string(),
            }
        })?;

        let profiles = vec![
            home.join(".bashrc"),
            home.join(".zshrc"),
            home.join(".bash_profile"),
            home.join(".profile"),
        ];

        for profile in profiles {
            if profile.exists() {
                if let Ok(content) = fs::read_to_string(&profile) {
                    findings.extend(self.scan_file_content(&content, &profile)?);
                }
            }
        }

        Ok(findings)
    }

    fn scan_environment_variables(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (key, _value) in std::env::vars() {
            if self.is_sensitive_variable(&key) {
                findings.push(Finding {
                    id: next_finding_id(),
                    check_id: self.id().to_string(),
                    check_name: self.name().to_string(),
                    severity: self.severity(),
                    platform: crate::types::current_platform(),
                    description: format!("Sensitive environment variable found: {}", key),
                    remediation: self.remediation().to_string(),
                    blocking: self.blocking_in_preflight(),
                    timestamp: chrono::Utc::now(),
                    details: json!({
                        "variable_name": key,
                        "variable_value_redacted": true,
                        "source": "process_environment"
                    }),
                });
            }
        }

        Ok(findings)
    }

    fn scan_ci_configuration(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let home = dirs::home_dir().ok_or_else(|| {
            crate::error::GardError::CheckExecutionError {
                check_name: "env-key-leakage".to_string(),
                reason: "Could not determine home directory".to_string(),
            }
        })?;

        let ci_paths = vec![
            home.join(".github/workflows"),
            home.join(".gitlab-ci.yml"),
            home.join(".circleci/config.yml"),
        ];

        for path in ci_paths {
            if path.exists() && path.is_file() {
                if let Ok(content) = fs::read_to_string(&path) {
                    findings.extend(self.scan_file_content(&content, &path)?);
                }
            } else if path.exists() && path.is_dir() {
                // Scan workflow files
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            if entry.path().extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false) {
                                if let Ok(content) = fs::read_to_string(entry.path()) {
                                    findings.extend(self.scan_file_content(&content, &entry.path())?);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    fn scan_file_content(&self, content: &str, source_path: &PathBuf) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let keypair_pattern = Regex::new(r"(?i)(SOLANA_KEYPAIR|KEYPAIR_PATH|SECRET_KEY|PRIVATE_KEY)").ok();
        let base58_pattern = Regex::new(r"[1-9A-HJ-NP-Z]{88}").ok();

        for (line_num, line) in content.lines().enumerate() {
            if let Some(ref pattern) = keypair_pattern {
                if pattern.is_match(line) {
                    findings.push(Finding {
                        id: next_finding_id(),
                        check_id: self.id().to_string(),
                        check_name: self.name().to_string(),
                        severity: self.severity(),
                        platform: crate::types::current_platform(),
                        description: format!("Keypair path pattern found in {}", source_path.display()),
                        remediation: self.remediation().to_string(),
                        blocking: self.blocking_in_preflight(),
                        timestamp: chrono::Utc::now(),
                        details: json!({
                            "source_file": source_path.to_string_lossy(),
                            "line_number": line_num + 1,
                            "pattern_matched": "keypair_variable"
                        }),
                    });
                }
            }

            if let Some(ref pattern) = base58_pattern {
                if pattern.is_match(line) && line.len() < 200 {
                    // Likely a Solana keypair
                    findings.push(Finding {
                        id: next_finding_id(),
                        check_id: self.id().to_string(),
                        check_name: self.name().to_string(),
                        severity: self.severity(),
                        platform: crate::types::current_platform(),
                        description: format!("Potential Base58-encoded keypair found in {}", source_path.display()),
                        remediation: self.remediation().to_string(),
                        blocking: self.blocking_in_preflight(),
                        timestamp: chrono::Utc::now(),
                        details: json!({
                            "source_file": source_path.to_string_lossy(),
                            "line_number": line_num + 1,
                            "pattern_matched": "base58_keypair"
                        }),
                    });
                }
            }
        }

        Ok(findings)
    }

    fn is_sensitive_variable(&self, key: &str) -> bool {
        let patterns = vec![
            "KEYPAIR", "KEY_PATH", "SECRET", "PRIVATE_KEY", 
            "SOLANA_KEYPAIR", "AWS_SECRET", "DATABASE_PASSWORD",
            "API_KEY", "TOKEN"
        ];

        patterns.iter().any(|p| key.to_uppercase().contains(p))
    }
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
    fn test_is_sensitive_variable() {
        let check = EnvVariablesCheck;
        assert!(check.is_sensitive_variable("SOLANA_KEYPAIR"));
        assert!(check.is_sensitive_variable("API_KEY"));
        assert!(!check.is_sensitive_variable("PATH"));
    }
}
