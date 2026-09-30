//! SSH key hygiene and agent configuration audit
//!
//! Checks ~/.ssh for unencrypted private keys, overly permissive file
//! modes, and ssh_config entries enabling agent forwarding — which lets
//! a compromised remote host use local keys.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct SshHygieneCheck;

impl CheckModule for SshHygieneCheck {
    fn id(&self) -> &str {
        "ssh-key-hygiene"
    }

    fn name(&self) -> &str {
        "SSH Key Hygiene and Agent Configuration"
    }

    fn description(&self) -> &str {
        "Audits ~/.ssh for unencrypted private keys, world- or group-readable key \
        files, and SSH client configuration that forwards the agent to remote hosts."
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
        "Encrypt private keys with a passphrase (ssh-keygen -p), set key files to \
        mode 0600, and remove 'ForwardAgent yes' from ssh_config except for \
        explicitly trusted hosts."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return Ok(findings);
        };
        let ssh_dir = home.join(".ssh");
        if !ssh_dir.exists() {
            return Ok(findings);
        }

        if let Ok(entries) = fs::read_dir(&ssh_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if self.is_private_key(&path) {
                    findings.extend(self.audit_private_key(&path));
                }
            }
        }

        let config_path = ssh_dir.join("config");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                findings.extend(self.audit_ssh_config(&content, &config_path));
            }
        }

        Ok(findings)
    }
}

impl SshHygieneCheck {
    fn is_private_key(&self, path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.ends_with(".pub")
            || name == "config"
            || name == "known_hosts"
            || name == "known_hosts.old"
            || name == "authorized_keys"
        {
            return false;
        }
        // Confirm by header rather than filename alone
        fs::read_to_string(path)
            .map(|c| c.contains("PRIVATE KEY"))
            .unwrap_or(false)
    }

    fn audit_private_key(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        let content = fs::read_to_string(path).unwrap_or_default();
        let encrypted = content.contains("ENCRYPTED")
            // OpenSSH format stores the KDF name; unencrypted keys use "none"
            || (content.contains("OPENSSH PRIVATE KEY") && !is_openssh_key_unencrypted(&content));

        if !encrypted {
            findings.push(build_finding(
                self,
                format!(
                    "Unencrypted SSH private key: {}. Anyone with file access can use \
                    this key without a passphrase.",
                    path.display()
                ),
                json!({
                    "key_path": path.to_string_lossy(),
                    "issue": "no_passphrase"
                }),
            ));
        }

        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                let mut finding = build_finding(
                    self,
                    format!(
                        "SSH private key {} has permissive mode {:o}; expected 0600.",
                        path.display(),
                        mode
                    ),
                    json!({
                        "key_path": path.to_string_lossy(),
                        "issue": "permissive_mode",
                        "mode": format!("{:o}", mode)
                    }),
                );
                finding.severity = Severity::High;
                findings.push(finding);
            }
        }

        findings
    }

    fn audit_ssh_config(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut current_host = String::from("(global)");

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            let lower = trimmed.to_lowercase();

            if lower.starts_with("host ") {
                current_host = trimmed[5..].trim().to_string();
            }

            if lower.starts_with("forwardagent") && lower.contains("yes") {
                let mut finding = build_finding(
                    self,
                    format!(
                        "SSH agent forwarding enabled for host '{}' in {}. A compromised \
                        remote host can use local keys while the session is open.",
                        current_host,
                        path.display()
                    ),
                    json!({
                        "config_file": path.to_string_lossy(),
                        "host": current_host,
                        "line_number": line_num + 1,
                        "issue": "agent_forwarding"
                    }),
                );
                // Wildcard forwarding is the dangerous case; scoped hosts warn
                if current_host != "*" && current_host != "(global)" {
                    finding.severity = Severity::Medium;
                    finding.blocking = false;
                }
                findings.push(finding);
            }
        }

        findings
    }
}

/// OpenSSH-format keys embed the KDF; "none" in the base64 header region
/// indicates no passphrase. Decoding properly requires base64 parsing of the
/// key blob, so we check the decoded prefix.
fn is_openssh_key_unencrypted(content: &str) -> bool {
    let body: String = content
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    // Decode enough of the blob to read ciphername/kdfname fields
    let decoded = base64_decode_prefix(&body, 96);
    let text = String::from_utf8_lossy(&decoded);
    text.contains("none")
}

/// Minimal base64 decoder for the first `max_out` bytes (no external dep)
fn base64_decode_prefix(input: &str, max_out: usize) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut out = Vec::with_capacity(max_out);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for byte in input.bytes() {
        let val = lookup[byte as usize];
        if val == 255 {
            continue;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            if out.len() >= max_out {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = SshHygieneCheck;
        assert_eq!(check.id(), "ssh-key-hygiene");
        assert!(check.blocking_in_preflight());
    }

    #[test]
    fn test_wildcard_forward_agent_blocks() {
        let check = SshHygieneCheck;
        let config = "Host *\n    ForwardAgent yes\n";
        let findings = check.audit_ssh_config(config, Path::new("/tmp/config"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].blocking);
    }

    #[test]
    fn test_scoped_forward_agent_warns() {
        let check = SshHygieneCheck;
        let config = "Host build-server\n    ForwardAgent yes\n";
        let findings = check.audit_ssh_config(config, Path::new("/tmp/config"));
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].blocking);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_commented_forward_agent_ignored() {
        let check = SshHygieneCheck;
        let config = "Host *\n    # ForwardAgent yes\n";
        let findings = check.audit_ssh_config(config, Path::new("/tmp/config"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_base64_decode_prefix() {
        // "openssh-key-v1" header bytes
        let encoded = "b3BlbnNzaC1rZXktdjEA";
        let decoded = base64_decode_prefix(encoded, 32);
        assert!(String::from_utf8_lossy(&decoded).contains("openssh-key-v1"));
    }
}
