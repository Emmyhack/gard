//! Core data types for Gard
//!
//! Defines the structures for findings, reports, severity levels, and
//! other fundamental types used throughout Gard.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    // Declaration order defines derived Ord: Info < Low < ... < Critical
    #[serde(rename = "INFO")]
    Info,
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "CRITICAL")]
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    pub fn color_code(&self) -> &str {
        match self {
            Severity::Critical => "\x1b[31m", // Red
            Severity::High => "\x1b[31m",     // Red
            Severity::Medium => "\x1b[33m",   // Yellow
            Severity::Low => "\x1b[36m",      // Cyan
            Severity::Info => "\x1b[34m",     // Blue
        }
    }

    pub fn color_reset(&self) -> &str {
        "\x1b[0m"
    }
}

/// Supported platforms for checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    #[serde(rename = "macos")]
    MacOS,
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "windows")]
    Windows,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Windows => write!(f, "Windows"),
        }
    }
}

/// Current platform detection
pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Linux // Default fallback
    }
}

/// A single security finding from a check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding
    pub id: String,

    /// Check module identifier
    pub check_id: String,

    /// Human-readable check name
    pub check_name: String,

    /// Severity of finding
    pub severity: Severity,

    /// Platform this finding applies to
    pub platform: Platform,

    /// Detailed description of finding
    pub description: String,

    /// Remediation recommendation
    pub remediation: String,

    /// Whether this finding blocks preflight
    pub blocking: bool,

    /// When this finding was discovered
    pub timestamp: DateTime<Utc>,

    /// Check-specific details in JSON
    pub details: serde_json::Value,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report schema version
    pub version: String,

    /// Gard version that generated this report
    pub gard_version: String,

    /// When report was generated
    pub timestamp: DateTime<Utc>,

    /// Hostname where report was generated
    pub hostname: String,

    /// Username who ran Gard
    pub username: String,

    /// Platform
    pub platform: Platform,

    /// Platform version (OS version)
    pub platform_version: String,

    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,

    /// Suppressions that were active (unexpired) at scan time
    #[serde(default)]
    pub active_suppressions: Vec<Suppression>,

    /// Whether report was signed
    pub signed: bool,

    /// Report signature (optional, if signed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Public key for verification (optional, if signed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// Report summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total number of findings
    pub total_findings: usize,

    /// Count of CRITICAL findings
    pub critical: usize,

    /// Count of HIGH findings
    pub high: usize,

    /// Count of MEDIUM findings
    pub medium: usize,

    /// Count of LOW findings
    pub low: usize,

    /// Count of INFO findings
    pub info: usize,

    /// Whether preflight would pass
    pub preflight_passing: bool,

    /// Number of blocking findings
    pub blocking_findings: usize,
}

impl ReportSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = ReportSummary {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            preflight_passing: true,
            blocking_findings: 0,
        };

        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }

            if finding.blocking {
                summary.blocking_findings += 1;
                summary.preflight_passing = false;
            }
        }

        summary
    }
}

/// Complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report metadata
    pub metadata: ReportMetadata,

    /// Report summary statistics
    pub summary: ReportSummary,

    /// All findings in report
    pub findings: Vec<Finding>,
}

/// Policy enforcement level for checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementLevel {
    #[serde(rename = "enforce")]
    Enforce,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "silent")]
    Silent,
}

/// Suppression entry in policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// Check ID to suppress
    pub check_id: String,

    /// Justification for suppression
    pub reason: String,

    /// Expiration date (YYYY-MM-DD)
    pub expires: String,
}

/// Gard policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Per-check enforcement levels
    pub checks: std::collections::HashMap<String, String>,

    /// Suppression list
    #[serde(default)]
    pub suppressions: Vec<Suppression>,

    /// Hardware wallet requirements
    #[serde(default)]
    pub hardware_wallet: HardwareWalletPolicy,

    /// Solana-specific configuration
    #[serde(default)]
    pub solana: SolanaPolicy,

    /// Nonce configuration
    #[serde(default)]
    pub nonce: NoncePolicy,

    /// Team roster of trusted signer keys
    #[serde(default)]
    pub team: TeamPolicy,

    /// Fleet compliance configuration
    #[serde(default)]
    pub fleet: FleetPolicy,

    /// Metadata
    #[serde(default)]
    pub metadata: PolicyMetadata,
}

/// Trusted signer roster for attestation and fleet verification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamPolicy {
    #[serde(default)]
    pub signers: Vec<TeamSigner>,
}

/// A team member's registered signing identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSigner {
    /// Member name
    pub name: String,

    /// Ed25519 public key (hex, from 'gard report --export-key')
    pub public_key: String,
}

/// Fleet compliance configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetPolicy {
    /// Shared directory where members submit signed reports
    pub dir: Option<String>,

    /// Reports older than this are flagged stale (default 24)
    pub max_age_hours: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareWalletPolicy {
    pub required: bool,
    pub minimum_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolanaPolicy {
    pub trusted_rpc_endpoints: Vec<String>,
    pub self_hosted_rpc_required: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoncePolicy {
    pub expected_authority: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub version: String,
    pub created: Option<String>,
    pub modified: Option<String>,
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }

    #[test]
    fn test_report_summary_from_findings() {
        let findings = vec![
            Finding {
                id: "f_001".to_string(),
                check_id: "test_check".to_string(),
                check_name: "Test Check".to_string(),
                severity: Severity::Critical,
                platform: current_platform(),
                description: "Test finding".to_string(),
                remediation: "Fix it".to_string(),
                blocking: true,
                timestamp: Utc::now(),
                details: serde_json::json!({}),
            },
            Finding {
                id: "f_002".to_string(),
                check_id: "test_check".to_string(),
                check_name: "Test Check".to_string(),
                severity: Severity::Medium,
                platform: current_platform(),
                description: "Test finding 2".to_string(),
                remediation: "Fix it".to_string(),
                blocking: false,
                timestamp: Utc::now(),
                details: serde_json::json!({}),
            },
        ];

        let summary = ReportSummary::from_findings(&findings);

        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.blocking_findings, 1);
        assert!(!summary.preflight_passing);
    }
}
