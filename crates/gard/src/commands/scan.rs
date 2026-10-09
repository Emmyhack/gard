//! Scan command - runs complete machine audit
//!
//! Runs all registered checks (subject to --skip/--only and policy
//! enforcement levels), produces a signed report, caches it, and prints
//! it in the requested format.

use crate::checks::CheckRegistry;
use crate::cli::ScanCommand;
use crate::config;
use crate::error::{GardError, Result};
use crate::output::{self, OutputFormat};
use crate::report::ReportSigner;
use crate::types::{current_platform, Finding, Policy, Report, ReportMetadata, ReportSummary};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

pub async fn execute(cmd: ScanCommand) -> Result<i32> {
    let format =
        OutputFormat::from_str(&cmd.format).ok_or_else(|| GardError::InvalidReportFormat {
            reason: format!("Unknown output format: {}", cmd.format),
        })?;

    let policy = config::load_policy(None)?;
    let skip = parse_check_list(cmd.skip.as_deref());
    let only = parse_check_list(cmd.only.as_deref());

    let mut report = run_scan(&policy, &skip, &only)?;

    if !cmd.no_sign {
        let signer = ReportSigner::new()?;
        signer.sign_report(&mut report)?;
    }

    save_last_scan(&report)?;

    let rendered = match format {
        OutputFormat::Plaintext => {
            let mut text = output::format_findings_plaintext(&report.findings, true);
            if !report.findings.is_empty() {
                text.push('\n');
            }
            text.push_str(&output::format_summary_plaintext(&report.summary, true));
            text.push('\n');
            text
        },
        OutputFormat::Json => output::format_report_json(&report),
        OutputFormat::JsonPretty => output::format_report_json_pretty(&report),
        OutputFormat::Markdown => output::format_report_markdown(&report),
    };

    if let Some(path) = cmd.output {
        fs::write(&path, &rendered)?;
        println!("Report written to {}", path);
    } else {
        println!("{}", rendered);
    }

    Ok(if report.findings.is_empty() { 0 } else { 1 })
}

/// Run all applicable checks and assemble a report with policy applied
pub fn run_scan(policy: &Policy, skip: &HashSet<String>, only: &HashSet<String>) -> Result<Report> {
    let start = Instant::now();
    let registry = CheckRegistry::new();
    let platform = current_platform();

    let mut findings = Vec::new();
    for check in registry.for_platform(platform) {
        let id = check.id().to_string();
        if skip.contains(&id) {
            continue;
        }
        if !only.is_empty() && !only.contains(&id) {
            continue;
        }
        if policy.checks.get(&id).map(String::as_str) == Some("silent") {
            continue;
        }
        match check.run() {
            Ok(check_findings) => findings.extend(check_findings),
            Err(e) => {
                tracing::warn!(check_id = %id, error = %e, "Check failed");
            },
        }
    }

    apply_policy(&mut findings, policy);
    // Most severe first
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.check_id.cmp(&b.check_id))
    });

    let summary = ReportSummary::from_findings(&findings);
    let mut metadata = build_metadata(start.elapsed().as_millis() as u64);
    metadata.active_suppressions = active_suppressions(policy);

    Ok(Report {
        metadata,
        summary,
        findings,
    })
}

/// Suppressions from policy that have not yet expired
pub fn active_suppressions(policy: &Policy) -> Vec<crate::types::Suppression> {
    let today = chrono::Utc::now().date_naive();
    policy
        .suppressions
        .iter()
        .filter(|s| {
            chrono::NaiveDate::parse_from_str(&s.expires, "%Y-%m-%d")
                .map(|d| d >= today)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Apply enforcement levels and unexpired suppressions from policy
fn apply_policy(findings: &mut Vec<Finding>, policy: &Policy) {
    let suppressed: HashSet<String> = active_suppressions(policy)
        .into_iter()
        .map(|s| s.check_id)
        .collect();

    findings.retain(|f| !suppressed.contains(f.check_id.as_str()));

    for finding in findings.iter_mut() {
        if policy.checks.get(&finding.check_id).map(String::as_str) == Some("warn") {
            finding.blocking = false;
        }
    }
}

fn build_metadata(scan_duration_ms: u64) -> ReportMetadata {
    ReportMetadata {
        version: "1.0".to_string(),
        gard_version: crate::VERSION.to_string(),
        timestamp: chrono::Utc::now(),
        hostname: sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string()),
        username: std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string()),
        platform: current_platform(),
        platform_version: sysinfo::System::os_version().unwrap_or_else(|| "unknown".to_string()),
        scan_duration_ms,
        active_suppressions: Vec::new(),
        signed: false,
        signature: None,
        public_key: None,
    }
}

pub fn parse_check_list(input: Option<&str>) -> HashSet<String> {
    input
        .map(|s| {
            s.split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Cache path for the most recent scan
pub fn last_scan_path() -> Result<PathBuf> {
    crate::paths::last_scan_path()
}

fn save_last_scan(report: &Report) -> Result<()> {
    let path = last_scan_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report)?;
    fs::write(&path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_check_list() {
        let parsed = parse_check_list(Some("a, b,c"));
        assert_eq!(parsed.len(), 3);
        assert!(parsed.contains("b"));
        assert!(parse_check_list(None).is_empty());
    }

    #[test]
    fn test_apply_policy_warn_downgrades_blocking() {
        let mut policy = Policy::default();
        policy
            .checks
            .insert("test-check".to_string(), "warn".to_string());

        let mut findings = vec![Finding {
            id: "f_1".to_string(),
            check_id: "test-check".to_string(),
            check_name: "Test".to_string(),
            severity: crate::types::Severity::High,
            platform: current_platform(),
            description: "x".to_string(),
            remediation: "y".to_string(),
            blocking: true,
            timestamp: chrono::Utc::now(),
            details: serde_json::json!({}),
        }];

        apply_policy(&mut findings, &policy);
        assert!(!findings[0].blocking);
    }

    #[test]
    fn test_apply_policy_suppression_removes_finding() {
        let mut policy = Policy::default();
        policy.suppressions.push(crate::types::Suppression {
            check_id: "test-check".to_string(),
            reason: "test".to_string(),
            expires: "2099-01-01".to_string(),
        });

        let mut findings = vec![Finding {
            id: "f_1".to_string(),
            check_id: "test-check".to_string(),
            check_name: "Test".to_string(),
            severity: crate::types::Severity::High,
            platform: current_platform(),
            description: "x".to_string(),
            remediation: "y".to_string(),
            blocking: true,
            timestamp: chrono::Utc::now(),
            details: serde_json::json!({}),
        }];

        apply_policy(&mut findings, &policy);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_expired_suppression_ignored() {
        let mut policy = Policy::default();
        policy.suppressions.push(crate::types::Suppression {
            check_id: "test-check".to_string(),
            reason: "test".to_string(),
            expires: "2020-01-01".to_string(),
        });

        let mut findings = vec![Finding {
            id: "f_1".to_string(),
            check_id: "test-check".to_string(),
            check_name: "Test".to_string(),
            severity: crate::types::Severity::High,
            platform: current_platform(),
            description: "x".to_string(),
            remediation: "y".to_string(),
            blocking: true,
            timestamp: chrono::Utc::now(),
            details: serde_json::json!({}),
        }];

        apply_policy(&mut findings, &policy);
        assert_eq!(findings.len(), 1);
    }
}
