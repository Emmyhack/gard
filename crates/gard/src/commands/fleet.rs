//! Fleet command - team-wide compliance over a shared directory
//!
//! Members submit signed scan reports into a shared directory (a synced
//! folder or a git repository); `fleet status` verifies every report's
//! signature, matches signing keys against the team roster, and shows
//! who is green, who is failing, whose report has gone stale, whose
//! suppressions are about to expire, and which findings are new since
//! the member's previous submission.

use crate::cli::FleetSubcommand;
use crate::config;
use crate::error::{GardError, Result};
use crate::report::{verify_report, ReportSigner};
use crate::types::{Policy, Report};
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_AGE_HOURS: u64 = 24;

/// Suppressions expiring within this many days are called out
const SUPPRESSION_WARN_DAYS: i64 = 7;

/// Subdirectory holding each member's previous submission for diffing
const HISTORY_DIR: &str = "history";

pub async fn execute(subcommand: FleetSubcommand) -> Result<i32> {
    let policy = config::load_policy(None)?;
    match subcommand {
        FleetSubcommand::Submit { dir } => submit(&policy, dir).await,
        FleetSubcommand::Status {
            dir,
            max_age_hours,
            json,
        } => status(&policy, dir, max_age_hours, json),
        FleetSubcommand::Dashboard {
            dir,
            max_age_hours,
            output,
        } => dashboard(&policy, dir, max_age_hours, output),
    }
}

async fn submit(policy: &Policy, dir: Option<String>) -> Result<i32> {
    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    fs::create_dir_all(&fleet_dir)?;

    let mut report = super::scan::run_scan(policy, &HashSet::new(), &HashSet::new())?;
    let signer = ReportSigner::new()?;
    signer.sign_report(&mut report)?;

    let file_name = format!(
        "{}@{}.json",
        sanitize(&report.metadata.username),
        sanitize(&report.metadata.hostname)
    );
    let path = fleet_dir.join(&file_name);

    // Keep the outgoing report as the member's previous submission so
    // status can show what changed between scans
    if path.exists() {
        let history_dir = fleet_dir.join(HISTORY_DIR);
        fs::create_dir_all(&history_dir)?;
        fs::rename(&path, history_dir.join(&file_name))?;
    }

    fs::write(&path, serde_json::to_string_pretty(&report)?)?;

    // Keep a previously generated dashboard current with every submission
    let dashboard_path = fleet_dir.join("index.html");
    if dashboard_path.exists() {
        let max_age = policy.fleet.max_age_hours.unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;
        let members = collect_members(policy, &fleet_dir, max_age)?;
        fs::write(&dashboard_path, render_dashboard(&members, max_age))?;
        println!("Dashboard refreshed: {}", dashboard_path.display());
    }

    let status = if report.summary.preflight_passing {
        "PASS".green().bold()
    } else {
        "FAIL".red().bold()
    };
    println!(
        "Submitted {} ({} findings, preflight {}) to {}",
        file_name,
        report.summary.total_findings,
        status,
        fleet_dir.display()
    );
    if fleet_dir.join(".git").exists() {
        println!("Fleet directory is a git repository — remember to commit and push.");
    }

    Ok(if report.summary.preflight_passing {
        0
    } else {
        1
    })
}

/// A suppression as shown in the fleet view
#[derive(serde::Serialize)]
struct SuppressionStatus {
    check_id: String,
    reason: String,
    expires: String,
    days_left: i64,
    expiring_soon: bool,
}

/// One member's row in the fleet view
#[derive(serde::Serialize)]
struct MemberStatus {
    file: String,
    member: String,
    hostname: String,
    signature_valid: bool,
    trusted: Option<String>,
    age_hours: i64,
    stale: bool,
    critical: usize,
    high: usize,
    total_findings: usize,
    preflight_passing: bool,
    suppressions: Vec<SuppressionStatus>,
    new_check_ids: Vec<String>,
    resolved_check_ids: Vec<String>,
}

fn status(
    policy: &Policy,
    dir: Option<String>,
    max_age_hours: Option<u64>,
    json: bool,
) -> Result<i32> {
    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    if !fleet_dir.exists() {
        return Err(GardError::ConfigurationError {
            path: fleet_dir.to_string_lossy().to_string(),
            reason: "Fleet directory does not exist".to_string(),
        });
    }

    let max_age = max_age_hours
        .or(policy.fleet.max_age_hours)
        .unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;

    let members = collect_members(policy, &fleet_dir, max_age)?;

    if members.is_empty() {
        println!(
            "No fleet reports found in {}. Members submit with 'gard fleet submit'.",
            fleet_dir.display()
        );
        return Ok(1);
    }

    let all_green = members
        .iter()
        .all(|m| m.signature_valid && m.preflight_passing && !m.stale);

    if json {
        let payload = serde_json::json!({
            "fleet_dir": fleet_dir.to_string_lossy(),
            "max_age_hours": max_age,
            "all_green": all_green,
            "members": members,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_table(&members, max_age);
        if all_green {
            println!(
                "\n{}",
                "FLEET GREEN — all members passing and fresh."
                    .green()
                    .bold()
            );
        } else {
            println!(
                "\n{}",
                "FLEET NOT GREEN — review the rows above.".red().bold()
            );
        }
    }

    Ok(if all_green { 0 } else { 1 })
}

/// Read and evaluate every member report in the fleet directory
fn collect_members(policy: &Policy, fleet_dir: &Path, max_age: i64) -> Result<Vec<MemberStatus>> {
    let mut members = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(fleet_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    entries.sort();

    for path in entries {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Report>(&content) else {
            tracing::warn!(file = %path.display(), "Skipping unparseable fleet report");
            continue;
        };
        let previous = load_previous(fleet_dir, &path);
        members.push(evaluate_member(
            &path,
            &report,
            previous.as_ref(),
            policy,
            max_age,
        ));
    }

    Ok(members)
}

fn dashboard(
    policy: &Policy,
    dir: Option<String>,
    max_age_hours: Option<u64>,
    output: Option<String>,
) -> Result<i32> {
    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    if !fleet_dir.exists() {
        return Err(GardError::ConfigurationError {
            path: fleet_dir.to_string_lossy().to_string(),
            reason: "Fleet directory does not exist".to_string(),
        });
    }

    let max_age = max_age_hours
        .or(policy.fleet.max_age_hours)
        .unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;

    let members = collect_members(policy, &fleet_dir, max_age)?;
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| fleet_dir.join("index.html"));
    fs::write(&output_path, render_dashboard(&members, max_age))?;

    println!(
        "Dashboard written to {} ({} member report(s)).",
        output_path.display(),
        members.len()
    );
    println!(
        "Open it locally, or serve the fleet directory (e.g. GitHub Pages) to give the team a URL."
    );
    if fleet_dir.join(".git").exists() {
        println!("Fleet directory is a git repository — remember to commit and push.");
    }

    Ok(0)
}

/// Render the fleet view into the self-contained HTML template
fn render_dashboard(members: &[MemberStatus], max_age: i64) -> String {
    let all_green = !members.is_empty()
        && members
            .iter()
            .all(|m| m.signature_valid && m.preflight_passing && !m.stale);

    let payload = serde_json::json!({
        "generated_at": chrono::Utc::now(),
        "max_age_hours": max_age,
        "all_green": all_green,
        "members": members,
    });
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{}".to_string())
        // Prevent a value containing "</script>" from closing the tag
        .replace("</", "<\\/");

    include_str!("fleet_dashboard.html").replace("__GARD_DATA__", &json)
}

fn load_previous(fleet_dir: &Path, current: &Path) -> Option<Report> {
    let file_name = current.file_name()?;
    let previous_path = fleet_dir.join(HISTORY_DIR).join(file_name);
    let content = fs::read_to_string(previous_path).ok()?;
    serde_json::from_str(&content).ok()
}

fn evaluate_member(
    path: &Path,
    report: &Report,
    previous: Option<&Report>,
    policy: &Policy,
    max_age: i64,
) -> MemberStatus {
    let signature_valid = verify_report(report).unwrap_or(false);

    let trusted = report.metadata.public_key.as_ref().and_then(|pk| {
        let pk_hex = pk.strip_prefix("ed25519 ").unwrap_or(pk);
        policy
            .team
            .signers
            .iter()
            .find(|s| s.public_key.eq_ignore_ascii_case(pk_hex))
            .map(|s| s.name.clone())
    });

    let age_hours = (chrono::Utc::now() - report.metadata.timestamp).num_hours();
    let today = chrono::Utc::now().date_naive();

    let suppressions = report
        .metadata
        .active_suppressions
        .iter()
        .map(|s| {
            let days_left = chrono::NaiveDate::parse_from_str(&s.expires, "%Y-%m-%d")
                .map(|d| (d - today).num_days())
                .unwrap_or(0);
            SuppressionStatus {
                check_id: s.check_id.clone(),
                reason: s.reason.clone(),
                expires: s.expires.clone(),
                days_left,
                expiring_soon: days_left <= SUPPRESSION_WARN_DAYS,
            }
        })
        .collect();

    let (new_check_ids, resolved_check_ids) = match previous {
        Some(prev) => diff_check_ids(report, prev),
        None => (Vec::new(), Vec::new()),
    };

    MemberStatus {
        file: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        member: trusted
            .clone()
            .unwrap_or_else(|| report.metadata.username.clone()),
        hostname: report.metadata.hostname.clone(),
        signature_valid,
        trusted,
        age_hours,
        stale: age_hours > max_age,
        critical: report.summary.critical,
        high: report.summary.high,
        total_findings: report.summary.total_findings,
        preflight_passing: report.summary.preflight_passing,
        suppressions,
        new_check_ids,
        resolved_check_ids,
    }
}

/// Check ids that appeared in, or disappeared from, the current report
/// relative to the previous one
fn diff_check_ids(current: &Report, previous: &Report) -> (Vec<String>, Vec<String>) {
    let current_ids: HashSet<&str> = current
        .findings
        .iter()
        .map(|f| f.check_id.as_str())
        .collect();
    let previous_ids: HashSet<&str> = previous
        .findings
        .iter()
        .map(|f| f.check_id.as_str())
        .collect();

    let mut new_ids: Vec<String> = current_ids
        .difference(&previous_ids)
        .map(|s| s.to_string())
        .collect();
    let mut resolved: Vec<String> = previous_ids
        .difference(&current_ids)
        .map(|s| s.to_string())
        .collect();
    new_ids.sort();
    resolved.sort();
    (new_ids, resolved)
}

fn print_table(members: &[MemberStatus], max_age: i64) {
    println!(
        "{:<16} {:<14} {:<6} {:<8} {:<5} {:<5} {:<9} STATUS",
        "MEMBER", "HOST", "AGE", "SIG", "CRIT", "HIGH", "TRUSTED"
    );
    for m in members {
        let status = if !m.signature_valid {
            "BAD SIG".red().bold()
        } else if m.stale {
            "STALE".yellow().bold()
        } else if !m.preflight_passing {
            "FAIL".red().bold()
        } else {
            "PASS".green().bold()
        };
        println!(
            "{:<16} {:<14} {:<6} {:<8} {:<5} {:<5} {:<9} {}",
            m.member,
            m.hostname,
            format!("{}h", m.age_hours),
            if m.signature_valid {
                "valid"
            } else {
                "INVALID"
            },
            m.critical,
            m.high,
            m.trusted.as_deref().unwrap_or("-"),
            status
        );

        for s in &m.suppressions {
            if s.days_left < 0 {
                continue;
            }
            let line = format!(
                "suppression '{}' expires in {} day(s) ({})",
                s.check_id, s.days_left, s.reason
            );
            if s.expiring_soon {
                println!("  {} {}", "!".yellow().bold(), line.yellow());
            } else {
                println!("  - {}", line);
            }
        }
        if !m.new_check_ids.is_empty() {
            println!(
                "  {} new since previous report: {}",
                "!".red().bold(),
                m.new_check_ids.join(", ").red()
            );
        }
        if !m.resolved_check_ids.is_empty() {
            println!(
                "  {} resolved since previous report: {}",
                "+".green(),
                m.resolved_check_ids.join(", ")
            );
        }
    }
    println!("\nStale threshold: {}h", max_age);
}

fn resolve_fleet_dir(policy: &Policy, dir: Option<String>) -> Result<PathBuf> {
    dir.or_else(|| policy.fleet.dir.clone())
        .map(PathBuf::from)
        .ok_or_else(|| GardError::ConfigurationError {
            path: "policy.toml".to_string(),
            reason: "No fleet directory given. Pass --dir or set [fleet] dir in policy."
                .to_string(),
        })
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{current_platform, Finding, ReportMetadata, ReportSummary, Severity};

    fn report_with_checks(check_ids: &[&str]) -> Report {
        let findings: Vec<Finding> = check_ids
            .iter()
            .map(|id| Finding {
                id: format!("f_{}", id),
                check_id: id.to_string(),
                check_name: id.to_string(),
                severity: Severity::High,
                platform: current_platform(),
                description: "x".to_string(),
                remediation: "y".to_string(),
                blocking: true,
                timestamp: chrono::Utc::now(),
                details: serde_json::json!({}),
            })
            .collect();
        Report {
            metadata: ReportMetadata {
                version: "1.0".to_string(),
                gard_version: "0.1.0".to_string(),
                timestamp: chrono::Utc::now(),
                hostname: "h".to_string(),
                username: "u".to_string(),
                platform: current_platform(),
                platform_version: "v".to_string(),
                scan_duration_ms: 1,
                active_suppressions: Vec::new(),
                signed: false,
                signature: None,
                public_key: None,
            },
            summary: ReportSummary::from_findings(&findings),
            findings,
        }
    }

    #[test]
    fn test_diff_detects_new_and_resolved() {
        let previous = report_with_checks(&["ssh-key-hygiene"]);
        let current = report_with_checks(&["ssh-key-hygiene", "open-ports-remote-access"]);
        let (new_ids, resolved) = diff_check_ids(&current, &previous);
        assert_eq!(new_ids, vec!["open-ports-remote-access".to_string()]);
        assert!(resolved.is_empty());

        let (new_ids, resolved) = diff_check_ids(&previous, &current);
        assert!(new_ids.is_empty());
        assert_eq!(resolved, vec!["open-ports-remote-access".to_string()]);
    }

    #[test]
    fn test_render_dashboard_embeds_data() {
        let report = report_with_checks(&["ssh-key-hygiene"]);
        let member = evaluate_member(
            Path::new("/tmp/u@h.json"),
            &report,
            None,
            &crate::types::Policy::default(),
            24,
        );
        let html = render_dashboard(&[member], 24);
        assert!(html.contains("ssh-key-hygiene") || html.contains("\"member\""));
        assert!(html.contains("Gard Fleet"));
        assert!(!html.contains("__GARD_DATA__"));
    }

    #[test]
    fn test_diff_no_changes() {
        let a = report_with_checks(&["ssh-key-hygiene"]);
        let b = report_with_checks(&["ssh-key-hygiene"]);
        let (new_ids, resolved) = diff_check_ids(&a, &b);
        assert!(new_ids.is_empty());
        assert!(resolved.is_empty());
    }
}
