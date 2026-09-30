//! Fleet command - team-wide compliance over a shared directory
//!
//! Members submit signed scan reports into a shared directory (a synced
//! folder or a git repository); `fleet status` verifies every report's
//! signature, matches signing keys against the team roster, and shows
//! who is green, who is failing, and whose report has gone stale.

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

pub async fn execute(subcommand: FleetSubcommand) -> Result<i32> {
    let policy = config::load_policy(None)?;
    match subcommand {
        FleetSubcommand::Submit { dir } => submit(&policy, dir).await,
        FleetSubcommand::Status {
            dir,
            max_age_hours,
            json,
        } => status(&policy, dir, max_age_hours, json),
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
    fs::write(&path, serde_json::to_string_pretty(&report)?)?;

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

    let mut members = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(&fleet_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
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
        members.push(evaluate_member(&path, &report, policy, max_age));
    }

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

fn evaluate_member(path: &Path, report: &Report, policy: &Policy, max_age: i64) -> MemberStatus {
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
    }
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
