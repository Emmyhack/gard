//! Preflight command - mandatory pre-signing checklist
//!
//! Runs the blocking subset of checks. Exit 0 means the machine is clear
//! to sign; exit 1 means blocking findings exist. --override records a
//! justification and allows signing to proceed.

use crate::cli::PreflightCommand;
use crate::config;
use crate::error::Result;
use crate::output;
use crate::types::Severity;
use colored::Colorize;
use std::collections::HashSet;
use std::fs;

pub async fn execute(cmd: PreflightCommand) -> Result<i32> {
    let policy = config::load_policy(None)?;
    let report = super::scan::run_scan(&policy, &HashSet::new(), &HashSet::new())?;

    let blocking: Vec<_> = report.findings.iter().filter(|f| f.blocking).collect();
    let warnings: Vec<_> = report.findings.iter().filter(|f| !f.blocking).collect();

    if cmd.json {
        let payload = serde_json::json!({
            "preflight_passed": blocking.is_empty(),
            "blocking_findings": blocking.len(),
            "warning_findings": warnings.len(),
            "override_reason": cmd.override_reason,
            "findings": report.findings,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_human_output(&report.findings, &blocking, &warnings, cmd.verbose);
    }

    if blocking.is_empty() {
        if !cmd.json {
            println!("\n{}", "PREFLIGHT PASSED — clear to sign.".green().bold());
        }
        return Ok(0);
    }

    if let Some(reason) = cmd.override_reason {
        if !cmd.confirm {
            if !cmd.json {
                eprintln!(
                    "\n{}",
                    "Override requires explicit --confirm to proceed.".yellow()
                );
            }
            return Ok(1);
        }
        record_override(&reason, blocking.len())?;
        if !cmd.json {
            println!(
                "\n{} Override recorded: {}",
                "PREFLIGHT OVERRIDDEN.".yellow().bold(),
                reason
            );
        }
        return Ok(0);
    }

    if !cmd.json {
        println!(
            "\n{} {} blocking finding(s) must be addressed before signing.",
            "PREFLIGHT FAILED.".red().bold(),
            blocking.len()
        );
    }
    Ok(1)
}

fn print_human_output(
    all: &[crate::types::Finding],
    blocking: &[&crate::types::Finding],
    warnings: &[&crate::types::Finding],
    verbose: bool,
) {
    println!("Gard Preflight — Pre-Signing Checklist");
    println!("======================================\n");

    if all.is_empty() {
        println!("No findings. All checks passed.");
        return;
    }

    if !blocking.is_empty() {
        println!("{}", "Blocking findings:".red().bold());
        for finding in blocking {
            print_finding_line(finding);
        }
        println!();
    }

    if !warnings.is_empty() {
        println!("{}", "Warnings (non-blocking):".yellow().bold());
        for finding in warnings {
            print_finding_line(finding);
        }
    }

    if verbose {
        let owned: Vec<crate::types::Finding> = all.to_vec();
        println!("\nDetails\n-------\n");
        println!("{}", output::format_findings_plaintext(&owned, true));
    }
}

fn print_finding_line(finding: &crate::types::Finding) {
    let severity = match finding.severity {
        Severity::Critical | Severity::High => finding.severity.to_string().red(),
        Severity::Medium => finding.severity.to_string().yellow(),
        _ => finding.severity.to_string().normal(),
    };
    println!("  [{}] {}", severity, finding.description);
}

/// Append override justifications to an audit log for later review
fn record_override(reason: &str, blocking_count: usize) -> Result<()> {
    let log_path = crate::paths::override_log_path()?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let entry = format!(
        "{} override blocking_findings={} reason={:?}\n",
        chrono::Utc::now().to_rfc3339(),
        blocking_count,
        reason
    );
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    file.write_all(entry.as_bytes())?;
    Ok(())
}
