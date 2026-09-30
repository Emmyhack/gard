//! Report command - format and export scan results
//!
//! Loads the last scan (or --input file), optionally verifies its
//! signature, and renders it in the requested format.

use crate::cli::ReportCommand;
use crate::error::{GardError, Result};
use crate::output::{self, OutputFormat};
use crate::report::{verify_report, ReportSigner};
use crate::types::{Report, Severity};
use std::fs;

pub async fn execute(cmd: ReportCommand) -> Result<i32> {
    if cmd.export_key {
        let signer = ReportSigner::new()?;
        println!("ed25519 {}", signer.public_key_hex());
        return Ok(0);
    }

    let report_path = match cmd.input {
        Some(ref path) => std::path::PathBuf::from(path),
        None => super::scan::last_scan_path()?,
    };

    if !report_path.exists() {
        return Err(GardError::InvalidReportFormat {
            reason: format!(
                "No report found at {}. Run 'gard scan' first.",
                report_path.display()
            ),
        });
    }

    let content = fs::read_to_string(&report_path)?;
    let mut report: Report =
        serde_json::from_str(&content).map_err(|e| GardError::InvalidReportFormat {
            reason: format!("Could not parse report: {}", e),
        })?;

    if cmd.verify {
        let valid = verify_report(&report)?;
        if valid {
            println!("Signature: VALID");
        } else {
            println!("Signature: INVALID or unsigned");
            return Ok(1);
        }
    }

    if let Some(ref filter) = cmd.filter {
        let min_severity = parse_severity(filter)?;
        report.findings.retain(|f| f.severity >= min_severity);
    }

    let format =
        OutputFormat::from_str(&cmd.format).ok_or_else(|| GardError::InvalidReportFormat {
            reason: format!("Unknown output format: {}", cmd.format),
        })?;

    let rendered = if cmd.summary {
        output::format_summary_plaintext(&report.summary, cmd.output.is_none())
    } else {
        match format {
            OutputFormat::Plaintext => {
                let mut text =
                    output::format_findings_plaintext(&report.findings, cmd.output.is_none());
                if !report.findings.is_empty() {
                    text.push('\n');
                }
                text.push_str(&output::format_summary_plaintext(
                    &report.summary,
                    cmd.output.is_none(),
                ));
                text
            },
            OutputFormat::Json => output::format_report_json(&report),
            OutputFormat::JsonPretty => output::format_report_json_pretty(&report),
            OutputFormat::Markdown => output::format_report_markdown(&report),
        }
    };

    if let Some(path) = cmd.output {
        fs::write(&path, &rendered)?;
        println!("Report written to {}", path);
    } else {
        println!("{}", rendered);
    }

    Ok(0)
}

fn parse_severity(input: &str) -> Result<Severity> {
    match input.to_uppercase().as_str() {
        "CRITICAL" => Ok(Severity::Critical),
        "HIGH" => Ok(Severity::High),
        "MEDIUM" => Ok(Severity::Medium),
        "LOW" => Ok(Severity::Low),
        "INFO" => Ok(Severity::Info),
        other => Err(GardError::InvalidReportFormat {
            reason: format!("Unknown severity filter: {}", other),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical").unwrap(), Severity::Critical);
        assert_eq!(parse_severity("HIGH").unwrap(), Severity::High);
        assert!(parse_severity("bogus").is_err());
    }
}
