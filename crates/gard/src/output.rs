/// Output formatting for Gard reports and findings
///
/// Provides human-readable and machine-readable output formats
/// for scan results and preflight checks.

use crate::types::{Finding, Report, ReportSummary};
use colored::Colorize;
use serde_json::json;

/// Format for report output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Plaintext,
    Json,
    JsonPretty,
    Markdown,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "plaintext" | "text" => Some(OutputFormat::Plaintext),
            "json" => Some(OutputFormat::Json),
            "json-pretty" | "pretty" => Some(OutputFormat::JsonPretty),
            "markdown" | "md" => Some(OutputFormat::Markdown),
            _ => None,
        }
    }
}

/// Format findings in plaintext with colors
pub fn format_findings_plaintext(findings: &[Finding], use_color: bool) -> String {
    let mut output = String::new();

    for (idx, finding) in findings.iter().enumerate() {
        if idx > 0 {
            output.push_str("\n---\n\n");
        }

        let severity_str = if use_color {
            format!(
                "{}{}{}",
                finding.severity.color_code(),
                finding.severity,
                finding.severity.color_reset()
            )
        } else {
            finding.severity.to_string()
        };

        output.push_str(&format!("[{}] {}\n", severity_str, finding.check_name));
        output.push_str(&format!("Module: {}\n", finding.check_id));
        output.push_str(&format!("Platform: {}\n", finding.platform));
        output.push_str(&format!("Blocking: {}\n\n", if finding.blocking { "Yes" } else { "No" }));

        output.push_str("Description:\n");
        for line in finding.description.lines() {
            output.push_str(&format!("  {}\n", line));
        }
        output.push('\n');

        output.push_str("Remediation:\n");
        for line in finding.remediation.lines() {
            output.push_str(&format!("  {}\n", line));
        }
        output.push('\n');

        if !finding.details.is_null() {
            output.push_str("Details:\n");
            if let Ok(details_str) = serde_json::to_string_pretty(&finding.details) {
                for line in details_str.lines() {
                    output.push_str(&format!("  {}\n", line));
                }
            }
        }
    }

    output
}

/// Format report summary in plaintext
pub fn format_summary_plaintext(summary: &ReportSummary, use_color: bool) -> String {
    let mut output = String::new();

    output.push_str("Summary\n");
    output.push_str("-------\n");
    output.push_str(&format!("Total Findings: {}\n", summary.total_findings));

    if use_color {
        if summary.critical > 0 {
            output.push_str(&format!(
                "  {}\n",
                format!("CRITICAL: {}", summary.critical).red()
            ));
        }
        if summary.high > 0 {
            output.push_str(&format!("  {}\n", format!("HIGH: {}", summary.high).red()));
        }
        if summary.medium > 0 {
            output.push_str(&format!(
                "  {}\n",
                format!("MEDIUM: {}", summary.medium).yellow()
            ));
        }
        if summary.low > 0 {
            output.push_str(&format!(
                "  {}\n",
                format!("LOW: {}", summary.low).cyan()
            ));
        }
    } else {
        if summary.critical > 0 {
            output.push_str(&format!("  CRITICAL: {}\n", summary.critical));
        }
        if summary.high > 0 {
            output.push_str(&format!("  HIGH: {}\n", summary.high));
        }
        if summary.medium > 0 {
            output.push_str(&format!("  MEDIUM: {}\n", summary.medium));
        }
        if summary.low > 0 {
            output.push_str(&format!("  LOW: {}\n", summary.low));
        }
    }

    output.push('\n');

    let status_str = if summary.preflight_passing {
        "PASSED"
    } else {
        "FAILED"
    };

    if use_color {
        let status = if summary.preflight_passing {
            status_str.green()
        } else {
            status_str.red()
        };
        output.push_str(&format!("Preflight Status: {}", status));
    } else {
        output.push_str(&format!("Preflight Status: {}", status_str));
    }

    output
}

/// Format report in JSON
pub fn format_report_json(report: &Report) -> String {
    serde_json::to_string(&json!({
        "metadata": report.metadata,
        "summary": report.summary,
        "findings": report.findings,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Format report in pretty-printed JSON
pub fn format_report_json_pretty(report: &Report) -> String {
    serde_json::to_string_pretty(&json!({
        "metadata": report.metadata,
        "summary": report.summary,
        "findings": report.findings,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Format report in Markdown
pub fn format_report_markdown(report: &Report) -> String {
    let mut output = String::new();

    output.push_str("# Gard Scan Report\n\n");
    output.push_str(&format!(
        "Generated: {}\n",
        report.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    output.push_str(&format!("Hostname: {}\n", report.metadata.hostname));
    output.push_str(&format!("Platform: {} {}\n\n", report.metadata.platform, report.metadata.platform_version));

    output.push_str("## Summary\n\n");
    output.push_str(&format!("- Total Findings: {}\n", report.summary.total_findings));
    output.push_str(&format!("  - CRITICAL: {}\n", report.summary.critical));
    output.push_str(&format!("  - HIGH: {}\n", report.summary.high));
    output.push_str(&format!("  - MEDIUM: {}\n", report.summary.medium));
    output.push_str(&format!("  - LOW: {}\n", report.summary.low));
    output.push_str(&format!("\nPreflight Status: {}\n\n", if report.summary.preflight_passing { "PASSED" } else { "FAILED" }));

    output.push_str("## Findings\n\n");

    for finding in &report.findings {
        output.push_str(&format!("### [{}] {}\n\n", finding.severity, finding.check_name));
        output.push_str(&format!("**Module:** {}\n\n", finding.check_id));
        output.push_str(&format!("**Severity:** {}\n\n", finding.severity));
        output.push_str(&format!("**Blocking:** {}\n\n", if finding.blocking { "Yes" } else { "No" }));

        output.push_str("**Description:**\n\n");
        output.push_str(&format!("{}\n\n", finding.description));

        output.push_str("**Remediation:**\n\n");
        output.push_str(&format!("{}\n\n", finding.remediation));

        if !finding.details.is_null() {
            output.push_str("**Details:**\n\n");
            output.push_str(&format!("```json\n{}\n```\n\n", serde_json::to_string_pretty(&finding.details).unwrap_or_default()));
        }
    }

    output
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("plaintext"), Some(OutputFormat::Plaintext));
        assert_eq!(OutputFormat::from_str("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("json-pretty"), Some(OutputFormat::JsonPretty));
        assert_eq!(OutputFormat::from_str("markdown"), Some(OutputFormat::Markdown));
        assert_eq!(OutputFormat::from_str("invalid"), None);
    }
}
