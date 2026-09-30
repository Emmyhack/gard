//! Attest command - produce a signed ceremony attestation
//!
//! Runs the full check suite and, only if preflight passes, writes a
//! signed attestation bound to the given ceremony id. A machine with
//! blocking findings cannot produce an attestation; there is no
//! override, because the artifact exists to convince co-signers.

use crate::attestation::Attestation;
use crate::cli::AttestCommand;
use crate::config;
use crate::error::Result;
use crate::report::ReportSigner;
use colored::Colorize;
use std::collections::HashSet;
use std::fs;

pub async fn execute(cmd: AttestCommand) -> Result<i32> {
    let policy = config::load_policy(None)?;
    let report = super::scan::run_scan(&policy, &HashSet::new(), &HashSet::new())?;

    let blocking_check_ids: Vec<String> = {
        let mut ids: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.blocking)
            .map(|f| f.check_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    };

    if !blocking_check_ids.is_empty() {
        if cmd.json {
            let payload = serde_json::json!({
                "attested": false,
                "ceremony_id": cmd.ceremony,
                "blocking_check_ids": blocking_check_ids,
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            eprintln!(
                "{} Machine has blocking findings from: {}",
                "ATTESTATION REFUSED.".red().bold(),
                blocking_check_ids.join(", ")
            );
            eprintln!("Run 'gard preflight' for details and remediation.");
        }
        return Ok(1);
    }

    let signer_name = cmd.signer.unwrap_or_else(|| {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string())
    });

    let mut attestation = Attestation::new(
        cmd.ceremony.clone(),
        signer_name,
        report.summary.clone(),
        blocking_check_ids,
        cmd.valid_for.max(1),
    );
    let signer = ReportSigner::new()?;
    attestation.sign(&signer)?;

    let output_path = cmd
        .output
        .unwrap_or_else(|| format!("gard-attestation-{}.json", sanitize(&cmd.ceremony)));
    fs::write(&output_path, serde_json::to_string_pretty(&attestation)?)?;

    if cmd.json {
        let payload = serde_json::json!({
            "attested": true,
            "ceremony_id": attestation.ceremony_id,
            "signer_name": attestation.signer_name,
            "expires_at": attestation.expires_at,
            "output": output_path,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "{} Ceremony '{}' attestation written to {}",
            "ATTESTED.".green().bold(),
            attestation.ceremony_id,
            output_path
        );
        println!(
            "Valid until {} — share with co-signers; they verify with:\n  gard verify {} --ceremony {}",
            attestation.expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
            output_path,
            attestation.ceremony_id
        );
    }

    Ok(0)
}

/// Keep ceremony-derived filenames shell- and filesystem-safe
fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
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

    #[test]
    fn test_sanitize_ceremony_id() {
        assert_eq!(sanitize("prop-42"), "prop-42");
        assert_eq!(sanitize("tx/9a?b"), "tx_9a_b");
    }
}
