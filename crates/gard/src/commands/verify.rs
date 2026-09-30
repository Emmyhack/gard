//! Verify command - check a co-signer's ceremony attestation
//!
//! Verifies signature, freshness, ceremony binding, and posture, and
//! matches the signing key against the trusted team roster when one is
//! configured. Exit 0 only when the attestation is acceptable.

use crate::attestation::{verify_attestation, Attestation};
use crate::cli::VerifyCommand;
use crate::config;
use crate::error::{GardError, Result};
use colored::Colorize;
use std::fs;

pub async fn execute(cmd: VerifyCommand) -> Result<i32> {
    let content = fs::read_to_string(&cmd.file)?;
    let attestation: Attestation =
        serde_json::from_str(&content).map_err(|e| GardError::InvalidReportFormat {
            reason: format!("Could not parse attestation: {}", e),
        })?;

    let policy = config::load_policy(None)?;
    let roster: Vec<(String, String)> = policy
        .team
        .signers
        .iter()
        .map(|s| (s.name.clone(), s.public_key.clone()))
        .collect();

    let outcome = verify_attestation(&attestation, cmd.ceremony.as_deref(), &roster)?;

    // Trust is enforced when explicitly requested, or automatically once
    // a team roster exists: an unknown key on a rostered team is a red flag.
    let require_trusted = cmd.require_trusted || !roster.is_empty();
    let acceptable = outcome.acceptable(require_trusted);

    if cmd.json {
        let payload = serde_json::json!({
            "acceptable": acceptable,
            "ceremony_id": attestation.ceremony_id,
            "signer_name": attestation.signer_name,
            "hostname": attestation.hostname,
            "issued_at": attestation.issued_at,
            "expires_at": attestation.expires_at,
            "checks": outcome,
            "trust_enforced": require_trusted,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(if acceptable { 0 } else { 1 });
    }

    println!(
        "Attestation for ceremony '{}' by {} ({}@{})",
        attestation.ceremony_id,
        attestation.signer_name,
        attestation.username,
        attestation.hostname
    );
    println!(
        "Issued {} — expires {}\n",
        attestation.issued_at.format("%Y-%m-%d %H:%M:%S UTC"),
        attestation.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    print_check("Signature valid", outcome.signature_valid);
    print_check("Fresh (not expired)", outcome.fresh);
    print_check("Ceremony binding", outcome.ceremony_match);
    print_check("Machine posture passing", outcome.posture_passing);

    match (&outcome.trusted_signer, require_trusted) {
        (Some(name), _) => {
            print_labeled("Trusted signer", true, &format!("registered as '{}'", name))
        },
        (None, true) => print_labeled(
            "Trusted signer",
            false,
            "signing key is not on the team roster",
        ),
        (None, false) => println!(
            "  {} Trusted signer: no team roster configured (add with 'gard team add')",
            "-".yellow()
        ),
    }

    if acceptable {
        println!(
            "\n{}",
            "ATTESTATION ACCEPTED — clear to countersign."
                .green()
                .bold()
        );
        Ok(0)
    } else {
        println!(
            "\n{}",
            "ATTESTATION REJECTED — do not countersign.".red().bold()
        );
        Ok(1)
    }
}

fn print_check(label: &str, passed: bool) {
    if passed {
        println!("  {} {}", "✓".green(), label);
    } else {
        println!("  {} {}", "✗".red(), label);
    }
}

fn print_labeled(label: &str, passed: bool, detail: &str) {
    if passed {
        println!("  {} {}: {}", "✓".green(), label, detail);
    } else {
        println!("  {} {}: {}", "✗".red(), label, detail);
    }
}
