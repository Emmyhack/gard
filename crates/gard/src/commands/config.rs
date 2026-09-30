//! Config command - manage policy configuration
//!
//! Initializes, displays, validates, and edits ~/.gard/policy.toml.

use crate::checks::CheckRegistry;
use crate::cli::{ConfigCommand, ConfigSubcommand};
use crate::config;
use crate::error::{GardError, Result};
use crate::types::{Policy, Suppression};
use std::fs;

pub async fn execute(cmd: ConfigCommand) -> Result<i32> {
    match cmd.subcommand {
        ConfigSubcommand::Init => init(),
        ConfigSubcommand::Show => show(),
        ConfigSubcommand::Validate => validate(),
        ConfigSubcommand::Set { key, value } => {
            println!(
                "Direct key setting is not supported yet; edit {} to set {} = {}",
                config::get_default_policy_path()?.display(),
                key,
                value
            );
            Ok(2)
        },
        ConfigSubcommand::Check { name, level } => set_check_level(&name, level.as_deref()),
        ConfigSubcommand::Suppress {
            check_name,
            reason,
            until,
        } => suppress(&check_name, reason.as_deref(), until.as_deref()),
        ConfigSubcommand::Unsuppress { check_name } => unsuppress(&check_name),
        ConfigSubcommand::ListChecks => list_checks(),
    }
}

fn init() -> Result<i32> {
    let path = config::get_default_policy_path()?;
    if path.exists() {
        println!("Policy file already exists at {}", path.display());
        return Ok(0);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    save_policy(&Policy::default())?;
    println!("Initialized default policy at {}", path.display());
    Ok(0)
}

fn show() -> Result<i32> {
    let policy = config::load_policy(None)?;
    let rendered = toml::to_string_pretty(&policy)
        .map_err(|e| GardError::PolicyValidationError(e.to_string()))?;
    println!("{}", rendered);
    Ok(0)
}

fn validate() -> Result<i32> {
    let path = config::get_default_policy_path()?;
    if !path.exists() {
        println!(
            "No policy file at {}. Run 'gard config init' to create one.",
            path.display()
        );
        return Ok(1);
    }

    let policy = config::load_policy(None)?;

    let registry = CheckRegistry::new();
    let known_ids: Vec<String> = registry.all().iter().map(|c| c.id().to_string()).collect();
    let mut problems = Vec::new();

    for (check_id, level) in &policy.checks {
        if !known_ids.contains(check_id) {
            problems.push(format!("Unknown check id: {}", check_id));
        }
        if !matches!(level.as_str(), "enforce" | "warn" | "silent") {
            problems.push(format!(
                "Invalid enforcement level '{}' for {} (expected enforce|warn|silent)",
                level, check_id
            ));
        }
    }

    for suppression in &policy.suppressions {
        if chrono::NaiveDate::parse_from_str(&suppression.expires, "%Y-%m-%d").is_err() {
            problems.push(format!(
                "Suppression for {} has invalid expiry '{}' (expected YYYY-MM-DD)",
                suppression.check_id, suppression.expires
            ));
        }
        if suppression.reason.trim().is_empty() {
            problems.push(format!(
                "Suppression for {} is missing a reason",
                suppression.check_id
            ));
        }
    }

    if problems.is_empty() {
        println!("Policy at {} is valid.", path.display());
        Ok(0)
    } else {
        for problem in &problems {
            eprintln!("ERROR: {}", problem);
        }
        Ok(1)
    }
}

fn set_check_level(name: &str, level: Option<&str>) -> Result<i32> {
    let mut policy = config::load_policy(None)?;

    let Some(level) = level else {
        let current = policy
            .checks
            .get(name)
            .cloned()
            .unwrap_or_else(|| "enforce (default)".to_string());
        println!("{}: {}", name, current);
        return Ok(0);
    };

    if !matches!(level, "enforce" | "warn" | "silent") {
        return Err(GardError::PolicyValidationError(format!(
            "Invalid level '{}' (expected enforce|warn|silent)",
            level
        )));
    }

    let registry = CheckRegistry::new();
    if registry.get(name).is_none() {
        return Err(GardError::PolicyValidationError(format!(
            "Unknown check id: {}. Run 'gard config list-checks' to see valid ids.",
            name
        )));
    }

    policy.checks.insert(name.to_string(), level.to_string());
    save_policy(&policy)?;
    println!("Set {} = {}", name, level);
    Ok(0)
}

fn suppress(check_name: &str, reason: Option<&str>, until: Option<&str>) -> Result<i32> {
    let reason = reason.ok_or_else(|| {
        GardError::PolicyValidationError("Suppression requires --reason".to_string())
    })?;
    let until = until.ok_or_else(|| {
        GardError::PolicyValidationError("Suppression requires --until YYYY-MM-DD".to_string())
    })?;

    chrono::NaiveDate::parse_from_str(until, "%Y-%m-%d").map_err(|_| {
        GardError::PolicyValidationError(format!(
            "Invalid --until date '{}' (expected YYYY-MM-DD)",
            until
        ))
    })?;

    let mut policy = config::load_policy(None)?;
    policy.suppressions.retain(|s| s.check_id != check_name);
    policy.suppressions.push(Suppression {
        check_id: check_name.to_string(),
        reason: reason.to_string(),
        expires: until.to_string(),
    });
    save_policy(&policy)?;
    println!("Suppressed {} until {} ({})", check_name, until, reason);
    Ok(0)
}

fn unsuppress(check_name: &str) -> Result<i32> {
    let mut policy = config::load_policy(None)?;
    let before = policy.suppressions.len();
    policy.suppressions.retain(|s| s.check_id != check_name);
    if policy.suppressions.len() == before {
        println!("No suppression found for {}", check_name);
        return Ok(1);
    }
    save_policy(&policy)?;
    println!("Removed suppression for {}", check_name);
    Ok(0)
}

fn list_checks() -> Result<i32> {
    let registry = CheckRegistry::new();
    let mut checks = registry.all();
    checks.sort_by(|a, b| a.id().cmp(b.id()));

    println!("{:<32} {:<10} {:<9} NAME", "ID", "SEVERITY", "BLOCKING");
    for check in checks {
        println!(
            "{:<32} {:<10} {:<9} {}",
            check.id(),
            check.severity().to_string(),
            if check.blocking_in_preflight() {
                "yes"
            } else {
                "no"
            },
            check.name()
        );
    }
    Ok(0)
}

fn save_policy(policy: &Policy) -> Result<()> {
    let path = config::get_default_policy_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rendered = toml::to_string_pretty(policy)
        .map_err(|e| GardError::PolicyValidationError(e.to_string()))?;
    fs::write(&path, rendered)?;
    Ok(())
}
