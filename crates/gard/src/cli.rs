//! CLI argument parsing and command dispatch
//!
//! Handles all command-line argument parsing and routing to command handlers.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gard",
    version,
    about = "OPSEC guardian CLI tool for Solana protocol teams",
    long_about = "Gard is a standalone CLI tool that enforces signing hygiene and detects dangerous configurations on developer and signer machines."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Use custom configuration file
    #[arg(global = true, long)]
    pub config: Option<String>,

    /// Use custom Gard data directory
    #[arg(global = true, long)]
    pub data_dir: Option<String>,

    /// Disable colored output
    #[arg(global = true, long)]
    pub no_color: bool,

    /// Suppress all output except exit code
    #[arg(global = true, short, long)]
    pub quiet: bool,

    /// Increase log verbosity (-L, -LL, -LLL); subcommands have their own -v
    #[arg(short = 'L', long = "log-verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Run complete local machine audit
    Scan(ScanCommand),

    /// Run mandatory pre-signing checklist
    Preflight(PreflightCommand),

    /// Manage Gard policy configuration
    Config(ConfigCommand),

    /// Format and export scan results
    Report(ReportCommand),

    /// Update Gard binary and check definitions
    Update(UpdateCommand),
}

#[derive(Parser, Clone)]
pub struct ScanCommand {
    /// Output format: plaintext, json, json-pretty
    #[arg(long, default_value = "plaintext")]
    pub format: String,

    /// Write report to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Include detailed check metadata
    #[arg(short, long)]
    pub verbose: bool,

    /// Skip specific check (comma-separated)
    #[arg(long)]
    pub skip: Option<String>,

    /// Run only specific check (comma-separated)
    #[arg(long)]
    pub only: Option<String>,

    /// Disable report signing
    #[arg(long)]
    pub no_sign: bool,
}

#[derive(Parser, Clone)]
pub struct PreflightCommand {
    /// Confirm preflight passed and prepare for signing
    #[arg(long)]
    pub sign: bool,

    /// Explicit confirmation that findings addressed
    #[arg(long)]
    pub confirm: bool,

    /// Override blocking findings with justification
    #[arg(long = "override", value_name = "REASON")]
    pub override_reason: Option<String>,

    /// Include detailed metadata
    #[arg(short, long)]
    pub verbose: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Clone)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub subcommand: ConfigSubcommand,
}

#[derive(Subcommand, Clone)]
pub enum ConfigSubcommand {
    /// Initialize default policy file
    Init,

    /// Display current policy configuration
    Show,

    /// Validate policy file syntax and schema
    Validate,

    /// Set individual policy key
    Set { key: String, value: String },

    /// Modify check enforcement status
    Check {
        name: String,
        #[arg(long)]
        level: Option<String>,
    },

    /// Suppress a specific check
    Suppress {
        check_name: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        until: Option<String>,
    },

    /// Remove check from suppression list
    Unsuppress { check_name: String },

    /// List all available checks
    ListChecks,
}

#[derive(Parser, Clone)]
pub struct ReportCommand {
    /// Output format: plaintext, json, markdown
    #[arg(long, default_value = "plaintext")]
    pub format: String,

    /// Write report to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Load specific report file
    #[arg(long)]
    pub input: Option<String>,

    /// Verify signature on report
    #[arg(long)]
    pub verify: bool,

    /// Export public key for verification
    #[arg(long)]
    pub export_key: bool,

    /// Show summary only
    #[arg(long)]
    pub summary: bool,

    /// Show only findings at severity level or above
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Parser, Clone)]
pub struct UpdateCommand {
    /// Check for update without installing
    #[arg(long)]
    pub check: bool,

    /// Update to specific version
    #[arg(long)]
    pub version: Option<String>,

    /// Update channel: stable, beta
    #[arg(long, default_value = "stable")]
    pub channel: String,

    /// Force update even if current version is latest
    #[arg(long)]
    pub force: bool,

    /// Skip signature verification
    #[arg(long)]
    pub no_signature_verify: bool,

    /// Update rules without updating binary
    #[arg(long)]
    pub rules_only: bool,

    /// Simulate update without making changes
    #[arg(long)]
    pub dry_run: bool,
}
