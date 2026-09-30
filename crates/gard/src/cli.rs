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

    /// Produce a signed machine-posture attestation for a signing ceremony
    Attest(AttestCommand),

    /// Verify a co-signer's ceremony attestation
    Verify(VerifyCommand),

    /// Submit to and inspect team fleet compliance
    Fleet(FleetCommand),

    /// Manage the trusted signer roster
    Team(TeamCommand),
}

#[derive(Parser, Clone)]
pub struct AttestCommand {
    /// Ceremony identifier to bind this attestation to (e.g. proposal or tx id)
    #[arg(long)]
    pub ceremony: String,

    /// Signer name presented to co-signers (defaults to OS username)
    #[arg(long)]
    pub signer: Option<String>,

    /// Minutes until the attestation expires
    #[arg(long, default_value = "30")]
    pub valid_for: i64,

    /// Write attestation to this path (default: gard-attestation-<ceremony>.json)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Clone)]
pub struct VerifyCommand {
    /// Path to the attestation file to verify
    pub file: String,

    /// Ceremony identifier the attestation must be bound to
    #[arg(long)]
    pub ceremony: Option<String>,

    /// Fail unless the signing key is on the trusted team roster
    #[arg(long)]
    pub require_trusted: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Clone)]
pub struct FleetCommand {
    #[command(subcommand)]
    pub subcommand: FleetSubcommand,
}

#[derive(Subcommand, Clone)]
pub enum FleetSubcommand {
    /// Run a fresh scan and submit the signed report to the fleet directory
    Submit {
        /// Fleet directory (defaults to [fleet] dir in policy)
        #[arg(long)]
        dir: Option<String>,
    },

    /// Generate a self-contained HTML dashboard from the fleet directory
    Dashboard {
        /// Fleet directory (defaults to [fleet] dir in policy)
        #[arg(long)]
        dir: Option<String>,

        /// Reports older than this many hours are flagged stale
        #[arg(long)]
        max_age_hours: Option<u64>,

        /// Write to this path (default: <fleet-dir>/index.html)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Serve a live fleet dashboard over HTTP on localhost
    Serve {
        /// Fleet directory (defaults to [fleet] dir in policy)
        #[arg(long)]
        dir: Option<String>,

        /// Port to listen on (localhost only)
        #[arg(long, default_value = "8787")]
        port: u16,

        /// Reports older than this many hours are flagged stale
        #[arg(long)]
        max_age_hours: Option<u64>,
    },

    /// Show compliance status for all submitted fleet reports
    Status {
        /// Fleet directory (defaults to [fleet] dir in policy)
        #[arg(long)]
        dir: Option<String>,

        /// Reports older than this many hours are flagged stale
        #[arg(long)]
        max_age_hours: Option<u64>,

        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
}

#[derive(Parser, Clone)]
pub struct TeamCommand {
    #[command(subcommand)]
    pub subcommand: TeamSubcommand,
}

#[derive(Subcommand, Clone)]
pub enum TeamSubcommand {
    /// Register a team member's public key (from 'gard report --export-key')
    Add {
        /// Member name
        name: String,

        /// Ed25519 public key as 64 hex characters
        #[arg(long)]
        key: String,
    },

    /// List registered team signers
    List,

    /// Remove a team member's key
    Remove {
        /// Member name
        name: String,
    },
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
