//! Command implementations for Gard
//!
//! Each command module handles a specific Gard operation: scan, preflight, config, report, update.

pub mod attest;
pub mod config;
pub mod fleet;
pub mod preflight;
pub mod report;
pub mod scan;
pub mod team;
pub mod update;
pub mod verify;

use crate::error::Result;

pub async fn execute_command(command: crate::cli::Commands, _cli: &crate::cli::Cli) -> Result<i32> {
    match command {
        crate::cli::Commands::Scan(cmd) => scan::execute(cmd).await,
        crate::cli::Commands::Preflight(cmd) => preflight::execute(cmd).await,
        crate::cli::Commands::Config(cmd) => config::execute(cmd).await,
        crate::cli::Commands::Report(cmd) => report::execute(cmd).await,
        crate::cli::Commands::Update(cmd) => update::execute(cmd).await,
        crate::cli::Commands::Attest(cmd) => attest::execute(cmd).await,
        crate::cli::Commands::Verify(cmd) => verify::execute(cmd).await,
        crate::cli::Commands::Fleet(cmd) => fleet::execute(cmd.subcommand).await,
        crate::cli::Commands::Team(cmd) => team::execute(cmd.subcommand).await,
    }
}
