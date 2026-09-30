//! Gard: OPSEC guardian CLI tool for Solana protocol teams
//!
//! This crate implements machine-level security checks and pre-flight
//! validation for cryptocurrency signing operations on developer machines.
pub mod attestation;
pub mod checks;
pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
pub mod output;
pub mod report;
pub mod types;

pub use error::{GardError, Result};
pub use types::{Finding, Report, Severity};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
