/// Error handling for Gard operations
///
/// All errors in Gard use a structured error type to provide context
/// and actionable remediation information. No unwrap() calls in
/// production code.

use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, GardError>;

#[derive(Error, Debug)]
pub enum GardError {
    #[error("Configuration error in {path}: {reason}")]
    ConfigurationError { path: String, reason: String },

    #[error("Check execution failed for {check_name}: {reason}")]
    CheckExecutionError {
        check_name: String,
        reason: String,
    },

    #[error("Permission denied: {resource}")]
    PermissionDenied { resource: String },

    #[error("Check {check_name} is not supported on {platform}")]
    PlatformUnsupported {
        check_name: String,
        platform: String,
    },

    #[error("Network error connecting to {endpoint}: {reason}")]
    NetworkError { endpoint: String, reason: String },

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid report format: {reason}")]
    InvalidReportFormat { reason: String },

    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("Policy validation error: {0}")]
    PolicyValidationError(String),

    #[error("Gard internal error: {0}")]
    Internal(String),
}

impl GardError {
    /// Return exit code for this error
    pub fn exit_code(&self) -> i32 {
        match self {
            GardError::ConfigurationError { .. } => 2,
            GardError::CheckExecutionError { .. } => 2,
            GardError::PermissionDenied { .. } => 2,
            GardError::PlatformUnsupported { .. } => 2,
            GardError::NetworkError { .. } => 2,
            GardError::SignatureVerificationFailed => 1,
            GardError::InvalidReportFormat { .. } => 2,
            GardError::IoError { .. } => 2,
            GardError::JsonError { .. } => 2,
            GardError::TomlError { .. } => 2,
            GardError::PolicyValidationError { .. } => 2,
            GardError::Internal { .. } => 3,
        }
    }

    /// Return suggested remediation for this error
    pub fn remediation(&self) -> &str {
        match self {
            GardError::ConfigurationError { .. } => {
                "Check policy file syntax and schema, run 'gard config validate'"
            }
            GardError::CheckExecutionError { .. } => {
                "Check system permissions and try again, or run with --skip to skip this check"
            }
            GardError::PermissionDenied { .. } => {
                "Ensure sufficient permissions, may require sudo for some checks"
            }
            GardError::PlatformUnsupported { .. } => {
                "This check is not available on your platform"
            }
            GardError::NetworkError { .. } => {
                "Check network connectivity, verify RPC endpoint is reachable"
            }
            GardError::SignatureVerificationFailed => {
                "Report signature is invalid or corrupted"
            }
            GardError::InvalidReportFormat { .. } => {
                "Report file format is corrupted or invalid"
            }
            GardError::IoError { .. } => "Check file permissions and disk space",
            GardError::JsonError { .. } => "Report JSON format is invalid",
            GardError::TomlError { .. } => "Policy TOML format is invalid",
            GardError::PolicyValidationError { .. } => {
                "Policy file contains validation errors"
            }
            GardError::Internal { .. } => "Gard encountered an internal error",
        }
    }
}
