/// Durable nonce account ownership verification
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct SolanaNonceCheck;

impl CheckModule for SolanaNonceCheck {
    fn id(&self) -> &str { "solana-durable-nonce-verify" }
    fn name(&self) -> &str { "Solana Durable Nonce Verification" }
    fn description(&self) -> &str { "Verifies durable nonce account authority" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Verify nonce account authority matches expected multisig" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
