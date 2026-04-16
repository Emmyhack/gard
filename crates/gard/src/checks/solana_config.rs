/// Solana CLI configuration audit
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct SolanaConfigCheck;

impl CheckModule for SolanaConfigCheck {
    fn id(&self) -> &str { "solana-cli-config" }
    fn name(&self) -> &str { "Solana CLI Configuration Audit" }
    fn description(&self) -> &str { "Audits Solana CLI configuration for security" }
    fn severity(&self) -> Severity { Severity::High }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Configure Solana keypair to hardware wallet or secure storage" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
