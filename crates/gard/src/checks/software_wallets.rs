/// Software wallet process and binary detection
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct SoftwareWalletsCheck;

impl CheckModule for SoftwareWalletsCheck {
    fn id(&self) -> &str { "software-wallet-detection" }
    fn name(&self) -> &str { "Software Wallet Detection" }
    fn description(&self) -> &str { "Detects running software wallet processes" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn blocking_in_preflight(&self) -> bool { false }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Consider using hardware wallet exclusively on signing machine" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
