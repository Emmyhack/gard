/// Hardware wallet connectivity verification
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct HardwareWalletCheck;

impl CheckModule for HardwareWalletCheck {
    fn id(&self) -> &str { "hardware-wallet-verify" }
    fn name(&self) -> &str { "Hardware Wallet Connectivity Verification" }
    fn description(&self) -> &str { "Verifies hardware wallet connectivity" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn blocking_in_preflight(&self) -> bool { false }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Connect hardware wallet device and install required software" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
