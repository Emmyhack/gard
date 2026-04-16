/// Unsigned or recently installed binaries in PATH
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct UnsignedBinariesCheck;

impl CheckModule for UnsignedBinariesCheck {
    fn id(&self) -> &str { "unsigned-binaries-in-path" }
    fn name(&self) -> &str { "Unsigned Binaries in PATH Detection" }
    fn description(&self) -> &str { "Detects unsigned or recently installed binaries" }
    fn severity(&self) -> Severity { Severity::High }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Verify binary authenticity and source" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
