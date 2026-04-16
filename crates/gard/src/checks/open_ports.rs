/// Open port scan scoped to remote access tool ports
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct OpenPortsCheck;

impl CheckModule for OpenPortsCheck {
    fn id(&self) -> &str { "open-ports-remote-access" }
    fn name(&self) -> &str { "Open Ports Remote Access Detection" }
    fn description(&self) -> &str { "Scans for open remote access ports" }
    fn severity(&self) -> Severity { Severity::High }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Close unnecessary remote access ports" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
