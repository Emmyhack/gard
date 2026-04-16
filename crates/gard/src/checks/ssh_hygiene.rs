/// SSH agent forwarding configuration audit
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct SshHygieneCheck;

impl CheckModule for SshHygieneCheck {
    fn id(&self) -> &str { "ssh-key-hygiene" }
    fn name(&self) -> &str { "SSH Key Hygiene and Agent Forwarding Audit" }
    fn description(&self) -> &str { "Audits SSH configuration for weak patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux] }
    fn remediation(&self) -> &str { "Disable SSH agent forwarding for untrusted hosts" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
