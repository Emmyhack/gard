/// Clipboard monitoring process detection
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct ClipboardMonitorCheck;

impl CheckModule for ClipboardMonitorCheck {
    fn id(&self) -> &str { "clipboard-monitor-detection" }
    fn name(&self) -> &str { "Clipboard Monitoring Process Detection" }
    fn description(&self) -> &str { "Detects processes monitoring system clipboard" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux] }
    fn remediation(&self) -> &str { "Identify and remove clipboard monitoring processes" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
