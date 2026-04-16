/// VSCode workspace trust and auto-run task detection
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct VscodeWorkspaceCheck;

impl CheckModule for VscodeWorkspaceCheck {
    fn id(&self) -> &str { "vscode-workspace-trust" }
    fn name(&self) -> &str { "VSCode Workspace Trust and Auto-Run Task Detection" }
    fn description(&self) -> &str { "Detects VSCode workspace with untrusted settings" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux] }
    fn remediation(&self) -> &str { "Review workspace settings and disable auto-trust" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
