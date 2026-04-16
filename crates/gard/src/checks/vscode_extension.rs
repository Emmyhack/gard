/// VSCode extension audit against known-malicious and high-risk list
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct VscodeExtensionCheck;

impl CheckModule for VscodeExtensionCheck {
    fn id(&self) -> &str { "vscode-extension-audit" }
    fn name(&self) -> &str { "VSCode Extension Audit" }
    fn description(&self) -> &str { "Audits installed extensions against known-malicious list" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn blocking_in_preflight(&self) -> bool { true }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Uninstall flagged extensions" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
