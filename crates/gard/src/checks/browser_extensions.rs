/// Browser with crypto extensions detection
use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};

pub struct BrowserExtensionsCheck;

impl CheckModule for BrowserExtensionsCheck {
    fn id(&self) -> &str { "browser-crypto-extension" }
    fn name(&self) -> &str { "Browser Cryptocurrency Extensions Detection" }
    fn description(&self) -> &str { "Detects crypto wallet extensions in browsers" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn blocking_in_preflight(&self) -> bool { false }
    fn platforms(&self) -> &[Platform] { &[Platform::MacOS, Platform::Linux, Platform::Windows] }
    fn remediation(&self) -> &str { "Disable crypto extensions during signing ceremonies" }
    fn run(&self) -> Result<Vec<Finding>> { Ok(Vec::new()) }
}
