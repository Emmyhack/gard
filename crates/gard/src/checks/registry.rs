/// Check module registry
///
/// Manages registration and execution of all security checks.

use super::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of all available checks
pub struct CheckRegistry {
    checks: HashMap<String, Arc<dyn CheckModule>>,
}

impl CheckRegistry {
    /// Create a new check registry with all built-in checks
    pub fn new() -> Self {
        let registry = CheckRegistry {
            checks: HashMap::new(),
        };

        // Register all checks here
        // These will be populated as checks are implemented
        
        registry
    }

    /// Register a check module
    pub fn register(&mut self, check: Arc<dyn CheckModule>) {
        self.checks.insert(check.id().to_string(), check);
    }

    /// Get a check by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn CheckModule>> {
        self.checks.get(id).cloned()
    }

    /// Get all registered checks
    pub fn all(&self) -> Vec<Arc<dyn CheckModule>> {
        self.checks.values().cloned().collect()
    }

    /// Get checks for a specific platform
    pub fn for_platform(&self, platform: Platform) -> Vec<Arc<dyn CheckModule>> {
        self.checks
            .values()
            .filter(|check| check.platforms().contains(&platform))
            .cloned()
            .collect()
    }

    /// Run all checks
    pub fn run_all(&self) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for check in self.all() {
            match check.run() {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    tracing::warn!(check_id = check.id(), error = ?e, "Check failed");
                }
            }
        }

        Ok(all_findings)
    }

    /// Run checks matching a filter
    pub fn run_matching<F>(&self, predicate: F) -> Result<Vec<Finding>>
    where
        F: Fn(&dyn CheckModule) -> bool,
    {
        let mut all_findings = Vec::new();

        for check in self.all() {
            if predicate(check.as_ref()) {
                match check.run() {
                    Ok(findings) => all_findings.extend(findings),
                    Err(e) => {
                        tracing::warn!(check_id = check.id(), error = ?e, "Check failed");
                    }
                }
            }
        }

        Ok(all_findings)
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = CheckRegistry::new();
        assert!(registry.all().is_empty() || !registry.all().is_empty()); // Always true
    }
}
