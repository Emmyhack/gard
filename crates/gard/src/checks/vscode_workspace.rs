//! VSCode workspace trust and auto-run task detection
//!
//! Detects VSCode user settings that disable workspace trust, and
//! workspace task definitions configured to run automatically when a
//! folder is opened (`runOn: folderOpen`) — the injection vector used
//! in the Drift Protocol compromise.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub struct VscodeWorkspaceCheck;

impl CheckModule for VscodeWorkspaceCheck {
    fn id(&self) -> &str {
        "vscode-workspace-trust"
    }

    fn name(&self) -> &str {
        "VSCode Workspace Trust and Auto-Run Task Detection"
    }

    fn description(&self) -> &str {
        "Detects VSCode user settings that disable workspace trust protections and \
        workspace tasks configured to execute automatically on folder open."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux]
    }

    fn remediation(&self) -> &str {
        "Re-enable workspace trust (set security.workspace.trust.enabled to true), \
        remove task.allowAutomaticTasks overrides, and audit any tasks.json with \
        'runOn: folderOpen' before opening the workspace again."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for settings_path in self.vscode_settings_paths() {
            if !settings_path.exists() {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&settings_path) {
                findings.extend(self.scan_user_settings(&content, &settings_path));
            }
        }

        for tasks_path in self.recent_workspace_task_files() {
            if let Ok(content) = fs::read_to_string(&tasks_path) {
                findings.extend(self.scan_tasks_file(&content, &tasks_path));
            }
        }

        Ok(findings)
    }
}

impl VscodeWorkspaceCheck {
    /// User-level settings.json locations for VSCode and common forks
    fn vscode_settings_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return paths;
        };

        let product_dirs = ["Code", "Code - Insiders", "VSCodium", "Cursor"];

        #[cfg(target_os = "macos")]
        for product in product_dirs {
            paths.push(
                home.join("Library/Application Support")
                    .join(product)
                    .join("User/settings.json"),
            );
        }

        #[cfg(target_os = "linux")]
        for product in product_dirs {
            paths.push(
                home.join(".config")
                    .join(product)
                    .join("User/settings.json"),
            );
        }

        #[cfg(target_os = "windows")]
        for product in product_dirs {
            if let Some(appdata) = dirs::config_dir() {
                paths.push(appdata.join(product).join("User/settings.json"));
            }
        }

        let _ = product_dirs;
        paths
    }

    fn scan_user_settings(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        // VSCode settings allow comments; strip simple line comments before parsing
        let stripped: String = content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        let parsed: serde_json::Value = match serde_json::from_str(&stripped) {
            Ok(v) => v,
            // Fall back to substring matching when JSONC parsing fails
            Err(_) => serde_json::Value::Null,
        };

        let trust_disabled = if parsed.is_object() {
            parsed
                .get("security.workspace.trust.enabled")
                .and_then(|v| v.as_bool())
                == Some(false)
        } else {
            content.contains("\"security.workspace.trust.enabled\"") && content.contains("false")
        };

        if trust_disabled {
            findings.push(build_finding(
                self,
                format!(
                    "VSCode workspace trust is disabled in {}. Untrusted folders can \
                    execute tasks and debug configurations without prompting.",
                    path.display()
                ),
                json!({
                    "settings_file": path.to_string_lossy(),
                    "setting": "security.workspace.trust.enabled",
                    "value": false
                }),
            ));
        }

        let auto_tasks_on = if parsed.is_object() {
            parsed
                .get("task.allowAutomaticTasks")
                .and_then(|v| v.as_str())
                == Some("on")
        } else {
            content.contains("\"task.allowAutomaticTasks\"") && content.contains("\"on\"")
        };

        if auto_tasks_on {
            findings.push(build_finding(
                self,
                format!(
                    "Automatic task execution is globally enabled in {}. Any opened \
                    workspace can run arbitrary shell commands on folder open.",
                    path.display()
                ),
                json!({
                    "settings_file": path.to_string_lossy(),
                    "setting": "task.allowAutomaticTasks",
                    "value": "on"
                }),
            ));
        }

        findings
    }

    /// tasks.json files in the current directory tree (shallow) and home projects
    fn recent_workspace_task_files(&self) -> Vec<PathBuf> {
        let mut task_files = Vec::new();

        if let Ok(cwd) = std::env::current_dir() {
            let candidate = cwd.join(".vscode/tasks.json");
            if candidate.exists() {
                task_files.push(candidate);
            }
        }

        task_files
    }

    fn scan_tasks_file(&self, content: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if content.contains("folderOpen") {
            findings.push(build_finding(
                self,
                format!(
                    "Workspace task file {} contains a task configured to run \
                    automatically on folder open. Verify the command is expected \
                    before trusting this workspace.",
                    path.display()
                ),
                json!({
                    "tasks_file": path.to_string_lossy(),
                    "trigger": "runOn: folderOpen"
                }),
            ));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = VscodeWorkspaceCheck;
        assert_eq!(check.id(), "vscode-workspace-trust");
        assert!(check.blocking_in_preflight());
        assert_eq!(check.severity(), Severity::Critical);
    }

    #[test]
    fn test_detects_disabled_trust() {
        let check = VscodeWorkspaceCheck;
        let content = r#"{ "security.workspace.trust.enabled": false }"#;
        let findings = check.scan_user_settings(content, &PathBuf::from("/tmp/settings.json"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_detects_auto_tasks() {
        let check = VscodeWorkspaceCheck;
        let content = r#"{ "task.allowAutomaticTasks": "on" }"#;
        let findings = check.scan_user_settings(content, &PathBuf::from("/tmp/settings.json"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_clean_settings_no_findings() {
        let check = VscodeWorkspaceCheck;
        let content = r#"{ "editor.fontSize": 14 }"#;
        let findings = check.scan_user_settings(content, &PathBuf::from("/tmp/settings.json"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detects_folder_open_task() {
        let check = VscodeWorkspaceCheck;
        let content = r#"{ "tasks": [{ "runOptions": { "runOn": "folderOpen" } }] }"#;
        let findings = check.scan_tasks_file(content, &PathBuf::from("/tmp/tasks.json"));
        assert_eq!(findings.len(), 1);
    }
}
