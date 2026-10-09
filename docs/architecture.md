# Gard Architecture and Feature Design

## 1. Command Surface and Interface

### 1.1 Core Commands

#### `gard scan`

Runs a complete local machine audit and produces a signed report.

Usage: `gard scan [OPTIONS]`

Options:
- `--format <FORMAT>`: Output format. Values: `json`, `plaintext`, `json-pretty`. Default: `plaintext`
- `-o, --output <PATH>`: Write report to file. If omitted, writes to stdout
- `--json`: Shorthand for `--format json`
- `--config <PATH>`: Use custom configuration file
- `-v, --verbose`: Include detailed check metadata and timing information
- `--skip <CHECK>`: Skip specific check by name (comma-separated list)
- `--only <CHECK>`: Run only specific check by name (comma-separated list)
- `--no-sign`: Skip report signing (reports are signed by default)
- `--no-sign`: Do not sign report
- `--timestamp`: Include precise timestamp in report (default: true)

Exit codes:
- `0`: Scan completed, no findings
- `1`: Scan completed, findings discovered (severity independent)
- `2`: Scan execution error (invalid configuration, permission denied, etc.)
- `3`: Gard internal error (panic, unexpected state)

#### `gard preflight`

Mandatory pre-signing checklist that blocks or warns before contributor proceeds.

Usage: `gard preflight [OPTIONS]`

Options:
- `--override <REASON>`: Override blocking findings with a justification (requires `--confirm`; recorded in `override.log`)
- `--confirm`: Explicit confirmation that findings have been reviewed and addressed
- `--override <REASON>`: Override blocking findings with explicit justification
- `--config <PATH>`: Use custom configuration file
- `-v, --verbose`: Include detailed check metadata
- `--json`: Output results in JSON format
- `--no-color`: Disable colored output
- `--timeout <SECONDS>`: Maximum time to wait for checks (default: 60s)
- `--enforce-policy`: Exit non-zero if policy violations detected (default: true)

Exit codes:
- `0`: Preflight passed, all mandatory checks passing
- `1`: Preflight failed, blocking findings present
- `2`: Preflight execution error
- `3`: Gard internal error
- `4`: Override attempted without required flags

#### `gard config`

Manages the local Gard policy file.

Usage: `gard config <SUBCOMMAND>`

Subcommands:
- `init`: Initialize default policy file in Gard data directory
- `show`: Display current policy configuration
- `validate`: Validate policy file syntax and schema
- `set <KEY> <VALUE>`: Set individual policy key
- `check <CHECK_NAME>`: Modify check enforcement status
- `suppress <CHECK_NAME> [--reason <TEXT>] [--until <DATE>]`: Add finding to suppression list
- `unsuppress <CHECK_NAME>`: Remove finding from suppression list
- `list-checks`: List all available checks with current enforcement status

Options (all subcommands):
- `--policy <PATH>`: Operate on specific policy file
- `--json`: Output in JSON format
- `-v, --verbose`: Show additional configuration metadata

Exit codes:
- `0`: Configuration operation successful
- `1`: Invalid policy file or configuration
- `2`: Configuration file not found
- `3`: Permission denied

#### `gard report`

Formats and exports the last scan result.

Usage: `gard report [OPTIONS]`

Options:
- `--format <FORMAT>`: Output format. Values: `json`, `plaintext`, `json-pretty`, `markdown`. Default: `plaintext`
- `-o, --output <PATH>`: Write report to file
- `--last`: Use last scan report from cache
- `--input <PATH>`: Load specific report file
- `--verify`: Verify signature on report (requires input file)
- `--export-key`: Export public key for signature verification
- `--summary`: Show summary statistics only
- `--filter <SEVERITY>`: Show only findings at or above severity level
- `--group-by <FIELD>`: Group findings by module, severity, or platform

Exit codes:
- `0`: Report exported successfully
- `1`: Report file not found
- `2`: Verification failed
- `3`: Format conversion error

#### `gard update`

Handles self-update and rule refresh.

Usage: `gard update [OPTIONS]`

Options:
- `--check`: Check for update without installing
- `--version <VERSION>`: Update to specific version
- `--channel <CHANNEL>`: Update channel. Values: `stable`, `beta`. Default: `stable`
- `--force`: Force update even if current version is latest
- `--no-signature-verify`: Skip signature verification (not recommended)
- `--rules-only`: Update rule definitions without updating binary
- `--dry-run`: Simulate update without making changes
- `-v, --verbose`: Show download progress and verification status

Exit codes:
- `0`: Update successful or no update available
- `1`: Update failed (network error, invalid signature, etc.)
- `2`: Current version already latest
- `3`: Gard internal error

### 1.2 Global Flags

Flags applicable to all commands:

- `--version`: Display Gard version and exit
- `--help`: Display help text and exit
- `--config <PATH>`: Use custom configuration file for all commands
- `--data-dir <PATH>`: Use custom Gard data directory (default: `~/.gard`)
- `--no-color`: Disable colored terminal output
- `--quiet`: Suppress all output except final exit code
- `-v, --verbose`: Increase verbosity (can be repeated: `-vv`, `-vvv`)

### 1.3 Output Modes

All commands support consistent output modes:

- Plaintext: Human-readable format optimized for terminal display
- JSON: Machine-readable format for automation and parsing
- JSON Pretty: Formatted JSON with indentation for readability
- Markdown (available for report command): Formatted for documentation and sharing

## 2. Check Modules Definition

Each module specifies: name, description, severity, remediation, blocking status, platform availability.

### 2.1 VSCode Workspace Trust and Auto-Run Task Detection

**Name**: `vscode-workspace-trust`

**Description**: Detects VSCode workspace with untrusted settings, auto-run tasks that execute code on load, and potentially malicious extension recommendations. Specifically checks for workspace configuration that auto-enables untrusted mode, task definitions that execute shell commands, and extension recommendations from untrusted sources.

**Severity**: CRITICAL

**Remediation**: Review `.vscode/extensions.json` for unexpected extension recommendations, disable auto-trust in workspace settings, disable or review all auto-run tasks, verify VSCode workspace settings match team security policy.

**Blocking in Preflight**: Yes

**Platforms**: macOS, Linux

**Implementation Details**:
- Scans all `.code-workspace` files in home directory and common workspace locations
- Reads `.vscode/extensions.json` for extension recommendations
- Reads `.vscode/tasks.json` for auto-run and watch tasks
- Flags extensions not in allow-list
- Flags all tasks with shell execution (check type `shell` and commands containing `sh`, `bash`, `zsh`, `pwsh`)
- Flags workspace settings that contain `security.workspace.trust.enabled: false`

---

### 2.2 VSCode Extension Audit Against Known-Malicious and High-Risk Extension List

**Name**: `vscode-extension-audit`

**Description**: Audits installed VSCode extensions against known-malicious and high-risk extension list. Checks for extensions with historical vulnerability records, extensions from untrusted publishers, and extensions requesting excessive permissions. Includes version verification against known-vulnerable versions.

**Severity**: CRITICAL (malicious extensions), HIGH (high-risk extensions)

**Remediation**: Uninstall flagged extensions, review necessity of high-risk extensions, verify extension publisher authenticity, subscribe to VSCode security advisories for installed extensions.

**Blocking in Preflight**: Yes (malicious), advisory (high-risk)

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Scans VSCode extensions directory: `~/.vscode/extensions`
- Maintains list of known-malicious extensions (name, version range, advisory)
- Maintains list of high-risk extensions (clipboard monitor extensions, process monitor extensions, clipboard modification extensions)
- For each installed extension: reads `package.json` to determine extension ID and version
- Checks against known-malicious list
- Flags extensions with overly broad permissions manifest
- Flags recently updated extensions (updated in last 7 days) with high-risk name patterns

---

### 2.3 TestFlight Installation Detection on macOS

**Name**: `macos-testflight-apps`

**Description**: Detects signer-relevant applications installed via TestFlight on macOS. TestFlight applications bypass notarization and sandbox restrictions. Checks for wallet applications, key managers, and other signing-related tools delivered via TestFlight instead of App Store or direct verification.

**Severity**: CRITICAL

**Remediation**: Uninstall TestFlight versions of applications, reinstall from App Store or verified direct source, verify application notarization and code signing, check application entitlements against expected permissions.

**Blocking in Preflight**: Yes

**Platforms**: macOS only

**Implementation Details**:
- Scans `~/Library/Developer/CoreSimulator/Devices/*/data/*/Library/Caches/` for TestFlight metadata
- Queries `/var/db/app_analytics/` for recent application installations
- Checks for presence of TestFlight marker files in application bundles
- Scans for wallet-related applications in Applications folder without proper code signing
- Uses `codesign -v` to verify code signing validity
- Checks application entitlements with `codesign -d --entitlements -` for excessive permissions
- Flags applications with `com.apple.security.network.client` without clear necessity
- Flags applications missing notarization

---

### 2.4 Software Wallet Process and Binary Detection

**Name**: `software-wallet-detection`

**Description**: Detects running software wallet processes and wallet binaries in standard installation locations. Software wallets can be exfiltration targets if compromised. Checks for known wallet applications: Phantom, Ledger Live, MetaMask, Slope, Magic Eden, and similar.

**Severity**: MEDIUM

**Remediation**: Consider using hardware wallet exclusively on signing machine, isolate wallet on separate machine from transaction signing, restrict wallet permissions via system settings, monitor wallet for unexpected network activity.

**Blocking in Preflight**: No

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Uses `ps aux | grep` to detect running wallet processes
- Maintains list of known wallet process names: `phantom`, `ledger-live`, `metaMask`, `slope`, etc.
- Scans Application directories for installed wallets: `/Applications`, `~/.local/share`, `C:\Program Files\`
- For each detected wallet: records version, installation path, last modification time
- Checks wallet configuration files for keypair storage patterns
- Reports wallet data directory location and accessibility

---

### 2.5 Clipboard Monitoring Process Detection

**Name**: `clipboard-monitor-detection`

**Description**: Detects running processes that monitor or access system clipboard. Clipboard hijacking is a direct attack on transaction integrity. Identifies processes accessing clipboard frequently, clipboard monitoring daemons, and clipboard manipulation tools.

**Severity**: CRITICAL

**Remediation**: Identify purpose of clipboard monitoring process, uninstall if unnecessary, add exception to tool allowlist if legitimate, monitor clipboard monitor itself for unauthorized access patterns.

**Blocking in Preflight**: Yes

**Platforms**: macOS, Linux

**Implementation Details**:
- macOS: Uses `log stream --predicate 'eventMessage contains "clipboard"'` to detect clipboard access
- macOS: Monitors `/tmp` and `/var/tmp` for clipboard cache files
- Linux: Audits D-Bus clipboard access via `gdbus` introspection
- Linux: Monitors `xclip` and `xsel` process spawning
- Identifies long-running processes accessing clipboard frequently
- Flags clipboard monitor processes running continuously

---

### 2.6 Environment Variable Audit for Leaked Key Material Patterns

**Name**: `env-key-leakage`

**Description**: Audits environment variables for patterns indicating leaked key material or sensitive paths. Checks shell profiles, process environment, and CI configuration for keypair paths, private key exports, and credential environment variables.

**Severity**: CRITICAL

**Remediation**: Remove all keypair paths from shell environment, use secure key loading mechanisms (SSH agent, hardware wallet), configure CI/CD to not expose secrets in environment, audit shell history for accidental key exposure.

**Blocking in Preflight**: Yes

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Reads shell profiles: `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`
- Scans for environment variable definitions matching patterns: `*KEYPAIR*`, `*KEY_PATH*`, `*SECRET*`, `*PRIVATE_KEY*`
- Checks current process environment via `env` command
- Scans for Base58-encoded 32-byte values in environment (Solana keypair patterns)
- Audits CI/CD configuration files in `.github/workflows/`, `.gitlab-ci.yml`, etc.
- Checks system-wide environment files: `/etc/environment`, `/etc/profile.d/`
- Reports exact environment variable names and values (redacted)

---

### 2.7 SSH Agent Forwarding Configuration Audit

**Name**: `ssh-key-hygiene`

**Description**: Audits SSH key configuration and agent setup for weak hygiene patterns. SSH agent forwarding can enable privilege escalation. Checks for agent forwarding enabled, unpassphrased keys, key isolation, and agent configuration.

**Severity**: HIGH

**Remediation**: Disable SSH agent forwarding for untrusted hosts, add passphrases to SSH keys, isolate signing-specific keys in separate SSH agent, disable `AddKeysToAgent` auto-loading, review SSH known_hosts for suspicious entries.

**Blocking in Preflight**: Yes (agent forwarding enabled for broad hosts)

**Platforms**: macOS, Linux

**Implementation Details**:
- Reads `~/.ssh/config` for `ForwardAgent yes` directives and host patterns
- Flags `ForwardAgent yes` for patterns matching `*` or broad host patterns
- Checks SSH key permissions with `ls -la ~/.ssh/`
- Uses `ssh-keygen -l -f` to list SSH keys and check for passphrases
- Keys without passphrase marked as unpassphrased
- Scans for SSH keys in non-standard locations
- Checks `~/.ssh/authorized_keys` and `~/.ssh/known_hosts` for age and suspicious entries
- Audits SSH agent socket and process

---

### 2.8 Open Port Scan Scoped to Known Remote Access Tool Ports

**Name**: `open-ports-remote-access`

**Description**: Scans for open ports commonly used by remote access tools. Detects VNC, RDP, SSH, TeamViewer, Chrome Remote Desktop, and similar services that could enable unauthorized access. Scoped to known remote access ports to avoid false positives.

**Severity**: HIGH

**Remediation**: Close remote access ports if not necessary, use SSH key authentication instead of password, restrict remote access to specific IP ranges, disable remote access tools if not required, enable firewall rules to restrict inbound connections.

**Blocking in Preflight**: Yes (VNC, RDP, TeamViewer active)

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Uses `netstat -an | grep LISTEN` to list listening ports
- Ports checked: SSH (22), VNC (5900, 5901-5910), RDP (3389), Mosh (60000), TeamViewer (5938), Chrome Remote Desktop (5555)
- For each open port: attempts to identify service version
- Checks process listening on port using `lsof -i :<port>`
- Flags remote access services running but not explicitly configured
- Reports listening address (localhost vs 0.0.0.0 indicating external exposure)

---

### 2.9 Browser with Crypto Extensions on Signing Machine

**Name**: `browser-crypto-extension`

**Description**: Detects browsers with cryptocurrency wallet extensions on signing machines. Browser extensions have deep privileges and can intercept transaction signing. Detects MetaMask, Phantom, Ledger, and similar extensions in Chrome, Firefox, and Safari.

**Severity**: MEDIUM

**Remediation**: Consider disabling crypto extensions during signing ceremonies, use separate browser profile without extensions for signing, isolate signing browser from general browsing, audit extension permissions and network access.

**Blocking in Preflight**: No

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Scans Chrome extension directory: `~/.config/google-chrome/Default/Extensions/`
- Scans Firefox profile directory: `~/.mozilla/firefox/*/extensions.json`
- Scans Safari extension directory: `~/Library/Safari/Extensions/`
- Maintains list of known crypto wallet extensions (Phantom ID, MetaMask ID, etc.)
- For each browser: lists installed extensions and checks against known wallet extensions
- Reports extension permissions extracted from manifest.json
- Flags extensions with broad content script permissions

---

### 2.10 Presence of Unsigned or Recently Installed Binaries in PATH

**Name**: `unsigned-binaries-in-path`

**Description**: Detects unsigned or recently installed binaries in PATH that could represent supply chain attack or compromised tooling. Checks for binaries without valid code signatures, binaries installed in last 7 days, and binaries in suspicious locations.

**Severity**: HIGH

**Remediation**: Verify binary authenticity and source, pin tool versions in automation, use reproducible binary verification, remove binaries installed from untrusted sources, audit build tools for unexpected modifications.

**Blocking in Preflight**: Yes (for development tool binaries like `solana`, `cargo`, `anchor`)

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Parses PATH environment variable and iterates through directories
- For each binary: checks code signature status (macOS: `codesign -v`)
- For each binary: checks modification time, flags if modified in last 7 days
- Maintains allow-list of known legitimate tools
- Specifically checks for development tools: `solana`, `cargo`, `anchor`, `rustc`, `node`, `npm`
- Reports binary location, code signature status, size, and last modification time
- Flags binaries in suspicious locations: `/tmp`, `/var/tmp`, user home subdirectories

---

### 2.11 Solana CLI Configuration Audit

**Name**: `solana-cli-config`

**Description**: Audits Solana CLI configuration including keypair file locations, RPC endpoint trust, and CLI wallet setup. Verifies that Solana CLI is configured to use secure keypair storage and trusted RPC endpoints.

**Severity**: HIGH

**Remediation**: Set Solana keypair to hardware wallet or secure key storage, verify RPC endpoint is trusted and controls security-critical accounts, disable insecure wallet auto-load, audit solana-cli version for security patches.

**Blocking in Preflight**: Yes (unsafe keypair configuration)

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Reads `~/.config/solana/cli/config.yml` (Solana CLI config)
- Extracts keypair path from configuration
- Verifies keypair file exists and has restricted permissions (600)
- Flags keypair stored in insecure locations: `/tmp`, `/var/tmp`, world-readable
- Audits RPC endpoint URL in configuration
- Checks RPC endpoint against list of known public endpoints
- Flags self-hosted RPC endpoints without HTTPS
- Verifies RPC endpoint is reachable and returns valid response
- Extracts RPC endpoint signature verification setting if available

---

### 2.12 Durable Nonce Account Ownership Verification

**Name**: `solana-durable-nonce-verify`

**Description**: Verifies that durable nonce accounts are owned by expected authority. Requires network access to verify nonce account state on Solana blockchain. Checks nonce authority against expected multisig or signing key.

**Severity**: CRITICAL

**Remediation**: If nonce authority is not as expected, request new nonce account creation from authorized multisig, do not proceed with transaction signing using mismatched nonce account.

**Blocking in Preflight**: Yes

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Requires nonce account address provided as environment variable or configuration
- Calls RPC endpoint to retrieve nonce account state
- Extracts nonce authority from account data
- Compares authority against expected authority (from configuration)
- Reports nonce account rent balance and status
- Flags nonce account if authority is not as expected
- Requires environment variable: `GARD_NONCE_ACCOUNT` and `GARD_NONCE_AUTHORITY`

---

### 2.13 Hardware Wallet Connectivity Verification

**Name**: `hardware-wallet-verify`

**Description**: Verifies connectivity and availability of configured hardware wallet. Hardware wallet is preferred signing mechanism. Checks for presence of hardware wallet software, daemon, and connectivity to actual hardware device.

**Severity**: MEDIUM

**Remediation**: Connect hardware wallet device, ensure hardware wallet software is running, verify USB connection, reinstall hardware wallet driver if needed.

**Blocking in Preflight**: Conditional (if hardware wallet is policy requirement)

**Platforms**: macOS, Linux, Windows

**Implementation Details**:
- Scans for hardware wallet software: Ledger Live, Trezor Suite
- Verifies hardware wallet daemon is running
- Attempts to enumerate connected hardware wallet devices
- Checks USB device list for hardware wallet hardware IDs
- macOS: scans `ioreg` for USB device presence
- Linux: scans `/sys/bus/usb/devices/` for device presence
- Verifies hardware wallet software version is current
- Reports device connectivity and readiness status

---

## 3. Check Module Registration and Execution Architecture

### 3.1 Module System Design

Modules are registered via trait implementation pattern:

```
trait CheckModule {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;
    fn blocking_in_preflight(&self) -> bool;
    fn platforms(&self) -> &[Platform];
    fn remediation(&self) -> &str;
    fn run(&self) -> Result<Vec<Finding>>;
}
```

Module registry:
- Built-in modules registered at compile time
- Module registry macro for simplified module addition
- Each module implements execution logic independently
- Modules execute sequentially or in parallel (non-blocking modules in parallel)
- Module execution timeouts: 30 seconds per module, 300 seconds total scan

---

### 3.2 Finding Collection and Aggregation

Findings from all modules collected into unified report structure:

```
struct Finding {
    check_id: String,
    check_name: String,
    severity: Severity,
    description: String,
    remediation: String,
    blocking: bool,
    platform: Platform,
    timestamp: DateTime<Utc>,
    details: Value, // JSON object with check-specific details
}
```

---

## 4. Policy and Configuration System

### 4.1 Policy File Schema

Gard policy file (stored at `~/.gard/policy.toml`):

```toml
# Gard Policy Configuration

# Enforcement level for each check
[checks]
vscode-workspace-trust = "enforce"          # enforce, warn, silent
vscode-extension-audit = "enforce"
macos-testflight-apps = "enforce"
software-wallet-detection = "warn"
clipboard-monitor-detection = "enforce"
env-key-leakage = "enforce"
ssh-key-hygiene = "enforce"
open-ports-remote-access = "enforce"
browser-crypto-extension = "warn"
unsigned-binaries-in-path = "enforce"
solana-cli-config = "enforce"
solana-durable-nonce-verify = "enforce"
hardware-wallet-verify = "warn"

# Suppression of specific findings with justification and expiry
[[suppressions]]
check_id = "software-wallet-detection"
reason = "Phantom wallet required for development, isolated on non-signing machine"
expires = "2026-06-01"

# Minimum required hardware wallet for preflight to pass
[hardware_wallet]
required = true
minimum_type = "ledger"  # ledger, trezor, solanafm

# RPC endpoint trust configuration
[solana]
trusted_rpc_endpoints = [
    "https://api.mainnet-beta.solana.com",
    "https://api.devnet.solana.com"
]
self_hosted_rpc_required = false

# Expected nonce account authority (if known)
[nonce]
expected_authority = "MultisigAuthority..."  # base58 encoded

# Policy version and metadata
[metadata]
version = "1"
created = "2026-04-01"
modified = "2026-04-16"
```

---

### 4.2 Policy Loading and Validation

- Policy file optional; default enforce all checks
- Policy file validation on load: schema check, reference validation
- Override via environment variables: `GARD_POLICY_FILE`
- Policy enforcement in all commands that run checks
- Invalid policy file causes error on execution

---

## 5. Report Format and Schema

### 5.1 JSON Report Format

```json
{
  "metadata": {
    "version": "1.0",
    "gard_version": "0.1.0",
    "timestamp": "2026-04-16T14:30:00Z",
    "hostname": "developer-mbp",
    "username": "alice",
    "platform": "macos",
    "platform_version": "14.4.1",
    "scan_duration_ms": 1234,
    "signed": true,
    "signature": "7a9f8d2e...",
    "public_key": "7c3f9a1e..."
  },
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "preflight_passing": false,
    "blocking_findings": 1
  },
  "findings": [
    {
      "id": "f_001",
      "check_id": "env-key-leakage",
      "check_name": "Environment Variable Audit for Leaked Key Material",
      "severity": "CRITICAL",
      "platform": "macos",
      "description": "Environment variable SOLANA_KEYPAIR found pointing to /Users/alice/solana/id.json",
      "remediation": "Remove keypair path from shell environment, use SSH agent for key loading",
      "timestamp": "2026-04-16T14:30:05Z",
      "blocking": true,
      "details": {
        "variable_name": "SOLANA_KEYPAIR",
        "variable_value_redacted": "true",
        "source_file": "~/.zshrc",
        "line_number": 42
      }
    }
  ],
  "signature_verification": {
    "verified": true,
    "algorithm": "ed25519",
    "verification_command": "gard report --input report.json --verify"
  }
}
```

### 5.2 Plaintext Report Format

```
Gard Scan Report
Generated: 2026-04-16 14:30:00 UTC
Hostname: developer-mbp
Platform: macOS 14.4.1

Summary
-------
Total Findings: 3
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 0
  LOW: 0

Preflight Status: FAILED (1 blocking finding)

Findings
--------

[CRITICAL] Environment Variable Audit for Leaked Key Material
Module: env-key-leakage
Platform: macOS
Blocking: Yes

Description:
  Environment variable SOLANA_KEYPAIR found pointing to keypair file
  
Remediation:
  Remove keypair path from shell environment, use SSH agent for key loading

Details:
  Variable Name: SOLANA_KEYPAIR
  Source File: ~/.zshrc (line 42)

---

[HIGH] SSH Agent Forwarding Enabled
Module: ssh-key-hygiene
Platform: macOS
Blocking: Yes

Description:
  SSH agent forwarding enabled for broad host patterns in ~/.ssh/config

Remediation:
  Disable SSH agent forwarding for untrusted hosts, restrict to known hosts only

Details:
  Forwarding Pattern: *.amazonaws.com
  Impact: Compromised AWS machine could forward auth back to signing machine

---

Report Signature
----------------
Algorithm: Ed25519
Signed: Yes
Verification: gard report --verify

Report verification can be done without Gard installed by extracting the 
public key and using standard tools:

openssl pkey -pubin -text -noout -in public_key.pem | grep -A 4 "pub:"
echo -n "<report_json>" | openssl dgst -sha256 -verify public_key.pem -signature <(echo "<signature>" | xxd -r -p)
```

---

### 5.3 Report Signing Mechanism

- Ed25519 keypair generated on first scan and stored at `~/.gard/keys/ed25519`
- Public key exported to `~/.gard/keys/ed25519.pub` as `ed25519 <hex>`
- Report signature: Ed25519 signature of JSON report (deterministic serialization)
- Signature appended to report as `signature` and `public_key` fields
- Verification independent of Gard: signature validation via OpenSSL or other standard tools
- Signature verification document included in plaintext report output

---

## 6. Binary Architecture

### 6.1 Crate Structure

```
crates/
  gard/                    # Main binary crate
    src/
      main.rs             # CLI entry point
      cli.rs              # Command parsing and dispatch
      commands/
        scan.rs
        preflight.rs
        config.rs
        report.rs
        update.rs
      checks/
        mod.rs
        registry.rs
        vscode_workspace_trust.rs
        vscode_extension_audit.rs
        [... other check implementations ...]
      report/
        format.rs
        json.rs
        plaintext.rs
        sign.rs
      config/
        policy.rs
        load.rs
        validate.rs
      error.rs
      output.rs
```

### 6.2 Module Registration

Checks registered via macro:

```rust
register_check!(VscodeWorkspaceTrustCheck);
register_check!(VscodeExtensionAuditCheck);
// ... etc
```

Registry contains:
- Check name, description, severity, blocking status
- Platform requirements (macOS, Linux, Windows)
- Module trait object for execution
- Execution timeout

### 6.3 Self-Update Mechanism

Self-update without supply chain risk:

- Update checker queries GitHub releases API for latest version
- Latest release checked against current version
- If update available: downloads signed release binary from GitHub
- Binary signature verified against public key stored in Gard binary
- Signature verification: Ed25519 signature of binary SHA256
- After verification: new binary extracted, permission set to 755, old binary backed up
- Update recorded in `~/.gard/update.log` with timestamp and version

---

## 7. Configuration Loading and Validation Pipeline

1. Default configuration loaded (all checks enforced)
2. Global policy file checked at `~/.gard/policy.toml`
3. Environment variable `GARD_POLICY_FILE` can override location
4. Per-command `--config` flag can override
5. Policy file validated against schema
6. Check enforcement levels applied
7. Suppression list loaded and expiry checked
8. Configuration ready for execution

---

## 8. Output Rendering Pipeline

1. Findings collected from all modules
2. Findings sorted by severity (CRITICAL first)
3. Suppressed findings filtered based on policy
4. Output format selected (json, plaintext, etc.)
5. Format renderer produces output
6. Signature added unless `--no-sign` is given
7. Output written to file or stdout
8. Exit code calculated based on findings

---

## 9. Command Dispatch and Execution Flow

1. CLI parsed using clap
2. Global options extracted (--config, --verbose, etc.)
3. Configuration loaded and validated
4. Subcommand dispatcher invokes appropriate command handler
5. Command handler executes check modules
6. Findings collected and validated
7. Output rendered in selected format
8. Exit code determined and returned

---

## 10. Error Handling Architecture

Structured error type with context:

```rust
pub enum GardError {
    ConfigurationError {
        path: String,
        reason: String,
    },
    CheckExecutionError {
        check_name: String,
        reason: String,
    },
    PermissionDenied {
        resource: String,
    },
    PlatformUnsupported {
        check_name: String,
        platform: String,
    },
    NetworkError {
        endpoint: String,
        reason: String,
    },
    SignatureVerificationFailed,
}
```

Error messages include:
- Clear description of what went wrong
- Actionable remediation suggestion
- Exit code indicating error category
- No unwrap calls in production code; all errors handled with Result type

