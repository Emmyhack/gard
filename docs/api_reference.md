# Gard API Reference

## Core Types

### `Severity`

Severity level of a finding.

```rust
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn display_color(&self) -> String { /* ... */ }
    pub fn as_u8(&self) -> u8 { /* ... */ }
}

impl PartialOrd for Severity { /* ... */ }
impl Ord for Severity { /* ... */ }
```

**Values (ordered):**
- `Critical` - Blocks signing ceremonies
- `High` - Significant risk, should be addressed
- `Medium` - Moderate risk
- `Low` - Minor issues
- `Info` - Informational only

---

### `Platform`

Operating system platform.

```rust
pub enum Platform {
    MacOS,
    Linux,
    Windows,
}

impl Platform {
    pub fn current_platform() -> Self { /* ... */ }
    pub fn as_str(&self) -> &str { /* ... */ }
}
```

---

### `Finding`

Single security finding from a check.

```rust
pub struct Finding {
    pub id: String,                  // Unique finding ID (f_XXXXXX)
    pub check_id: String,            // Check that produced this finding
    pub check_name: String,          // Human-readable check name
    pub severity: Severity,          // Severity level
    pub platform: Platform,          // Platform where found
    pub description: String,         // What was found
    pub remediation: String,         // How to fix it
    pub blocking: bool,              // Blocks preflight if true
    pub timestamp: DateTime<Utc>,    // When found
    pub details: serde_json::Value,  // Additional context as JSON
}

impl Finding {
    pub fn new(check_id: &str, description: &str) -> Self { /* ... */ }
}
```

---

### `Report`

Complete scan report with findings.

```rust
pub struct Report {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

pub struct ReportMetadata {
    pub version: String,           // Report format version
    pub gard_version: String,      // Gard version that created report
    pub timestamp: DateTime<Utc>,  // When report was created
    pub hostname: String,          // Machine hostname
    pub username: String,          // User who ran scan
    pub platform: Platform,        // OS platform
    pub scan_duration_ms: u64,     // How long scan took
    pub signature: Option<String>, // Ed25519 signature (hex)
    pub public_key: Option<String>, // Public key (ed25519 <hex>)
    pub signed: bool,              // Was report signed?
}

pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}
```

---

### `Policy`

Security policy configuration.

```rust
pub struct Policy {
    pub metadata: PolicyMetadata,
    pub default_enforcement: EnforcementLevel,
    pub checks: HashMap<String, CheckPolicy>,
}

pub enum EnforcementLevel {
    Enforce,   // Check must pass, blocks preflight if finding
    Warn,      // Check runs, finding reported but doesn't block
    Silent,    // Check runs but finding not reported
}

pub struct CheckPolicy {
    pub enforcement: EnforcementLevel,
    pub blocking: bool,            // Override blocking status
    pub suppressions: Vec<Suppression>,
}

pub struct Suppression {
    pub reason: String,
    pub until: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub created_by: String,
}
```

---

## Check Module Interface

### `CheckModule` Trait

All security checks implement this trait.

```rust
pub trait CheckModule: Send + Sync + Debug {
    /// Unique identifier for this check
    fn id(&self) -> &str;
    
    /// Human-readable name
    fn name(&self) -> &str;
    
    /// Detailed description
    fn description(&self) -> &str;
    
    /// Severity level of findings from this check
    fn severity(&self) -> Severity;
    
    /// Whether a finding from this check blocks preflight
    fn blocking_in_preflight(&self) -> bool;
    
    /// Platforms this check supports
    fn platforms(&self) -> &[Platform];
    
    /// Remediation instructions
    fn remediation(&self) -> &str;
    
    /// Execute the check and return findings
    fn run(&self) -> Result<Vec<Finding>>;
}
```

---

## Error Handling

### `GardError` Enum

```rust
pub enum GardError {
    ConfigurationError(String),
    
    CheckExecutionError {
        check_name: String,
        reason: String,
    },
    
    PermissionDenied,
    
    PlatformUnsupported,
    
    NetworkError(String),
    
    SignatureVerificationFailed,
    
    InvalidReportFormat,
    
    IoError(std::io::Error),
    
    JsonError(serde_json::Error),
    
    TomlError(toml::de::Error),
    
    PolicyValidationError(String),
    
    Internal(String),
}

impl GardError {
    /// Get process exit code for this error
    pub fn exit_code(&self) -> u8 {
        match self {
            GardError::ConfigurationError(_) => 5,
            GardError::CheckExecutionError { .. } => 2,
            GardError::PermissionDenied => 3,
            GardError::PlatformUnsupported => 3,
            GardError::NetworkError(_) => 2,
            GardError::SignatureVerificationFailed => 2,
            GardError::InvalidReportFormat => 2,
            GardError::IoError(_) => 3,
            GardError::JsonError(_) => 2,
            GardError::TomlError(_) => 5,
            GardError::PolicyValidationError(_) => 5,
            GardError::Internal(_) => 4,
        }
    }
    
    /// Get remediation instructions for this error
    pub fn remediation(&self) -> &str { /* ... */ }
}
```

### `Result` Type

```rust
pub type Result<T> = std::result::Result<T, GardError>;
```

---

## CLI Interface

### `Cli` Struct

```rust
#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    #[arg(long)]
    pub config: Option<String>,      // Custom policy file
    
    #[arg(long)]
    pub data_dir: Option<String>,    // Custom data directory
    
    #[arg(long)]
    pub no_color: bool,              // Disable colors
    
    #[arg(short, long)]
    pub quiet: bool,                 // Suppress output
    
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,                 // Verbosity level
}
```

### Commands

#### `scan`

Run complete audit.

```rust
pub struct ScanCommand {
    #[arg(long, default_value = "plaintext")]
    pub format: String,              // Output format
    
    #[arg(short, long)]
    pub output: Option<String>,      // Write to file
    
    #[arg(short, long)]
    pub verbose: bool,               // Detailed metadata
    
    #[arg(long)]
    pub skip: Option<String>,        // Skip checks (comma-separated)
    
    #[arg(long)]
    pub only: Option<String>,        // Only run checks (comma-separated)
    
    #[arg(long)]
    pub no_sign: bool,               // Don't sign report
}
```

#### `preflight`

Pre-signing checklist.

```rust
pub struct PreflightCommand {
    #[arg(long)]
    pub sign: bool,                  // Prepare for signing
    
    #[arg(long)]
    pub confirm: bool,               // Confirm ready
    
    #[arg(long)]
    pub override_reason: Option<String>, // Override blocking
    
    #[arg(short, long)]
    pub verbose: bool,               // Detailed output
    
    #[arg(long)]
    pub json: bool,                  // JSON output
}
```

#### `config`

Manage policy.

**Subcommands:**
- `init` - Initialize default policy
- `show` - Display current policy
- `validate` - Validate policy file
- `set <check_id> <key> <value>` - Set option
- `check <check_id>` - Check enforcement level
- `suppress <check_id> <reason>` - Suppress finding
- `unsuppress <check_id>` - Remove suppression
- `list-checks` - List available checks

#### `report`

Manage scan results.

```rust
pub struct ReportCommand {
    #[arg(long, default_value = "plaintext")]
    pub format: String,              // Output format
    
    #[arg(short, long)]
    pub output: Option<String>,      // Write to file
    
    #[arg(short, long)]
    pub input: Option<String>,       // Read from file
    
    #[arg(long)]
    pub verify: bool,                // Verify signature
    
    #[arg(long)]
    pub export_key: bool,            // Export public key
    
    #[arg(long)]
    pub summary: bool,               // Summary only
    
    #[arg(long)]
    pub filter: Option<String>,      // Filter findings
}
```

#### `update`

Update Gard.

```rust
pub struct UpdateCommand {
    #[arg(long)]
    pub check: bool,                 // Check for updates
    
    #[arg(long)]
    pub version: Option<String>,     // Specific version
    
    #[arg(long)]
    pub channel: Option<String>,     // Release channel
    
    #[arg(long)]
    pub force: bool,                 // Force update
    
    #[arg(long)]
    pub no_signature_verify: bool,   // Skip signature check
    
    #[arg(long)]
    pub rules_only: bool,            // Update rules only
    
    #[arg(long)]
    pub dry_run: bool,               // Don't actually update
}
```

---

## Output Formatting

### `OutputFormat` Enum

```rust
pub enum OutputFormat {
    Plaintext,    // Terminal output with colors
    Json,         // Compact JSON
    JsonPretty,   // Pretty-printed JSON
    Markdown,     // GitHub-compatible markdown
}
```

### Formatter Functions

```rust
pub fn format_findings_plaintext(
    findings: &[Finding],
    colored: bool,
) -> String;

pub fn format_summary_plaintext(
    summary: &ReportSummary,
    colored: bool,
) -> String;

pub fn format_report_json(report: &Report) -> Result<String>;

pub fn format_report_json_pretty(report: &Report) -> Result<String>;

pub fn format_report_markdown(report: &Report) -> Result<String>;
```

---

## Report Signing

### `ReportSigner` Struct

```rust
pub struct ReportSigner {
    signing_key: SigningKey,
}

impl ReportSigner {
    /// Create new signer (loads or creates keypair)
    pub fn new() -> Result<Self>;
    
    /// Sign a report
    pub fn sign_report(&self, report: &mut Report) -> Result<()>;
    
    /// Get public key as hex
    pub fn public_key_hex(&self) -> String;
}

/// Verify a signed report
pub fn verify_report(report: &Report) -> Result<bool>;
```

**Keypair Storage:**
- Private key: `~/.gard/keys/ed25519` (32 bytes)
- Public key: `~/.gard/keys/ed25519.pub` (OpenSSH format)

---

## Policy Configuration

### `Config` Struct

```rust
pub struct Config;

impl Config {
    /// Load policy from file or defaults
    pub fn load() -> Result<Policy>;
    
    /// Load policy from specific path
    pub fn load_from(path: &Path) -> Result<Policy>;
    
    /// Get default policy path
    pub fn policy_path() -> Result<PathBuf>;
    
    /// Save policy to file
    pub fn save(policy: &Policy) -> Result<()>;
}
```

---

## Check Registry

### `CheckRegistry` Struct

```rust
pub struct CheckRegistry {
    checks: HashMap<String, Arc<dyn CheckModule>>,
}

impl CheckRegistry {
    /// Create registry with all checks
    pub fn new() -> Self;
    
    /// Register a check
    pub fn register(&mut self, check: Arc<dyn CheckModule>);
    
    /// Get check by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn CheckModule>>;
    
    /// Get all checks
    pub fn all(&self) -> Vec<Arc<dyn CheckModule>>;
    
    /// Get checks for platform
    pub fn for_platform(&self, platform: Platform) -> Vec<Arc<dyn CheckModule>>;
    
    /// Run all checks
    pub fn run_all(&self) -> Result<Vec<Finding>>;
    
    /// Run matching checks
    pub fn run_matching(&self, ids: &[String]) -> Result<Vec<Finding>>;
}
```

---

## Commands Module

### `execute_command` Function

```rust
pub async fn execute_command(
    command: Commands,
    cli: &Cli,
) -> Result<u8>;  // Returns exit code
```

### Individual Command Functions

```rust
pub async fn scan(cmd: ScanCommand, cli: &Cli) -> Result<Report>;
pub async fn preflight(cmd: PreflightCommand, cli: &Cli) -> Result<()>;
pub async fn config(cmd: ConfigCommand, cli: &Cli) -> Result<()>;
pub async fn report(cmd: ReportCommand, cli: &Cli) -> Result<()>;
pub async fn update(cmd: UpdateCommand, cli: &Cli) -> Result<()>;
```

---

## Exit Codes

| Code | Meaning | Cause |
|------|---------|-------|
| 0 | Success | No errors |
| 1 | Findings found | Check found issues (check scan) |
| 2 | Preflight failed | Blocking finding during preflight |
| 3 | Permission error | Need elevated privileges or platform error |
| 4 | Internal error | Bug in Gard |
| 5 | Configuration error | Invalid policy or configuration |

---

## Environment Variables

### Configuration

- `RUST_LOG` - Set logging level (trace, debug, info, warn, error)
- `GARD_CONFIG` - Override policy file location
- `GARD_DATA_DIR` - Override data directory

### Integration

- `CI` - Set when running in CI/CD (affects output)
- `GITHUB_ACTIONS` - Set when running in GitHub Actions

---

## File Paths

### Standard Locations

| File | Location |
|------|----------|
| Policy | `~/.gard/policy.toml` |
| Private key | `~/.gard/keys/ed25519` |
| Public key | `~/.gard/keys/ed25519.pub` |
| Cache | `~/.gard/cache/` |

### Custom Locations

```bash
gard --config /custom/path/policy.toml --data-dir /custom/gard/dir
```

---

## JSON Report Format

```json
{
  "metadata": {
    "version": "1.0",
    "gard_version": "0.1.0",
    "timestamp": "2026-04-15T12:34:56Z",
    "hostname": "vault-machine",
    "username": "alice",
    "platform": "Linux",
    "scan_duration_ms": 2340,
    "signature": "abc123def456...",
    "public_key": "ed25519 abc123...",
    "signed": true
  },
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "id": "f_000001",
      "check_id": "env-key-leakage",
      "check_name": "Environment Variable Audit",
      "severity": "Critical",
      "platform": "Linux",
      "description": "Keypair environment variable found",
      "remediation": "Remove from shell environment",
      "blocking": true,
      "timestamp": "2026-04-15T12:34:56Z",
      "details": {
        "variable_name": "SOLANA_KEYPAIR",
        "source": ".bashrc"
      }
    }
  ]
}
```

---

## Integration Examples

### Rust Library Integration

```rust
use gard::checks::CheckRegistry;
use gard::types::Platform;

let registry = CheckRegistry::new();

// Get all checks for current platform
let checks = registry.for_platform(Platform::Linux);

// Run all checks
let findings = registry.run_all()?;

// Filter findings
let critical = findings
    .into_iter()
    .filter(|f| f.severity == Severity::Critical)
    .collect::<Vec<_>>();
```

### CLI Integration

```bash
#!/bin/bash

# Run scan and capture findings
gard scan --format json --output report.json

# Verify report is signed
if ! gard report --input report.json --verify; then
    echo "Report signature verification failed"
    exit 1
fi

# Export public key for verification
gard report --input report.json --export-key
```

---

## Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Full scan | ~2-5s | Depends on check complexity |
| Preflight | ~1-3s | Subset of checks |
| Policy load | <10ms | Cached after first load |
| Report sign | ~5ms | Ed25519 operation |
| Report verify | ~10ms | Signature validation |

---

## Version Compatibility

**Report Format Version:** 1.0
- Bumped when report structure changes incompatibly
- Backward compatibility maintained when possible
- Version field in metadata for migration

**Gard Version:** Semantic versioning (major.minor.patch)
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes

---

## See Also

- [User Guide](user_guide.md) - End-user documentation
- [Developer Guide](developer_guide.md) - Development information
- [Architecture](architecture.md) - Design decisions
- [Research](research.md) - Threat modeling
