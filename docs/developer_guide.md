# Gard Developer Guide

## Project Structure

```
gard/
├── crates/
│   └── gard/
│       ├── src/
│       │   ├── main.rs              # CLI entry point
│       │   ├── lib.rs               # Library root, module declarations
│       │   ├── cli.rs               # Command-line argument definitions
│       │   ├── error.rs             # Error types and handling
│       │   ├── types.rs             # Core data structures
│       │   ├── output.rs            # Report formatting (plaintext, JSON, markdown)
│       │   ├── checks/
│       │   │   ├── mod.rs           # Check trait definition
│       │   │   ├── registry.rs      # Check discovery and execution
│       │   │   ├── env_variables.rs # Environment variable audit (implemented)
│       │   │   ├── vscode_workspace.rs
│       │   │   ├── vscode_extension.rs
│       │   │   ├── clipboard_monitor.rs
│       │   │   ├── ssh_hygiene.rs
│       │   │   ├── open_ports.rs
│       │   │   ├── software_wallets.rs
│       │   │   ├── unsigned_binaries.rs
│       │   │   ├── solana_config.rs
│       │   │   ├── solana_nonce.rs
│       │   │   ├── hardware_wallet.rs
│       │   │   └── browser_extensions.rs
│       │   ├── commands/
│       │   │   ├── mod.rs           # Command dispatcher
│       │   │   ├── scan.rs          # Full audit command
│       │   │   ├── preflight.rs     # Pre-signing checklist
│       │   │   ├── config.rs        # Policy management
│       │   │   ├── report.rs        # Report viewing and export
│       │   │   └── update.rs        # Binary and rule updates
│       │   ├── config/
│       │   │   └── mod.rs           # Policy loading and validation
│       │   └── report/
│       │       └── mod.rs           # Report signing with Ed25519
│       ├── Cargo.toml               # Binary crate dependencies
│       └── tests/
│           └── integration_tests.rs
├── Cargo.toml                        # Workspace root
├── Cargo.lock
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Tests and linting
│       └── release.yml              # Release automation
├── docs/
│   ├── README.md
│   ├── research.md                  # Threat modeling
│   ├── architecture.md              # Design documentation
│   ├── user_guide.md                # User documentation
│   ├── developer_guide.md           # This file
│   └── api_reference.md             # API documentation
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

## Development Setup

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- C compiler (gcc/clang for native dependencies)
- Git

### Clone and Build

```bash
git clone https://github.com/gard/gard.git
cd gard

# Build debug binary
cargo build

# Build release binary
cargo build --release

# Run tests
cargo test --all

# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Security audit
cargo audit
```

### Development Workflow

```bash
# 1. Make your changes
# 2. Run tests locally
cargo test --all

# 3. Check code quality
cargo fmt --check
cargo clippy -- -D warnings

# 4. Build binary
cargo build --release

# 5. Test binary
./target/release/gard scan

# 6. Commit and push
git add .
git commit -m "Description of changes"
git push origin feature-branch
```

## Core Architecture

### Check Module System

Every security check implements the `CheckModule` trait:

```rust
pub trait CheckModule: Send + Sync {
    fn id(&self) -> &str;                          // Unique identifier
    fn name(&self) -> &str;                        // Human-readable name
    fn description(&self) -> &str;                 // Full description
    fn severity(&self) -> Severity;                // CRITICAL, HIGH, MEDIUM, LOW, INFO
    fn blocking_in_preflight(&self) -> bool;       // Blocks signing if blocking=true + finding
    fn platforms(&self) -> &[Platform];            // MacOS, Linux, Windows
    fn remediation(&self) -> &str;                 // How to fix the issue
    fn run(&self) -> Result<Vec<Finding>>;         // Execute the check
}
```

### Check Implementation Template

```rust
// src/checks/my_check.rs

use crate::checks::CheckModule;
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;

pub struct MyCheck;

impl CheckModule for MyCheck {
    fn id(&self) -> &str {
        "my-check-id"
    }

    fn name(&self) -> &str {
        "My Check Name"
    }

    fn description(&self) -> &str {
        "Detailed description of what this check does"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn blocking_in_preflight(&self) -> bool {
        true  // or false for non-blocking
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn remediation(&self) -> &str {
        "Step-by-step instructions to fix the issue"
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Detection logic here
        if some_condition {
            findings.push(Finding {
                id: "f_000001".to_string(),
                check_id: self.id().to_string(),
                check_name: self.name().to_string(),
                severity: self.severity(),
                platform: crate::types::current_platform(),
                description: "Issue found: ...".to_string(),
                remediation: self.remediation().to_string(),
                blocking: self.blocking_in_preflight(),
                timestamp: chrono::Utc::now(),
                details: json!({
                    "key": "value",
                    "other_info": 123
                }),
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_metadata() {
        let check = MyCheck;
        assert_eq!(check.id(), "my-check-id");
        assert!(check.blocking_in_preflight());
    }
}
```

### Register New Check

Add to `src/checks/mod.rs`:

```rust
pub mod my_check;
```

Add instantiation to `src/checks/registry.rs`:

```rust
use crate::checks::my_check::MyCheck;

impl CheckRegistry {
    pub fn new() -> Self {
        let mut registry = CheckRegistry {
            checks: HashMap::new(),
        };
        
        // Register all checks
        registry.register(Arc::new(MyCheck));
        
        registry
    }
}
```

## Error Handling

All functions return `Result<T>` which is `std::result::Result<T, GardError>`.

Error types in `src/error.rs`:

```rust
pub enum GardError {
    ConfigurationError(String),      // Policy/config issues
    CheckExecutionError { 
        check_name: String, 
        reason: String 
    },                               // Check failed to run
    PermissionDenied,                // Need elevated privileges
    PlatformUnsupported,             // Not on required platform
    NetworkError(String),            // Network/download failed
    SignatureVerificationFailed,     // Report signature invalid
    InvalidReportFormat,             // Report file corrupted
    IoError(std::io::Error),         // File/directory operations
    JsonError(serde_json::Error),    // JSON serialization
    TomlError(toml::de::Error),      // TOML parsing
    PolicyValidationError(String),   // Policy file invalid
    Internal(String),                // Internal bug
}

impl GardError {
    pub fn exit_code(&self) -> u8 { ... }  // Exit codes
    pub fn remediation(&self) -> &str { ... }  // User guidance
}
```

## Output Formatting

Available formats in `src/output.rs`:

```rust
pub enum OutputFormat {
    Plaintext,        // Human-readable, colored terminal output
    Json,             // Compact JSON
    JsonPretty,       // Indented JSON
    Markdown,         // GitHub-compatible markdown
}
```

### Custom Formatters

To add a new format:

1. Add variant to `OutputFormat` enum
2. Implement `format_findings_*()` and `format_report_*()` functions
3. Update `match` statements in formatter functions

## Testing

### Test Structure

```
crates/gard/tests/
├── check_env_variables_test.rs
├── check_vscode_test.rs
├── cli_test.rs
├── config_test.rs
└── report_signing_test.rs
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_finds_issue() {
        let check = EnvVariablesCheck;
        let findings = check.run().unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_check_no_false_positives() {
        // Set up clean environment
        let check = MyCheck;
        let findings = check.run().unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_command_execution() {
        let result = commands::execute_command(/* ... */).await;
        assert!(result.is_ok());
    }
}
```

### Run Tests

```bash
# All tests
cargo test --all

# Specific test
cargo test test_check_finds_issue

# Integration tests only
cargo test --test '*' --all

# With output
cargo test -- --nocapture

# Verbose
cargo test -- --verbose
```

## Cross-Platform Checks

CI compiles and tests on Linux and macOS. To exercise the Linux-only code paths
(`cfg(target_os = "linux")`) from a Mac without Docker, let Apple's clang act as
the cross C compiler that `ring` needs:

```bash
rustup target add x86_64-unknown-linux-gnu
SDK=$(xcrun --show-sdk-path)
export CC_x86_64_unknown_linux_gnu=clang
export AR_x86_64_unknown_linux_gnu=ar
export CFLAGS_x86_64_unknown_linux_gnu="--target=x86_64-unknown-linux-gnu -isystem $SDK/usr/include -Wno-everything"
cargo check  --target x86_64-unknown-linux-gnu
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
```

This type-checks and lints the Linux build; it does not produce a runnable
binary (link with a real Linux toolchain or use CI for that).

For Windows, install `mingw-w64` from Homebrew and check the GNU target:

```bash
rustup target add x86_64-pc-windows-gnu
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
cargo check --target x86_64-pc-windows-gnu
```

## Dependency Management

All dependencies are declared in `Cargo.toml` with justifications.

### Adding Dependencies

1. Add to workspace `Cargo.toml`:
   ```toml
   [workspace.dependencies]
   my_crate = "1.0"
   ```

2. Reference in binary crate `Cargo.toml`:
   ```toml
   my_crate = { workspace = true }
   ```

3. Run `cargo audit` to check for security issues

4. Update `docs/architecture.md` with justification

## Release Process

See `.github/workflows/release.yml` for automation.

Manual release:

```bash
# 1. Update version in Cargo.toml
# 2. Update CHANGELOG.md
# 3. Build release binary
cargo build --release

# 4. Create git tag
git tag v0.2.0

# 5. Push tag (triggers GitHub Actions release)
git push origin v0.2.0
```

## Performance Considerations

### Optimization Guidelines

1. **Async I/O**: Use `tokio` for file/network operations
2. **Parallel Checks**: Run independent checks in parallel
3. **Minimal Dependencies**: Keep binary lean and fast
4. **Caching**: Cache repeated lookups (processes, configurations)

### Profiling

```bash
# CPU profiling
cargo build --release
perf record -g ./target/release/gard scan
perf report

# Memory usage
/usr/bin/time -v ./target/release/gard scan
```

## Security Considerations

### For Contributors

1. **No unsafe code** without explicit justification
2. **Validate all input** from environment, files, network
3. **Use type system** for validation where possible
4. **Handle errors gracefully** - don't panic
5. **Audit dependencies** - review new additions

### Security Scanning

```bash
# Dependency vulnerabilities
cargo audit

# Supply chain
cargo deny check

# Code quality
cargo clippy -- -D warnings
```

## Debugging

### Enable Debug Logging

```bash
# Standard output
RUST_LOG=debug cargo run

# More verbose
RUST_LOG=trace,gard=debug cargo run

# File output
RUST_LOG=debug cargo run 2> debug.log
```

### Debugging with GDB

```bash
# Compile with debug symbols
cargo build

# Run in debugger
gdb ./target/debug/gard

# Inside GDB
(gdb) run scan
(gdb) bt  # backtrace
(gdb) print variable_name
```

## Documentation

### Update Documentation When

- Adding new commands or options
- Changing error messages
- Modifying check behavior
- Adding new dependencies

### Documentation Files

- **README.md**: Overview and installation
- **user_guide.md**: End-user documentation
- **developer_guide.md**: This file
- **api_reference.md**: API documentation
- **architecture.md**: Design decisions
- **research.md**: Threat modeling

## Contributing

### PR Process

1. Fork repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes and test: `cargo test --all`
4. Format: `cargo fmt`
5. Lint: `cargo clippy -- -D warnings`
6. Commit with clear message
7. Push and create pull request
8. Address review feedback

### Code Style

- Follow Rust idioms and conventions
- Use descriptive variable names
- Comment non-obvious logic
- Keep functions focused and small
- Maximum line length: 100 characters (prefer less)

### Review Checklist

- Tests pass: `cargo test --all`
- Formatting correct: `cargo fmt --check`
- No clippy warnings: `cargo clippy -- -D warnings`
- No new vulnerabilities: `cargo audit`
- Documentation updated
- Commit messages clear

## Useful Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Clap Documentation](https://docs.rs/clap/latest/clap/)
- [Serde Documentation](https://serde.rs/)

## Troubleshooting

### Build Issues

**"error: linker 'cc' not found"**
```bash
# Install build tools
sudo apt-get install build-essential  # Linux
brew install gcc  # macOS
```

**"error\[E0514\]: found crate which does not match"**
```bash
# Clean build
cargo clean
cargo build
```

### Test Issues

**Tests hang**
```bash
# Run with timeout
timeout 60 cargo test
```

**Intermittent test failures**
```bash
# Run tests sequentially
cargo test -- --test-threads=1
```

## Getting Help

- **Issues**: GitHub Issues for bugs and features
- **Discussions**: GitHub Discussions for questions
- **Security**: security@gard.dev for security issues
- **Development**: Discord channel for real-time help

## Code of Conduct

See [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) for expectations.
