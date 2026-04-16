# Gard User Guide

## Introduction

Gard is a command-line tool that enforces signing hygiene and detects dangerous machine configurations for Solana protocol teams. It runs a comprehensive audit of your local machine, identifies security misconfigurations that could lead to keypair compromise, and provides actionable remediation guidance.

## Installation

### From Release Binary

```bash
# Download the latest release
curl -L https://github.com/gard/releases/latest/download/gard-$(uname -s)-$(uname -m) -o gard
chmod +x gard
sudo mv gard /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/gard/gard.git
cd gard
cargo install --path crates/gard
```

### Verify Installation

```bash
gard --version
gard --help
```

## Quick Start

### 1. Run a Complete Audit

```bash
gard scan
```

This runs all security checks against your local machine and outputs results in a human-readable format.

**Output:**
```
Gard Security Scan Report
=======================

CRITICAL (Blocking):
  [env-key-leakage] Keypair environment variable found
  - Variable: SOLANA_KEYPAIR
  - Source: .bashrc
  - Remediation: Remove keypair paths from shell environment

Scan Summary:
  Duration: 2.34s
  Checks Run: 13
  Findings: 3
  Critical: 1 (blocking)
  High: 2 (non-blocking)
```

### 2. Run Pre-Signing Checklist

```bash
gard preflight
```

Runs mandatory checks before signing ceremonies. Blocks if critical findings are present.

**With confirmation:**
```bash
gard preflight --confirm
```

**Override blocking issues (with justification):**
```bash
gard preflight --override-reason "Issue documented and mitigated"
```

### 3. Export Results

```bash
# JSON format for programmatic processing
gard scan --format json --output scan_report.json

# JSON-pretty for human review
gard scan --format json-pretty --output report.json

# Markdown for documentation
gard scan --format markdown --output report.md
```

### 4. Sign a Report

```bash
gard scan --output report.json
gard report --input report.json --verify --export-key
```

## Check Modules

Gard runs 13 comprehensive security checks:

### Critical (Blocking in Preflight)

1. **Environment Variables Audit** (`env-key-leakage`)
   - Detects keypair paths and secret environment variables
   - Scans shell profiles, process environment, CI configuration
   - **Severity:** CRITICAL | **Blocking:** Yes

2. **VSCode Workspace Audit** (`vscode-workspace`)
   - Detects secrets committed in VS Code settings
   - Checks for exposed API keys and credentials
   - **Severity:** CRITICAL | **Blocking:** Yes

3. **VSCode Extension Security** (`vscode-extension`)
   - Detects compromised or suspicious extensions
   - Validates extension permissions and sources
   - **Severity:** CRITICAL | **Blocking:** Yes

4. **Clipboard Monitor Detection** (`clipboard-monitor`)
   - Detects clipboard monitoring processes (like macOS PasteNow)
   - Identifies active clipboard access
   - **Severity:** CRITICAL | **Blocking:** Yes

5. **Hardware Wallet Communication** (`hardware-wallet`)
   - Ensures hardware wallets are connected and accessible
   - Validates firmware versions
   - **Severity:** CRITICAL | **Blocking:** Yes

6. **Solana Configuration Audit** (`solana-config`)
   - Checks Solana CLI configuration for security issues
   - Detects keypair storage insecurity
   - **Severity:** CRITICAL | **Blocking:** Yes

7. **Durable Nonce Configuration** (`solana-nonce`)
   - Validates durable nonce authority and security
   - Prevents nonce key reuse across ceremonies
   - **Severity:** CRITICAL | **Blocking:** Yes

### High (Non-blocking but Recommended)

8. **SSH Security Hygiene** (`ssh-hygiene`)
   - Checks SSH key permissions and agent configuration
   - Detects disabled key protections
   - **Severity:** HIGH | **Blocking:** No

9. **Open Ports Audit** (`open-ports`)
   - Detects unexpected open network ports
   - Identifies listening services
   - **Severity:** HIGH | **Blocking:** No

10. **Unsigned Binaries** (`unsigned-binaries`)
    - Detects unsigned or self-signed binaries in PATH
    - Validates binary signatures
    - **Severity:** HIGH | **Blocking:** No

### Medium (Recommended for Compliance)

11. **Software Wallet Detection** (`software-wallets`)
    - Detects software wallets (MetaMask, Phantom, etc.)
    - Warns about key exposure risks
    - **Severity:** MEDIUM | **Blocking:** No

12. **Browser Extensions Audit** (`browser-extensions`)
    - Detects suspicious browser extensions
    - Checks for known malicious extensions
    - **Severity:** MEDIUM | **Blocking:** No

13. **System Configuration** (`system-config`)
    - General system security checks
    - OS-specific security settings
    - **Severity:** MEDIUM | **Blocking:** No

## Configuration

### Policy Management

Create or edit `~/.gard/policy.toml`:

```toml
# Global enforcement level: enforce, warn, silent
[default]
enforcement = "enforce"

# Per-check overrides
["env-key-leakage"]
enforcement = "enforce"
blocking = true

["software-wallets"]
enforcement = "warn"
blocking = false

# Suppression with expiry
["open-ports"]
enforcement = "warn"
suppressed = true
suppressed_until = "2026-04-15T00:00:00Z"
suppression_reason = "Known safe service, documented in OPSEC plan"
```

### Configure Policy

```bash
# Initialize default policy
gard config init

# Show current policy
gard config show

# Validate policy file
gard config validate

# Set specific check enforcement
gard config set env-key-leakage enforcement enforce

# List all available checks
gard config list-checks

# Suppress a finding temporarily
gard config suppress open-ports "Documented safe service"

# Remove suppression
gard config unsuppress open-ports
```

## Signing Ceremony Workflow

### Safe Signing Ceremony Procedure

1. **Prepare Machine**
   ```bash
   # Run full audit
   gard scan --output pre_scan.json
   
   # Review all findings
   gard report --input pre_scan.json --format markdown --output pre_scan.md
   ```

2. **Run Preflight**
   ```bash
   # Mandatory preflight check
   gard preflight --verbose
   
   # If issues exist, either:
   # a) Fix them
   # b) Document and override with justification
   gard preflight --confirm --override-reason "All findings documented in OPSEC plan"
   ```

3. **Execute Signing Ceremony**
   ```bash
   # Proceed with signing ceremony only after preflight passes
   solana-keygen grind --starts-with <PREFIX>
   ```

4. **Post-Ceremony Verification**
   ```bash
   # Run audit after signing
   gard scan --output post_scan.json
   
   # Sign and archive report
   gard report --input post_scan.json --format json --output signed_report.json
   ```

## Report Management

### View Reports

```bash
# Show summary only
gard report --input report.json --summary

# Filter by severity
gard report --input report.json --filter "CRITICAL|HIGH"

# Export findings as JSON
gard report --input report.json --export-key --format json --output exported.json
```

### Verify Signed Reports

```bash
# Verify signature
gard report --input report.json --verify

# Get signer public key
gard report --input report.json --export-key
```

## Binary Updates

### Check for Updates

```bash
# Check available updates
gard update check

# Check specific version
gard update check --version 0.2.0

# Check specific release channel
gard update check --channel stable
```

### Update Gard

```bash
# Perform update with signature verification
gard update

# Update rules only (check definitions)
gard update --rules-only

# Dry-run to see what would change
gard update --dry-run

# Force update
gard update --force
```

## Troubleshooting

### No findings reported, but I know there are issues

1. **Check is disabled**: Verify in `~/.gard/policy.toml` that the check isn't suppressed
2. **Permissions**: Gard needs to read shell configs and process environment
3. **Platform mismatch**: Some checks are platform-specific (macOS, Linux, Windows)

```bash
# List all available checks for your platform
gard config list-checks

# Enable verbose logging
gard scan -vvv
```

### "Permission denied" errors

Gard reads system configuration files that may require elevated permissions:

```bash
# Run with appropriate permissions
sudo gard scan
```

### Report verification fails

1. **Wrong key**: Ensure you're using the public key from the signer's machine
2. **Corrupted report**: Check file integrity
3. **Version mismatch**: Different Gard versions may be incompatible

### Preflight blocking legitimate findings

Use the override mechanism with proper documentation:

```bash
gard preflight \
  --confirm \
  --override-reason "Finding X documented in OPSEC-2026-Q2.md, mitigated with procedure Y"
```

## Examples

### Team OPSEC Validation

```bash
#!/bin/bash
# Run gard on all team machines before ceremony

for team_member in alice bob charlie; do
  ssh "$team_member@vault-machine" \
    "gard scan --format json --output report_$(date +%s).json"
  scp "$team_member@vault-machine:report_*.json" "./reports/"
done

# Analyze all reports
for report in reports/*.json; do
  echo "=== $report ==="
  gard report --input "$report" --summary
done
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Pre-Signing OPSEC Check

on: [push, pull_request]

jobs:
  gard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Gard security scan
        run: |
          gard scan --format json --output gard_report.json
          gard report --input gard_report.json --summary
      - name: Archive report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: gard-report
          path: gard_report.json
```

### Custom Policy Enforcement

```bash
# Create strict policy for vault machines
cat > ~/.gard/policy.toml << 'EOF'
[default]
enforcement = "enforce"

# All critical checks mandatory
["env-key-leakage"]
enforcement = "enforce"
blocking = true

["vscode-workspace"]
enforcement = "enforce"
blocking = true

["vscode-extension"]
enforcement = "enforce"
blocking = true

["clipboard-monitor"]
enforcement = "enforce"
blocking = true

["hardware-wallet"]
enforcement = "enforce"
blocking = true

["solana-config"]
enforcement = "enforce"
blocking = true

["solana-nonce"]
enforcement = "enforce"
blocking = true

# Suppress only with explicit documentation
["open-ports"]
enforcement = "warn"
suppressed = false
EOF

# Validate policy
gard config validate

# Run with strict policy
gard preflight --verbose
```

## Advanced Usage

### Integration with OPSEC Procedures

Embed Gard into your operational security procedures:

```bash
# Pre-signing ceremony checklist
cat > pre_ceremony_checks.sh << 'EOF'
#!/bin/bash
set -e

echo "=== Pre-Ceremony OPSEC Validation ==="

# 1. Machine isolation
echo "[1/4] Verifying network isolation..."
gard scan --only open-ports --format json | grep -q CRITICAL && {
  echo "ERROR: Open ports detected"
  exit 1
}

# 2. Key isolation
echo "[2/4] Verifying key isolation..."
gard scan --only env-key-leakage --format json | grep -q CRITICAL && {
  echo "ERROR: Keypair exposure detected"
  exit 1
}

# 3. Hardware wallet
echo "[3/4] Verifying hardware wallet..."
gard scan --only hardware-wallet --format json | grep -q CRITICAL && {
  echo "ERROR: Hardware wallet not ready"
  exit 1
}

# 4. Signing readiness
echo "[4/4] Running preflight..."
gard preflight --confirm

echo "✓ All checks passed, ready for ceremony"
EOF

chmod +x pre_ceremony_checks.sh
```

### Continuous Compliance Monitoring

```bash
# Run daily compliance scan via cron
0 0 * * * /usr/local/bin/gard scan --format json --output /var/log/gard/daily_$(date +\%Y\%m\%d).json

# Weekly summary
0 0 * * 0 /usr/local/bin/gard report --input /var/log/gard/daily_*.json --summary
```

## Security Considerations

### Running Gard

- **Gard is non-invasive**: It only reads configuration files and system state, never modifies anything
- **Elevated privileges**: Some checks require reading protected files (use `sudo` if needed)
- **Network access**: Update checks require outbound HTTPS to GitHub releases

### Report Security

- Reports are signed with Ed25519
- Public key is exported separately for verification
- Archive reports separately from signing keys
- Use version control for policy files, not for report files

### Limitations

- Gard cannot detect everything (e.g., sophisticated malware)
- Some checks are operating-system specific
- False positives possible with non-standard configurations
- Requires recent file permissions (cannot detect deleted files)

## Getting Help

```bash
# General help
gard --help

# Command-specific help
gard scan --help
gard preflight --help
gard config --help

# Verbose output for debugging
gard -vvv scan

# Report a bug
# https://github.com/gard/issues
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no issues found |
| 1 | One or more findings reported |
| 2 | Preflight failed (blocking finding) |
| 3 | Execution error (permission denied, file not found, etc.) |
| 4 | Internal error (bug in Gard) |
| 5 | Configuration error |

## Version History

See [CHANGELOG.md](../CHANGELOG.md) for detailed version history.

## License

Gard is licensed under the Business Source License (BSL-1.1). See [LICENSE](../LICENSE) for details.
