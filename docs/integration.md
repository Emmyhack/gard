# Gard Integration Guide

For protocol teams, DevOps leads, and CI/CD engineers responsible for enforcing Gard across contributor teams.

---

## 1. Enforcing Gard in Contributor Onboarding

Follow these steps to add Gard to your contributor onboarding checklist and signer certification workflow.

### Step-by-step Onboarding Process

1. **Send onboarding document** to new contributor with Gard installation instructions.
   - Install from binary: `curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-x86_64-apple-darwin -o gard && chmod +x gard && sudo mv gard /usr/local/bin/`
   - Or from source: `git clone https://github.com/nextlevelbuilder/gard.git && cd gard && cargo build --release`
   - Verify: `gard --version`

2. **Contributor runs initial audit** on their development machine.
   ```bash
   gard scan --output onboarding-scan.json
   ```
   - Exit code 0: Clean machine, ready to proceed
   - Exit code 1: Findings present, must address before proceeding
   - Exit code 2+: Error, retry or contact team lead

3. **Review findings** with contributor if exit code is 1.
   ```bash
   gard report --input onboarding-scan.json --format markdown -o onboarding-findings.md
   ```
   - Discuss each finding with contributor
   - Determine if issues are machine-specific, tool-specific, or environmental
   - For items that cannot be remediated (e.g., TestFlight on signer machine): document exception

4. **Remediation verification** for blocking findings.
   - Have contributor address findings per remediation steps in output
   - After remediation, re-run: `gard scan --output onboarding-scan-2.json`
   - Continue until exit code is 0

5. **Signer certification** once findings are addressed.
   - Run preflight check: `gard preflight --confirm`
   - If exit code 0: Contributor is certified as signing-ready
   - If exit code 1: Blocking finding present, must address before signing
   - Document certification timestamp and findings

### Unsupported Machines

For contributors whose machines cannot run Gard (unsupported OS, restricted environment):

1. **Determine why** Gard cannot run (Windows OS, restricted Linux environment, corporate proxy, etc.)
2. **Document exception** in team OPSEC plan with justification
3. **Provide manual checks** equivalent to Gard output (e.g., "Confirm no wallet software installed", "Confirm SSH agent not forwarded")
4. **Quarterly re-verification** - Gard not available doesn't mean exceptions are permanent

### Machines That Fail Repeatedly

If a contributor's machine fails the same checks repeatedly:

1. **Investigate root cause** - Is this environmental, or is the contributor ignoring guidance?
2. **Escalate to security lead** if required findings cannot be remediated
3. **Rotate responsibility** - If machine cannot be used for signing, assign non-signing duties

---

## 2. Enforcing Preflight in Multisig Ceremony Workflows

Procedure for a multisig coordinator to require preflight reports from all signers before initiating a signing ceremony.

### Pre-Ceremony Signer Checklist

**Coordinator communicates to signers (48 hours before ceremony):**

1. Each signer must generate their public key:
   ```bash
   gard keys show
   ```
   Example output: `HpQoACyKBXL8Jv3nQnBX3FpG8K2V9j4R5mL7n8Q2KpRs`

2. Signer stores this public key (safe to share publicly)

3. Signer generates preflight report:
   ```bash
   gard preflight --json > preflight-report.json
   ```

4. Signer signs the report with signing key (if required by ceremony):
   ```bash
   gard report --input preflight-report.json --verify
   ```

5. Signer submits preflight-report.json to ceremony coordinator

### Coordinator Verification Procedure

**Coordinator receives all signer preflight reports:**

1. **Verify report format** - Each report must be valid JSON (not truncated, not corrupted)
   ```bash
   jq . preflight-report-signer1.json > /dev/null 2>&1 && echo "Valid JSON" || echo "Invalid JSON"
   ```

2. **Verify report signature** - Check that report passes signature verification with signer's public key:
   ```bash
   gard report verify --public-key HpQoACyKBXL8Jv3nQnBX3FpG8K2V9j4R5mL7n8Q2KpRs --report preflight-report-signer1.json
   ```
   - Exit code 0: Signature valid, report is authentic
   - Exit code 1: Signature invalid, report may be tampered
   - Exit code 2: Verification error, retry or contact Gard support

3. **Check findings in each report**:
   ```bash
   jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' preflight-report-signer1.json
   ```
   - If any CRITICAL or HIGH severity findings: see "Handling Preflight Failures" below
   - If all findings are LOW or INFO: proceed with ceremony

4. **Document signer status**:
   ```
   Signer: Alice (ed25519 public key HpQoACyK...)
   Preflight: PASSED (submitted 2026-04-27T14:32:00Z)
   Findings: 1 INFO (outdated Solana CLI version)
   Override: None
   Status: CLEARED FOR SIGNING
   ```

### Example: Valid Preflight Report Structure

```json
{
  "metadata": {
    "timestamp": "2026-04-27T14:32:00Z",
    "version": "0.1.0",
    "public_key": "ed25519 HpQoACyKBXL8Jv3nQnBX3FpG8K2V9j4R5mL7n8Q2KpRs",
    "signature": "a1b2c3d4e5f6... (hex-encoded Ed25519 signature)",
    "signed": true,
    "preflight_result": "pass"
  },
  "findings": [
    {
      "id": "finding-001",
      "check_id": "env-key-leakage",
      "check_name": "Environment Variable Audit",
      "severity": "INFO",
      "platform": "macOS",
      "blocking": false,
      "description": "No sensitive environment variables detected"
    }
  ],
  "summary": {
    "checks_run": 13,
    "findings_total": 1,
    "findings_critical": 0,
    "findings_high": 0,
    "findings_medium": 0,
    "findings_low": 0,
    "findings_info": 1
  }
}
```

### Handling Preflight Failures

**If a signer's preflight report shows CRITICAL or HIGH findings:**

1. **Contact signer immediately** (24+ hours before ceremony)
   - "Your machine has a blocking finding that must be addressed before signing"
   - Provide the finding details and remediation steps

2. **Signer remediates** the issue on their machine

3. **Signer re-runs preflight**:
   ```bash
   gard preflight --json > preflight-report-REVISED.json
   ```

4. **Coordinator re-verifies** the revised report

5. **If still failing**: Consider rescheduling ceremony or removing signer from this ceremony

### Handling Preflight Overrides

**If a signer uses `--override` flag to bypass a blocking finding:**

Signer does:
```bash
gard preflight --override "TestFlight wallet isolated on non-signing machine, documented in exception list" --confirm --json > preflight-report.json
```

Coordinator sees in report:
```json
"metadata": {
  "preflight_result": "override",
  "override_reason": "TestFlight wallet isolated on non-signing machine, documented in exception list",
  "override_timestamp": "2026-04-27T14:32:00Z"
}
```

**Coordinator must:**
1. Review override reason
2. Check exception list to verify override is documented
3. Obtain explicit approval from security lead before allowing signer to proceed
4. Document override in ceremony log with security lead sign-off

Override is only acceptable when:
- Finding is non-security-critical (e.g., outdated documentation)
- Specific mitigation is documented (e.g., TestFlight on isolated device)
- Security lead has explicitly approved the exception
- Override reason can be traced back to a specific OPSEC decision

---

## 3. CI Integration

GitHub Actions workflow snippet to enforce Gard in your CI/CD pipeline.

```yaml
name: Gard Security Check

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  gard-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # Install Gard from binary (cached between runs)
      - name: Cache Gard binary
        uses: actions/cache@v3
        id: cache-gard
        with:
          path: ~/.cargo/bin/gard
          key: gard-v0.1.0-${{ runner.os }}-${{ runner.arch }}
      
      - name: Install Gard
        if: steps.cache-gard.outputs.cache-hit != 'true'
        run: |
          curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-x86_64-unknown-linux-gnu -o gard
          chmod +x gard
          mkdir -p ~/.cargo/bin && mv gard ~/.cargo/bin/
      
      # Run Gard scan
      - name: Run Gard scan
        id: gard
        run: |
          ~/.cargo/bin/gard scan --output gard-report.json --no-sign || EXIT_CODE=$?
          echo "exit_code=${EXIT_CODE:-0}" >> $GITHUB_OUTPUT
      
      # Upload report as artifact
      - name: Upload Gard report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: gard-report
          path: gard-report.json
      
      # Fail workflow if findings present (exit code 1)
      - name: Check Gard results
        run: |
          EXIT_CODE=${{ steps.gard.outputs.exit_code }}
          if [ "$EXIT_CODE" = "1" ]; then
            echo "ERROR: Gard found security findings. See artifact."
            exit 1
          elif [ "$EXIT_CODE" -ge "2" ]; then
            echo "ERROR: Gard execution failed with exit code $EXIT_CODE"
            exit 1
          fi
          echo "PASS: Gard scan completed successfully"
          exit 0
```

**How it works:**
- Caches the Gard binary between runs (avoids re-downloading)
- Runs `gard scan` on every PR and push to main
- Uploads JSON report as CI artifact for analysis
- Fails the workflow if any findings are present (exit code 1)
- Fails the workflow if Gard itself errors (exit codes 2+)
- Takes ~30 seconds to complete (mostly Gard scan time)

**Customization:**
- Change `x86_64-unknown-linux-gnu` for different OS/architecture
- Add `--skip env-key-leakage` to exclude specific checks
- Add `--only vscode-extension` to run only certain checks
- Change failure condition: `if [ "$EXIT_CODE" -ne "0" ]` to fail on any non-zero code

---

## 4. Policy File Management for Teams

How teams maintain a shared policy file across contributors with version control.

### Policy File Location

Each contributor has a Gard policy file at:
- **macOS/Linux**: `~/.gard/policy.toml`
- **Windows**: `%APPDATA%\gard\policy.toml`

Teams can:
1. Auto-generate from template (Option A)
2. Share versioned policy in Git (Option B)

### Option A: Auto-generated Policy (Recommended for most teams)

In team onboarding, run:
```bash
gard config init
```

This creates a default policy with:
- All checks enabled
- No suppressions
- All severity levels enforced

### Option B: Shared Team Policy (For enforced standards)

If your team has specific policy requirements:

1. **Create `team-policy.toml` in repository**:
   ```toml
   [policy]
   minimum_severity = "MEDIUM"
   blocking_checks = ["env-key-leakage", "solana-config"]
   
   [[suppressions]]
   check_id = "unsigned-binaries"
   reason = "CI environment runs unsigned build tools"
   expires = "2026-12-31"
   
   [[suppressions]]
   check_id = "vscode-extension"
   reason = "Team standard includes Copilot extension"
   expires = "2026-12-31"
   ```

2. **Distribute to contributors**:
   ```bash
   cp team-policy.toml ~/.gard/policy.toml
   ```

3. **Verify policy is applied**:
   ```bash
   gard config show
   gard config validate
   ```

### Per-contributor Suppressions

If a contributor needs to suppress a finding (e.g., TestFlight while remediating):

1. **Request exception** from security lead with:
   - Check name (e.g., `testflight-detection`)
   - Reason (e.g., "TestFlight wallet isolated on non-signing machine")
   - Duration (e.g., "30 days" or "until 2026-05-27")

2. **Security lead approves** and documents in policy file:
   ```bash
   gard config suppress testflight-detection \
     --reason "TestFlight on non-signing device (Alice, exception #042)" \
     --expires 2026-05-27
   ```

3. **Verify suppression applied**:
   ```bash
   gard scan
   # Finding should appear with [SUPPRESSED] tag
   ```

4. **Auto-expiry**: Gard automatically removes suppressions after expiry date
   - Run `gard scan` on or after expiry date
   - Finding appears as active again (not suppressed)
   - Contributor or team lead must re-request exception or remediate

### Policy File Versioning in CI

Enforce that contributors are using approved policy version:

```yaml
- name: Validate team policy version
  run: |
    POLICY_VERSION=$(gard config show | grep "version:" | awk '{print $2}')
    REQUIRED_VERSION="0.1.0"
    if [ "$POLICY_VERSION" != "$REQUIRED_VERSION" ]; then
      echo "ERROR: Policy version $POLICY_VERSION, required $REQUIRED_VERSION"
      echo "Run: gard config init"
      exit 1
    fi
```

---

## 5. Nonce Authority Verification in Ceremony Prep

Procedure for using `gard preflight` with nonce-authority-verify module before durable nonce signing ceremony.

### When to Use

Before ANY signing ceremony that uses durable nonces for Solana transactions (multisig operations, protocol upgrades, etc.).

### Preparation (Ceremony Lead)

1. **Identify nonce authority address**:
   ```bash
   # Example: ceremony for upgrade authority transaction
   NONCE_AUTHORITY="2rKwdBVHsYMfWPJELfQjGUVGCRrSfqNARxfKFRFJ4BVg"
   ```

2. **Communicate to all signers** (24 hours before ceremony):
   - "Nonce authority for this ceremony: $NONCE_AUTHORITY"
   - "All signers must verify this matches their nonce-authority-verify check"

### Signer Verification (Each signer, before ceremony)

1. **Run preflight with nonce authority check**:
   ```bash
   gard preflight --module nonce-authority-verify --verbose
   ```

2. **Expected output (passing)**:
   ```
   Gard Preflight Verification
   ===========================
   
   Running: nonce-authority-verify
   
   Finding: NONCE_AUTHORITY_MATCH
   Status: PASS
   Description: Nonce authority matches ceremony specification
     Local nonce: 2rKwdBVHsYMfWPJELfQjGUVGCRrSfqNARxfKFRFJ4BVg
     Ceremony nonce: 2rKwdBVHsYMfWPJELfQjGUVGCRrSfqNARxfKFRFJ4BVg
   
   Preflight Status: PASS
   Exit Code: 0
   ```

3. **If nonce mismatch**:
   ```
   Finding: NONCE_AUTHORITY_MISMATCH
   Status: FAIL (BLOCKING)
   Description: Local nonce account does not match ceremony specification
     Local nonce: 9999999999999999999999999999999999999999999
     Ceremony nonce: 2rKwdBVHsYMfWPJELfQjGUVGCRrSfqNARxfKFRFJ4BVg
   
   Remediation: Contact ceremony lead. If nonces should match, investigate why local nonce differs.
   
   Preflight Status: FAIL
   Exit Code: 1
   ```

### Troubleshooting Nonce Mismatches

**If a signer's local nonce doesn't match ceremony spec:**

1. **Signer checks RPC configuration**:
   ```bash
   solana config get
   # Check RPC Url - should be ceremony-specified RPC
   ```

2. **Signer checks local nonce account** (if using persistent nonce):
   ```bash
   solana nonce-account <nonce-pubkey>
   # Verify this nonce account exists and authority is correct
   ```

3. **Resolve mismatch**:
   - If RPC is wrong: `solana config set --url <ceremony-rpc>`
   - If nonce account is wrong: Update Solana config to point to correct nonce
   - If ceremony spec is wrong: Ceremony lead provides corrected nonce authority

4. **Re-run preflight** after fix:
   ```bash
   gard preflight --module nonce-authority-verify
   ```

### Ceremony Log Entry

Coordinator documents in ceremony log:
```
Ceremony: Protocol Upgrade v2 (2026-04-27)
Nonce Authority: 2rKwdBVHsYMfWPJELfQjGUVGCRrSfqNARxfKFRFJ4BVg

Signer Nonce Verification:
- Alice: PASS (2026-04-27T14:00:00Z)
- Bob: PASS (2026-04-27T14:02:00Z)
- Carol: FAIL -> remediated -> PASS (2026-04-27T14:15:00Z)

All signers cleared for nonce-based signing.
Proceeding with ceremony.
```

---

## 6. Upgrading Gard Across the Team

Procedure for rolling out new Gard versions to all contributors.

### Coordinator: Determine Minimum Version

1. **Review release notes** for v0.2.0 (or new version)
   - Security fixes: require immediate rollout
   - New checks: recommend at next cycle
   - Bug fixes: recommend when possible

2. **Set minimum version** in team policy:
   ```bash
   gard config set minimum_version "0.2.0"
   ```

3. **Announce upgrade** to team:
   - "Gard v0.2.0 is now required. Upgrade by end of week."
   - If security fix: "URGENT: Upgrade to v0.2.0 immediately"

### Contributor: Upgrade Steps

1. **Check current version**:
   ```bash
   gard --version
   # Gard v0.1.0
   ```

2. **Download new version**:
   ```bash
   # macOS x86_64
   curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.2.0/gard-x86_64-apple-darwin -o gard-new
   chmod +x gard-new
   
   # Verify signature (if available)
   gard-new keys show  # Should work without error
   ```

3. **Replace old version**:
   ```bash
   sudo mv gard-new /usr/local/bin/gard
   ```

4. **Verify upgrade**:
   ```bash
   gard --version
   # Gard v0.2.0
   ```

5. **Re-run preflight** to check if new version detects new issues:
   ```bash
   gard preflight --confirm
   ```

### CI: Enforce Minimum Version

```yaml
- name: Verify Gard version
  run: |
    GARD_VERSION=$(gard --version | grep -oP 'v\K[0-9.]+')
    MINIMUM_VERSION="0.2.0"
    
    if [ "$(printf '%s\n' "$MINIMUM_VERSION" "$GARD_VERSION" | sort -V | head -n1)" != "$MINIMUM_VERSION" ]; then
      echo "ERROR: Gard version $GARD_VERSION, minimum required is $MINIMUM_VERSION"
      echo "Upgrade: curl -L <release-url> -o gard && chmod +x gard && sudo mv gard /usr/local/bin/"
      exit 1
    fi
    echo "PASS: Gard $GARD_VERSION meets minimum requirement"
```

### Handling Holdouts

Contributors who don't upgrade:

1. **CI fails** on their pull requests (enforced version check fails)
2. **They cannot merge** until they upgrade
3. **For critical security upgrades**:
   - Enforce upgrade in onboarding
   - Do not allow signing ceremonies for contributors on outdated version
   - Document exception with security lead approval

---

## Appendix: Gard Policy File Schema

Full schema for `~/.gard/policy.toml`:

```toml
# Policy file version (must match Gard version)
version = "0.1.0"

# Minimum Gard version required
minimum_gard_version = "0.1.0"

# Minimum severity level for blocking findings
# Valid: CRITICAL, HIGH, MEDIUM, LOW, INFO
minimum_severity = "HIGH"

# Checks that are blocking in preflight (others are informational)
blocking_checks = [
  "env-key-leakage",
  "solana-config",
  "solana-nonce",
]

# Checks to disable entirely (removed from scan output)
disabled_checks = []

# Findings to suppress (with reason and expiration)
[[suppressions]]
check_id = "vscode-extension"
reason = "Team standard includes Copilot extension"
expires = "2026-12-31"

[[suppressions]]
check_id = "unsigned-binaries"
reason = "Build tools in /usr/local/bin are from trusted sources"
expires = "2026-12-31"
```

---

**For questions about this guide or integration issues, contact your security team.**
