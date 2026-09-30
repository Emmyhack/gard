# Gard: OPSEC Guardian for Solana Protocol Teams

Gard is a standalone CLI tool that enforces signing hygiene and detects dangerous configurations on developer and signer machines. It operates at the operational security layer — detecting compromised development environments, misconfigured Solana operations, and blocking insecure signing ceremonies before they occur.

Gard was conceived from the Drift Protocol attack of April 1, 2026, a $285M exploit combining social engineering, VSCode extension compromise, TestFlight delivery, durable nonce abuse, and oracle manipulation. Gard detects every one of these attack vectors at the machine and configuration level before they become exploits.

## What Gard Detects

- VSCode workspace trust bypass and auto-run task injection
- Malicious VSCode extensions against known-malicious and high-risk extension lists
- TestFlight and sideloaded applications on macOS
- Software wallets that can be exfiltration targets
- Clipboard monitoring and address hijacking processes
- Keypair material leaked in environment variables or shell profiles
- SSH agent misconfiguration and forwarding to untrusted hosts
- Open remote access ports (VNC, RDP, SSH) and services
- Cryptocurrency browser extensions on signing machines
- Unsigned or recently-installed binaries in PATH
- Solana CLI misconfiguration and unsafe keypair storage
- Durable nonce account authority mismatches
- Missing or disconnected hardware wallet devices

## Installation

### From Binary (Recommended)

Download the latest binary for your platform from [GitHub Releases](https://github.com/nextlevelbuilder/gard/releases):

```bash
# macOS x86_64
curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-x86_64-apple-darwin -o gard
chmod +x gard
sudo mv gard /usr/local/bin/

# macOS ARM64
curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-aarch64-apple-darwin -o gard
chmod +x gard
sudo mv gard /usr/local/bin/

# Linux x86_64
curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-x86_64-unknown-linux-gnu -o gard
chmod +x gard
sudo mv gard /usr/local/bin/

# Linux ARM64
curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-aarch64-unknown-linux-gnu -o gard
chmod +x gard
sudo mv gard /usr/local/bin/
```

Verify checksum (critical for security tools):

```bash
curl -L https://github.com/nextlevelbuilder/gard/releases/download/v0.1.0/gard-x86_64-apple-darwin.sha256 -o gard.sha256
sha256sum -c gard.sha256
```

### From Source

Requires Rust 1.70+:

```bash
git clone https://github.com/nextlevelbuilder/gard.git
cd gard
cargo build --release
./target/release/gard --version
```

## Quick Start

### Run a Full Machine Audit

```bash
gard scan
```

Output shows findings with severity levels and remediation steps.

### Run Pre-Signing Checklist

Before any transaction signing ceremony:

```bash
gard preflight
```

Blocks if dangerous configurations detected. Use `--override` only with explicit justification:

```bash
gard preflight --override "TestFlight wallet isolated on non-signing machine" --confirm
```

### View Last Scan Report

```bash
gard report
gard report --format json
gard report --format markdown -o report.md
```

### Attest a Signing Ceremony

Before countersigning a multisig proposal, each signer produces a signed
machine-posture attestation bound to the ceremony:

```bash
gard attest --ceremony prop-42 --signer alice
```

Attestation is refused while blocking findings exist — there is no override.
Co-signers verify each other's attestations before countersigning:

```bash
gard verify gard-attestation-prop-42.json --ceremony prop-42
```

Register teammates' keys so verification also proves who signed:

```bash
gard report --export-key            # each member shares this output
gard team add alice --key <hex>     # everyone registers everyone
```

### Track Fleet Compliance

Point the team at a shared directory (a synced folder or git repository):

```bash
gard fleet submit --dir ~/team/gard-fleet     # each member, e.g. daily
gard fleet status --dir ~/team/gard-fleet     # anyone
```

`fleet status` verifies every report's signature, flags stale or failing
members, warns on suppressions expiring within 7 days, shows findings that
are new or resolved since each member's previous submission, and exits
non-zero unless the whole fleet is green. Set `[fleet] dir` in policy to
drop the `--dir` flag.

### Initialize Policy

Create local policy file at `~/.gard/policy.toml`:

```bash
gard config init
gard config show
```

### Verify Report Signature

Reports are signed with Ed25519 and can be verified without Gard installed:

```bash
gard report --verify
gard report --export-key > public_key.pem
```

## Command Reference

### gard scan

Run complete local machine audit and produce signed report.

```bash
gard scan [OPTIONS]
```

Options:
- `--format <FORMAT>`: Output format: `json`, `plaintext`, `json-pretty`. Default: `plaintext`
- `-o, --output <PATH>`: Write report to file
- `--config <PATH>`: Use custom configuration file
- `-v, --verbose`: Include detailed check metadata
- `--skip <CHECK>`: Skip specific check (comma-separated)
- `--only <CHECK>`: Run only specific check (comma-separated)
- `--no-sign`: Do not sign report

Exit codes:
- `0`: No findings
- `1`: Findings discovered
- `2`: Execution error

### gard preflight

Mandatory pre-signing checklist. Blocks signing if preconditions not met.

```bash
gard preflight [OPTIONS]
```

Options:
- `--sign`: Confirm preflight passed and prepare for signing
- `--confirm`: Explicit confirmation that findings addressed
- `--override <REASON>`: Override blocking findings with justification
- `--config <PATH>`: Use custom configuration file
- `-v, --verbose`: Include detailed metadata
- `--json`: Output in JSON format

Exit codes:
- `0`: Preflight passed
- `1`: Preflight failed
- `2`: Execution error

### gard config

Manage local Gard policy configuration.

```bash
gard config <SUBCOMMAND>
```

Subcommands:
- `init`: Initialize default policy file
- `show`: Display current policy
- `validate`: Validate policy file
- `check <NAME>`: Modify check enforcement status
- `suppress <CHECK> --reason <TEXT> --until <DATE>`: Suppress finding

### gard report

Format and export scan results.

```bash
gard report [OPTIONS]
```

Options:
- `--format <FORMAT>`: Output format: `json`, `plaintext`, `markdown`. Default: `plaintext`
- `-o, --output <PATH>`: Write to file
- `--input <PATH>`: Load specific report file
- `--verify`: Verify signature
- `--summary`: Show summary only
- `--filter <SEVERITY>`: Show only findings at severity level or above

### gard update

Update Gard binary and check definitions.

```bash
gard update [OPTIONS]
```

Options:
- `--check`: Check for update without installing
- `--version <VERSION>`: Update to specific version
- `--channel <CHANNEL>`: Update channel: `stable`, `beta`. Default: `stable`
- `--force`: Force update
- `--rules-only`: Update rules without updating binary
- `--dry-run`: Simulate update

Exit codes:
- `0`: Update successful
- `1`: Update failed
- `2`: Already latest version

### gard attest

Produce a signed machine-posture attestation bound to a ceremony. Refused
while blocking findings exist.

```bash
gard attest --ceremony <ID> [--signer <NAME>] [--valid-for <MINUTES>] [-o <PATH>] [--json]
```

Exit codes: `0` attestation written, `1` blocking findings present.

### gard verify

Verify a co-signer's attestation: signature, freshness, ceremony binding,
posture, and (when a team roster exists) that the key belongs to a
registered signer.

```bash
gard verify <FILE> [--ceremony <ID>] [--require-trusted] [--json]
```

Exit codes: `0` acceptable, `1` rejected.

### gard fleet

File-based team compliance over a shared directory.

```bash
gard fleet submit [--dir <PATH>]
gard fleet status [--dir <PATH>] [--max-age-hours <N>] [--json]
gard fleet dashboard [--dir <PATH>] [--max-age-hours <N>] [-o <PATH>]
```

`submit` runs a fresh scan and writes the signed report as
`<user>@<host>.json`. `status` verifies signatures, flags stale (default
24h) and failing members, and exits `0` only when the fleet is green.

`dashboard` renders the same view into a self-contained `index.html` in the
fleet directory: summary tiles, per-member status, expiring suppressions,
and new/resolved findings, in light and dark themes with no external
dependencies. Once generated, every `fleet submit` refreshes it, and the
page reloads itself every 5 minutes — so serving the fleet directory (for
example with GitHub Pages on the shared repo) gives the team a URL to
check daily without running any server.

### gard team

Manage the trusted signer roster stored in `policy.toml` under `[team]`.

```bash
gard team add <NAME> --key <HEX>
gard team list
gard team remove <NAME>
```

## Configuration Reference

### Policy File Format

Policy file stored at `~/.gard/policy.toml`:

```toml
[checks]
vscode-workspace-trust = "enforce"
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

[[suppressions]]
check_id = "software-wallet-detection"
reason = "Phantom wallet required for development, isolated on non-signing machine"
expires = "2026-06-01"

[hardware_wallet]
required = true
minimum_type = "ledger"

[solana]
trusted_rpc_endpoints = [
    "https://api.mainnet-beta.solana.com",
    "https://api.devnet.solana.com"
]

[nonce]
expected_authority = "MultisigAddress..."

[[team.signers]]
name = "alice"
public_key = "<64-hex-chars-from-gard-report---export-key>"

[fleet]
dir = "/Users/alice/team/gard-fleet"
max_age_hours = 24
```

### Check Enforcement Levels

- `enforce`: Check blocks preflight if findings detected
- `warn`: Check alerts but does not block
- `silent`: Check suppressed

### Suppression Format

Each suppression entry requires:
- `check_id`: Check identifier to suppress
- `reason`: Justification for suppression
- `expires`: Expiration date (YYYY-MM-DD format)

## Data Directory

Gard stores data at `~/.gard/`:

```
~/.gard/
  policy.toml           - Local policy configuration
  keys/
    ed25519            - Private key for report signing
    ed25519.pub        - Public key (OpenSSH format)
  cache/
    last_scan.json     - Last scan result
  update.log           - Update history
```

## Report Verification

Reports are signed with Ed25519. Public key included in each report.

### Verify Without Gard Installed

Extract public key from report:

```bash
cat report.json | jq -r '.metadata.public_key' > pubkey.pem
```

Verify signature using OpenSSL:

```bash
cat report.json | jq -c '.metadata | del(.signature, .public_key)' | \
  openssl dgst -sha256 -verify pubkey.pem -signature <(echo "..." | xxd -r -p)
```

## Platform Support

- macOS 12.0+ (x86_64, ARM64)
- Linux 4.15+ (x86_64, ARM64)
- Windows 10+ (x86_64) - Limited check support

Some checks are platform-specific:
- TestFlight detection: macOS only
- VSCode workspace trust: macOS, Linux
- Open port scanning: All platforms
- Durable nonce verification: All platforms (requires RPC access)

## Roadmap and Scaling Strategy

See [docs/scaling.md](docs/scaling.md) for where Gard is headed: signed rulesets (v0.2), team fleet compliance (v0.3), and attestation-gated signing ceremonies (v0.4).

## Security Policy

See [SECURITY.md](SECURITY.md) for responsible disclosure procedure.

## Contributing

Contributions welcome. All code must pass:

```bash
cargo test --all
cargo clippy -- -D warnings
cargo audit
cargo deny check all
```

## License

MIT License. See LICENSE file.

## References

- Solana Documentation: https://docs.solana.com
- Squads Protocol: https://squads.so
- RustSec Advisory Database: https://rustsec.org
