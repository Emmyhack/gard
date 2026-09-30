# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `gard attest`: signed, time-boxed machine-posture attestations bound to a
  ceremony id; refused when blocking findings exist (no override)
- `gard verify`: verifies a co-signer's attestation (signature, freshness,
  ceremony binding, posture) and matches the key against the team roster
- `gard fleet submit` / `gard fleet status`: file-based team compliance over
  a shared directory, with signature verification, staleness flagging, and
  tamper detection
- Fleet change detection: each submission archives the previous report, and
  `fleet status` shows findings new or resolved since a member's last submit
- Suppression visibility: scan reports embed active suppressions, and
  `fleet status` warns when one expires within 7 days
- `gard fleet dashboard`: renders the fleet view into a self-contained,
  theme-aware `index.html` (no server, no external dependencies) that
  `fleet submit` keeps refreshed; serve the fleet directory (e.g. GitHub
  Pages) to give the team a URL
- `gard fleet serve`: live web dashboard on localhost with a JSON API
  (`/api/status`) that recomputes fleet state per request; the page polls
  every 30 seconds — no external web framework, built on the existing
  tokio runtime
- `gard team add/list/remove`: trusted signer roster stored in policy.toml,
  so distributing one policy file distributes the trust anchors
- `[team]` and `[fleet]` policy sections

### Changed
- Placeholder for future improvements

### Fixed
- Placeholder for future fixes

### Deprecated
- Placeholder for future deprecations

### Removed
- Placeholder for future removals

### Security
- Placeholder for future security fixes

## [0.1.0] - 2026-04-16

### Added

#### Core Commands
- `gard scan`: Complete local machine audit with signed report output
- `gard preflight`: Mandatory pre-signing checklist with blocking on findings
- `gard config`: Policy file management and check configuration
- `gard report`: Report formatting, export, and verification
- `gard update`: Self-update and rule refresh functionality

#### Check Modules
- VSCode workspace trust and auto-run task detection
- VSCode extension audit against known-malicious and high-risk extension list
- TestFlight installation detection on macOS
- Software wallet process and binary detection
- Clipboard monitoring process detection
- Environment variable audit for leaked key material patterns
- SSH agent forwarding configuration audit
- Open port scan scoped to remote access tool ports
- Browser cryptocurrency extensions detection
- Unsigned or recently installed binaries in PATH detection
- Solana CLI configuration audit
- Durable nonce account ownership verification
- Hardware wallet connectivity verification

#### Output Formats
- Human-readable plaintext output with severity indicators
- Machine-readable JSON output for automation
- Markdown format for documentation and sharing
- Pretty-printed JSON for direct inspection

#### Report Signing
- Ed25519 signature generation for all reports
- Report signature verification capability
- Public key export for independent verification
- Verification instructions embedded in reports

#### Policy System
- Policy file configuration at ~/.gard/policy.toml
- Per-check enforcement level configuration (enforce, warn, silent)
- Finding suppression with expiration dates
- Hardware wallet requirement policies

#### Platform Support
- macOS 12.0+ (x86_64 and ARM64)
- Linux 4.15+ (x86_64 and ARM64)
- Windows 10+ (x86_64, limited check support)

#### Security Features
- No unsafe code blocks in production code
- Structured error handling with context
- Async I/O for network operations
- Platform-specific code with proper gating
- Consistent string formatting for parseable output
- Ed25519 cryptographic signing

### Changed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Security
- All dependencies audited via cargo-audit
- All license restrictions validated via cargo-deny
- Clippy linting enforced with -D warnings
- No unwrap() calls in production code
- All findings from initial threat modeling addressed

---

For detailed technical information, see [docs/research.md](docs/research.md) and [docs/architecture.md](docs/architecture.md).
