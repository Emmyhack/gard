# Gard Scaling Strategy

**Status:** Direction agreed, v0.1.0 shipped as the foundation
**Last updated:** 2026-09-30

## The one-line thesis

Gard should not scale as a scanner. It should scale as the **attestation layer for signing ceremonies**: a verifiable, cryptographically signed claim about the state of a signer's machine at the moment of signing.

Scanners are a commodity. A signed machine-posture attestation that co-signers can verify before countersigning is not — and v0.1.0 already contains the seed of it, because every scan report is Ed25519-signed.

## Why this and not something else

The Drift Protocol attack ($285M, April 2026) succeeded because one compromised developer laptop silently poisoned a signing quorum. Generic endpoint security (CrowdStrike, Jamf) could not have gated that ceremony, because it does not understand nonce authorities, keypair storage, or multisig workflows. Gard operates exactly at that layer. That is the defensible position; everything below builds on it.

## The four layers, in order of leverage

### 1. The wedge: attestation-gated signing ceremonies

Today `gard preflight` gates only the local machine, on the honor system. The product is to wire it into the multisig workflow itself:

- Before a ceremony (Squads or any multisig), each co-signer runs preflight.
- The signed report travels with the ceremony.
- Signer B cryptographically verifies that signer A's machine passed policy **before** countersigning.

A single compromised laptop can no longer silently poison a quorum. No competitor does this, and it reuses what is already built: report signing, the policy engine, blocking semantics, exit codes.

### 2. The revenue layer: team fleet compliance

A small server (initially even a shared repository of signed reports) that collects each team member's scans:

- Who is green, whose machine grew an SSH listener overnight.
- Which suppressions expire this week.
- Ceremony readiness at a glance.

Security leads at protocol teams pay for this dashboard. The CLI stays free and open source as the adoption funnel.

### 3. The moat: rules as a signed data feed

The indicator lists (known-malicious VSCode extensions, clipboard-stealer process names, wallet extension IDs) are currently `const` arrays compiled into the binary — stale the day a release ships. The architectural change to make **first**:

- Move indicators into a versioned, **signed ruleset** fetched by `gard update --rules-only` (the flag exists; the mechanism is the v0.2 work).
- Community contributions and incident-response teams feed the list.
- Detection quality then compounds without binary releases — an advisory-database-shaped moat, in the spirit of RustSec.

### 4. The expansion: chain-agnostic check packs

Only 2 of the 12 checks are Solana-specific. SSH hygiene, VSCode workspace trust, clipboard monitors, browser wallet extensions — an EVM protocol team has the identical threat model. Restructuring into `gard-core` plus per-ecosystem check packs roughly 10x's the addressable market with little new detection code.

## What Gard deliberately will NOT become

**A resident daemon / general endpoint agent.** Three reasons:

1. It competes with EDR vendors on their turf, where they win.
2. A privileged always-on agent on every signer machine is exactly the supply-chain target an attacker wants; Gard would become the vulnerability it exists to prevent.
3. It abandons the trust advantage of a small, auditable, run-on-demand binary.

## Sequencing

| Version | Deliverable | Builds on |
|---------|-------------|-----------|
| v0.2 | Rules-as-data: signed ruleset format + `--rules-only` update path | Existing update command and report-signing infra |
| v0.3 | Report collection and team fleet view | v0.2 attestation reports as the data source |
| v0.4 | Ceremony integration (Squads first): attested co-signing | v0.3 collection + existing preflight gate |

Each step reuses the last, and the attestation format becomes the spec everything else hangs off. The format should be treated as a public, stable contract from v0.2 onward.

## Open questions

- Attestation transport for ceremonies: embedded in the transaction memo, a sidecar service, or out-of-band exchange?
- Ruleset governance: who signs the canonical feed, and what is the contribution/review process?
- Fleet server: self-hosted first (protocol teams distrust third-party custody of security telemetry) vs. hosted for smaller teams?
