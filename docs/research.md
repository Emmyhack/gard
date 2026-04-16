# Gard: Threat Model and Research

## 1. Drift Protocol Attack Technical Anatomy

### 1.1 VSCode Extension and Repository Delivery

The malicious VSCode extension was delivered through a fraudulent GitHub repository mimicking a legitimate open source project. The attack chain:

- Fraudulent repository created with typosquatting on a known VSCode extension for Solana development
- Repository forked legitimate code, embedded malicious payload in extension activation code
- Payload activated on extension load without requiring explicit user action
- Attack surface exploited: VSCode's extension auto-install from workspace recommendations in `.vscode/extensions.json`
- Additional vector: manual installation of extension from untrusted marketplace account impersonating team member
- Delivery mechanism: social engineering via Slack/Discord with link to "recommended setup guide" that included VSCode workspace file with malicious extension recommendations

### 1.2 TestFlight Delivery Mechanism on macOS

TestFlight used as secondary delivery vector for iOS/macOS signer application payload:

- Legitimate mobile wallet app (common example: Phantom, Ledger Live) TestFlight build compromised or spoofed build distributed
- Entitlements exploited: `com.apple.security.files.user-selected.read-write` for keychain and file access
- Entitlements exploited: `com.apple.security.network.client` for outbound network access without user restriction
- macOS sideloading via unsigned/unnotarized binaries installed directly on signer machines with minimal verification
- TestFlight bypasses notarization requirements and sandboxing restrictions for internal testing builds
- Attack path: victim receives TestFlight invite link for "updated signer app", installs unvetted application with full entitlements
- Payload in signer app: intercepts locally-stored keypairs, monitors clipboard, exfiltrates transaction details before signing

### 1.3 Durable Nonce Abuse for Pre-Signed Transactions

Solana durable nonces allow pre-signing of transactions that can be executed later without becoming invalid:

- Durable nonce is a Solana account with specific state: `nonce_authority`, `blockhash`, and `lamports`
- Pre-signed transaction structure: signer creates transaction with blockhash from nonce account, signs offline, transmission is deferred
- Vulnerability: attacker with access to pre-signed transaction can identify when nonce advances and execute transaction at strategic time
- Attack scenario: attacker gains access to shared pre-signed multisig transaction (via compromised machine, clipboard, or transmission channel)
- Attacker monitors RPC endpoint for nonce account state changes via `getAccountInfo` with polling
- Once nonce advances to new blockhash, attacker submits original pre-signed transaction using old blockhash knowledge - this would normally fail, BUT durable nonce transactions bypass blockhash validation
- Transaction executes even if submitted long after signing because nonce account state is the validation, not global blockhash
- Additional risk: multisig ceremonies often pre-sign batches of transactions for planned actions; if ceremony details leak, attacker knows exactly what transaction to wait for
- Pre-signed transaction metadata often includes: timestamp, destination addresses, amounts - all visible to attacker without decryption

### 1.4 Oracle Manipulation Execution

Oracle manipulation in Drift Protocol attack:

- Drift Protocol uses oracle-based pricing for perpetual futures collateral valuation
- Attack path: attacker compromises RPC node or injects responses to `getProgramAccounts` calls querying oracle price feeds
- Collateral oracle accounts typically stored in known program addresses; attacker targets these by filtering account list
- Fake oracle response construction: crafted malicious Solana account state with inflated collateral values
- Preconditions: attacker needs network position to inject responses OR compromised validator/RPC node, OR compromised client-side account parsing
- Attack timing: pre-signed transactions for liquidations or collateral adjustments execute at attacker-controlled price point
- Attacker sets collateral value to enable liquidation of victim positions at profit, or enables over-leveraging victim account
- Oracle price feed authority signatures are NOT validated at transaction execution time in vulnerable contract versions; price is read as state value

### 1.5 DPRK Operational Playbook for Crypto Targeting

Observed patterns from DPRK-attributed crypto attack groups (Lazarus, APT37):

- Initial reconnaissance: target identification through LinkedIn, GitHub, Discord public profiles of Solana protocol developers
- Social engineering: creation of fake personas with development background, building rapport over weeks on Discord/Twitter
- Credential compromise: phishing emails mimicking CI/CD systems (GitHub Actions notifications, deployment confirmations)
- Supply chain attacks: compromised GitHub accounts of open source maintainers, published malicious library updates
- Persistence mechanisms: malware installed via VSCode extensions, npm packages, brew formulas
- Exfiltration targets: SSH keys, `.solana/id.json` keypair files, browser local storage for wallet extensions
- Operational security: use of residential proxy infrastructure, activity from timezone matching target location
- Dwell time: 2-4 weeks between initial compromise and exploitation to avoid detection
- Communication channels: blend legitimate-looking CI/CD notifications with command and control

## 2. Full Threat Surface for Gard Coverage

### 2.1 Software Wallets on Signing Machines

Risk profile: Software wallets running on signing machines represent primary exfiltration target:

- Phantom, Ledger Live, Slope, Magic Eden wallet installations on macOS/Linux signing machines
- Keypair material stored in plaintext or with weak encryption in wallet data directories
- Wallet process memory can be dumped by local privilege escalation or malicious extension
- Wallet browser extension communication to backend service without proper certificate pinning
- Clipboard interaction: wallet extension watching clipboard for addresses, providing substitute malicious address
- Signed transactions in wallet process memory before being transmitted
- RPC endpoint configuration in wallet can be manipulated if wallet is compromised
- No mechanism to prevent wallet operation during preflight or signing ceremony

### 2.2 VSCode Workspace Trust and Auto-Run Tasks

Workspace trust is frequently bypassed or misconfigured:

- Workspace trust settings in `.vscode/settings.json` can be pre-configured to allow untrusted workspace
- Auto-run tasks in `.vscode/tasks.json` execute shell commands on workspace load without explicit approval if workspace trusted
- `.vscode/extensions.json` specifies recommended extensions that auto-install silently on workspace open
- Malicious extension in recommendations runs with full VSCode process privileges, including access to all open files and terminals
- Workspace file (`.code-workspace`) can contain arbitrary settings that override user defaults
- Settings can specify shell command execution in various hooks (build, debug, test)
- Attacker can hide malicious recommendations in `.vscode/extensions.json` with benign extension list mixed in

### 2.3 TestFlight and Sideloaded Applications on macOS

macOS application delivery is frequently unverified:

- TestFlight applications bypass notarization requirements and sandboxing restrictions
- User prompted only once for app usage, not shown actual entitlements being granted
- Sideloaded applications (dragged to Applications folder) can run without any OS verification if user disables Gatekeeper
- Code signing verification can be bypassed on Intel Macs if user chooses "Open Anyway" even once
- Application bundles can contain arbitrary shell scripts in bundle structure
- Entitlements in provisioning profile grant access to keychain, files, network without granular user control
- TestFlight beta version numbering and UI do not distinguish from production releases
- User has no visibility into what changed between TestFlight versions

### 2.4 Clipboard Hijacking and Address Substitution

Clipboard is a key vulnerability vector at OS level:

- Any process with user privilege can read and write clipboard
- Clipboard monitoring: malicious process reads clipboard on timer, watches for Solana address patterns, substitutes wallet address
- Address recognition: common patterns are Base58-encoded 32-byte values, easy to detect via regex
- Substitution payload: attacker clipboard hijacker pre-loads clipboard with attacker wallet address when user copie legitimate address
- User observes correct address in source application, but clipboard contains hijacked address
- No OS-level clipboard audit or cryptographic integrity verification
- Clipboard hijacking works across all applications - browser, terminal, IDE, wallet
- Attacks on transaction confirmation: user copies transaction details for review, hijacker modifies amounts or recipient

### 2.5 Environment Variable Leakage

Shell profiles and CI configurations frequently leak key material:

- `.bashrc`, `.zshrc`, `.bash_profile` often contain `export SOLANA_KEYPAIR=/path/to/key.json` or similar
- Keypair paths set in environment persist across process spawns and can be read by other processes
- Private key data sometimes logged in `PS_AUX` output when parent process name contains key path
- CI/CD environment variable configuration in GitHub Actions, GitLab CI, Jenkins stored in plaintext in some cases
- Secret rotation timestamps in CI configuration often predate actual signing operations
- Child process environment inherits parent environment; malicious process launched from shell inherits keypair paths
- Environment variable leakage visible to any local process via `/proc/<pid>/environ` on Linux or `ps` output on macOS

### 2.6 SSH Key Hygiene and Agent Forwarding

SSH configuration frequently enables privilege escalation:

- SSH keypairs used for Git commit signing, deployment access, not isolated by purpose
- SSH agent running on signing machine with keys loaded; agent forwarding enabled in SSH config
- Agent forwarding allows remote machine accessed via SSH to sign on behalf of local machine
- Attacker with access to remote machine can forward authentication back to local machine
- SSH key passphrases frequently absent or weak on signing machines (convenience over security)
- SSH keys stored in default locations with predictable permissions
- SSH config file specifies `AddKeysToAgent yes` which auto-loads keys without user interaction
- No audit logging of SSH agent operations or key usage

### 2.7 Browser Extensions on Signing Machines

Browser extensions have deep privileges on signing machines:

- Crypto wallet extensions (MetaMask, Phantom) have access to all browser data and network traffic
- Extensions can read and modify clipboard, intercept network requests, monitor user actions
- Extension update mechanism frequently auto-updates without user review
- Malicious extension can inject into transaction approval flows, modifying transaction before user sees it
- Browser profile used for signing often same profile used for general browsing (email, GitHub, etc.)
- No mechanism to isolate browser extension access to only signing-related sites
- Extension data stored in plaintext in browser profile directory
- No audit of extension resource access or network communication

### 2.8 Unsigned and Recently Installed Binaries in PATH

Binary execution patterns are frequently dangerous:

- Development tools frequently installed via curl | bash pattern without verification
- Go get, Rust cargo, npm install frequently execute arbitrary build scripts during installation
- Binaries in PATH may be recently installed replacements of legitimate tools (via typosquatting or PATH hijacking)
- No verification that binary is authentic; only hash matching from original source, not end-to-end verification
- Development environment frequently includes custom shell functions or aliases that override standard tools
- Makefile or justfile execution can run arbitrary commands without explicit invocation
- Shell PATH search order can be manipulated by compromised shell profile

### 2.9 Network Exposure of Signing Machines

Network configuration frequently exposes signing machines to attack:

- Open ports on signing machines running services: SSH (22), VNC (5900), Mosh (60000), debug tools (localhost:8080)
- Remote access tools installed and running: TeamViewer, Chrome Remote Desktop, Microsoft Remote Desktop
- Network monitoring shows signing machine accessible from untrusted networks (VPN exit points, cloud infrastructure)
- Firewall configuration non-existent or permissive on signing machines
- Network segmentation absent between signing machine and general development network
- RPC endpoints contacted from signing machine may not be over TLS or may have certificate pinning disabled
- DNS resolution on signing machine may be intercepted or manipulated by attacker with network position

## 3. Solana-Specific Operational Risks

### 3.1 Durable Nonce Account Ownership and Authority

Durable nonce accounts are critical infrastructure for pre-signing but frequently misconfigured:

- Nonce account is owned by the Solana System Program, but authority is delegated to a keypair
- Authority can be a single account or a multisig account
- Common misconfiguration: nonce authority same as transaction signer (single point of compromise)
- Ownership verification requires reading nonce account state from RPC; no cryptographic binding
- Multiple nonce accounts for same authority pattern used to enable parallelization but increases attack surface
- Nonce account rent-exempt status not verified; attacker can drain account lamports if authority is compromised
- Nonce initialization creates security assumption: first account to initialize nonce controls it

### 3.2 Pre-Signed Transaction Storage and Transmission

Pre-signed transactions are frequently stored and transmitted insecurely:

- Pre-signed transactions are complete serialized Solana transactions with signatures appended
- Storage locations: plaintext files on disk, Git repositories, shared cloud storage, email
- Transmission: unencrypted email, Slack messages, Discord, unencrypted file shares
- Pre-signed transaction contains: all instruction data, all accounts involved, both source and destination addresses, amounts
- Attacker can analyze pre-signed transaction to understand intended operation even without signature validation
- Batch pre-signing common pattern: coordinator signs 100+ transactions for upcoming operations, stores in file
- If pre-signed transaction batch leaks, attacker knows entire operation plan and can schedule attack accordingly
- No encryption envelope around pre-signed transactions; visible to anyone with file access
- Serialization format is deterministic; attacker can detect modification and still submit transaction if original signatures valid

### 3.3 Multisig Tooling in Production

Production multisig tooling is limited and frequently misconfigured:

- Squads Protocol is primary multisig infrastructure on Solana for protocol governance
- Signing ceremony participants coordinate via out-of-band channels (Discord, Slack, email, in-person)
- Ceremony coordinator prepares transaction, shares with signers via insecure channels for review
- Signers review transaction offline or in low-security environment (shared screen, email)
- Partial signatures collected from signers and recombined by coordinator
- No cryptographic binding between partial signatures and transaction finality
- Coordinator machine frequently same machine as other development activity (no isolation)
- Signing ceremony frequently rushed due to time-sensitive operations or incident response
- Multisig threshold frequently low relative to number of signers (e.g., 3-of-5 for 5-person quorum)

### 3.4 Signing Ceremony Patterns and Failure Modes

Signing ceremonies in production frequently have documented failure modes:

- Verbal confirmation pattern: signer verbally confirms transaction details over call, but reads from compromised screen
- Screen sharing confirmation: transaction displayed on shared screen which may be captured or screen-shared over insecure channel
- Transaction details review: amounts, addresses, authority delegations reviewed but without secure cryptographic binding
- Time zone delays: ceremony spanning multiple time zones results in asynchronous signing and re-coordination
- Retry logic: failed ceremony attempts lead to re-transmission and re-confirmation of same transaction
- Authority verification: signers rarely verify that transaction authority matches expected multisig structure
- Chain of custody: transaction moves through multiple hands and storage locations, no audit trail
- Ceremony records: ceremony transcripts and chat logs retained in discoverable locations

### 3.5 RPC Behaviors Exploitable by Attackers

RPC endpoints expose attack surface for nonce monitoring and transaction orchestration:

- `getAccountInfo` for nonce account returns current blockhash; attacker polls endpoint on interval to monitor advancement
- `getRecentBlockhash` returns current blockhash but does not validate nonce account relationship
- `sendTransaction` will accept transaction with outdated blockhash if durable nonce account is present
- `getTransactionStatus` or `confirmTransaction` allows attacker to monitor when transaction enters mempool
- No rate limiting on RPC calls; attacker can poll nonce state with high frequency
- Public RPC endpoints have no authentication; any attacker can monitor any account
- RPC endpoint does not return transaction chain-of-custody data or authorization source
- `getProgramAccounts` allows querying all oracle accounts in one call; attacker can identify oracle prices to target

## 4. CLI Tooling Standards for Security Tools in Rust Ecosystem

### 4.1 Output Structure and Formats

Security tools in Rust follow established patterns for output:

- Machine-readable output (JSON) separate from human-readable output (plaintext, table)
- JSON output schema consistent and stable across versions (no breaking changes)
- Exit codes follow Unix convention: 0 for success, non-zero for various failure modes
- Human-readable output optimized for terminal display: colored text, aligned columns, clear hierarchy
- Severity levels standardized: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Each finding includes: check name, severity, file/location, remediation suggestion, CWE/CVE reference if applicable
- Quiet mode (`-q` flag) suppresses all output except final exit code
- Verbose mode (`-v` flag) includes additional context: timing, intermediate checks, configuration loaded
- JSON output includes metadata: scan timestamp, tool version, schema version, execution environment

### 4.2 Output from Established Tools

`cargo audit` output patterns:

- JSON output includes: `vulnerabilities` array with id, crate, advisory, version, cvss, etc.
- Human output lists vulnerability summary, affected crate versions, recommendation to upgrade
- Exit code: 0 if no vulnerabilities, 1 if vulnerabilities found, 2 if execution error

`cargo deny` output patterns:

- Checks bans, licenses, advisories separately
- JSON output categorizes findings by check type
- Human output shows failed checks with explanation and suggestion to add to allow-list
- Exit code: 0 if passing, 1 if any violations

`trivy` (container scanner) output patterns:

- Severity filtering: `--severity CRITICAL,HIGH`
- JSON output includes layer information, hash digests, remediation PRs
- Exit code configurable per severity: default 0, can be configured to exit 1 on MEDIUM+

### 4.3 Rule Configuration and Suppression

Security tools provide mechanisms to customize checks:

- Suppression file (allow-list) specifies checks to skip with justification
- Suppression entries include: check ID, resource identifier, justification text, expiry date
- Expiry dates enforce re-evaluation of suppressed checks
- Configuration file format: TOML common for Rust tools (similar to Cargo.toml)
- Per-directory or per-file configuration overrides
- Rule severity can be adjusted: demote HIGH to MEDIUM, promote LOW to HIGH for specific cases
- Comment syntax in configuration allows inline notes
- Configuration validation on load: invalid configuration fails with helpful error message

### 4.4 Packaging and Distribution

Security tools in Rust ecosystem follow distribution patterns:

- Binary distribution via GitHub releases with checksums (SHA256)
- Distribution for multiple platforms: Linux x86_64, aarch64; macOS x86_64, aarch64; Windows
- Installation via Homebrew (macOS), apt (Linux), cargo binstall, direct download
- Self-update mechanism: binary compares version with upstream, downloads new version, replaces in-place
- Update signatures: signed releases or checksum verification against trusted source
- Version pinning: tools support version constraints in automation (exact version, latest patch, latest minor)
- Container images for CI/CD integration
- No external dependency downloads during execution (tool is single self-contained binary)

## 5. Go-to-Market Patterns for Developer Security Tools

### 5.1 Adoption Inside Protocol Teams

Security tools gain adoption through specific patterns:

- Initial adoption: individual developer discovers tool, runs locally, advocates internally
- Second wave: tool integrated into CI/CD pipeline, makes check gates mandatory
- Team adoption: tool added to onboarding checklist for new team members
- Scaling: tool configuration standardized across team, policy enforcement via Git hooks
- Enforcement: team lead adds tool to code review checklist, PR cannot merge without clean scan

### 5.2 Integration into Workflows

Tools are most effective when integrated into existing workflows:

- Git pre-commit hooks: tool runs before commit is accepted, blocks commit if findings discovered
- CI/CD gates: tool runs in pipeline, fails build if findings above configured severity
- IDE integration: tool provides LSP or IDE plugin, shows findings inline while developing
- Developer machine: tool runs on regular interval (via launchd/systemd), alerts developer to new findings
- Signing ceremony: tool runs as mandatory step before transaction signing, blocks signing if preconditions not met

### 5.3 Enforcement Mechanisms

Tools must have mechanisms to enforce adoption:

- Mandatory mode: tool must pass before operation proceeds, no override without explicit action
- Reporting mode: tool produces report for auditing, non-blocking but tracked
- Advisory mode: tool alerts but does not block, allows developer discretion
- Override mechanism: explicit flag required to override tool, action recorded in audit log
- Team policy: policy file defines which checks are mandatory vs advisory for team
- Escalation: non-passing checks escalated to team lead or security officer for resolution

## 6. Threat Model Summary

Gard must detect and prevent:

1. Compromised development environment: malicious VSCode extensions, unsigned binaries, suspicious processes
2. Compromised application layer: malicious wallet installations, fake TestFlight applications, clipboard hijacking
3. Compromised signing infrastructure: weak SSH keys, insecure keypair storage, open network ports
4. Misconfigured Solana operations: weak nonce authority, insecure pre-signed transaction storage, untrusted RPC endpoints
5. Ceremony failures: lack of verification, insufficient authority checks, inability to abort ceremony
6. Supply chain attacks: auto-installed extensions, unverified binary updates, compromised dependencies

Gard enforces:

1. Machine hygiene: whitelisted processes, verified binaries, secure permissions
2. Configuration verification: proper nonce setup, authority verification, RPC validation
3. Ceremony blocking: mandatory preflight before signing, clear abort mechanism, immutable signing reports
4. Detection and alerting: real-time notification of dangerous patterns, historical comparison, trend analysis

