# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in Gard, please report it responsibly to prevent disclosure of the vulnerability before a patch is available.

**Do not open public GitHub issues for security vulnerabilities.**

## Reporting Process

1. Use GitHub private vulnerability reporting on this repository
   (Security tab → "Report a vulnerability"), including:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix if available

2. Include the following information:
   - Gard version affected
   - Operating system and version
   - Any configuration details relevant to the vulnerability

3. Allow up to 90 days for a security patch to be developed and released before public disclosure.

## Vulnerability Handling

Upon receipt of a vulnerability report:

1. The report is acknowledged within 48 hours
2. A security advisory is created (initially private)
3. A fix is developed with priority based on severity
4. The fix is released in a security patch version
5. A public security advisory is published simultaneously with the patch
6. Reporter is credited unless they request anonymity

## Severity Levels

- **CRITICAL**: Immediate exploitation risk, impacts all users
- **HIGH**: Likely exploitation risk, impacts many users
- **MEDIUM**: Potential exploitation risk, requires specific conditions
- **LOW**: Theoretical risk or limited impact

## Supported Versions

Security patches are provided for:
- Current major version (all minor versions)
- Previous major version (latest minor version only)

## Dependencies

Gard uses cargo-audit to track security vulnerabilities in dependencies. All dependencies are regularly audited and updated. Users should keep Gard updated to the latest version to receive dependency security patches.

## Security Best Practices for Gard

While Gard implements many security checks, remember:

- Gard is one layer in a defense-in-depth strategy
- No single tool can guarantee security
- Regular manual security reviews are necessary
- Keep Gard updated to latest version
- Run Gard regularly (on every signing operation)
- Take all CRITICAL and HIGH findings seriously
- Use hardware wallets for signing whenever possible
- Isolate signing machines from general development and browsing

## Responsible Disclosure Credit

Researchers who responsibly disclose security vulnerabilities will be credited in release notes and security advisories unless they request anonymity.

Examples of responsible disclosure:
- Private email notification before public disclosure
- Providing time for patch development and testing
- Not exploiting the vulnerability beyond what's necessary to demonstrate impact
- Not sharing vulnerability details publicly before patch release
