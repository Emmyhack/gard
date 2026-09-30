//! Ceremony attestations
//!
//! An attestation is a signed, time-boxed claim about a signer machine's
//! security posture, bound to a specific ceremony identifier. Co-signers
//! verify each other's attestations before countersigning, so a single
//! compromised machine cannot silently poison a multisig quorum.

use crate::error::{GardError, Result};
use crate::report::ReportSigner;
use crate::types::{current_platform, Platform, ReportSummary};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Maximum tolerated clock skew when checking issuance time
const MAX_CLOCK_SKEW_MINUTES: i64 = 5;

/// A signed machine-posture claim bound to a ceremony
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Attestation schema version
    pub version: String,

    /// Ceremony this attestation is bound to (e.g. a proposal or tx id)
    pub ceremony_id: String,

    /// Human name of the signer presenting this attestation
    pub signer_name: String,

    /// Hostname of the attested machine
    pub hostname: String,

    /// OS user the checks ran as
    pub username: String,

    /// Platform of the attested machine
    pub platform: Platform,

    /// Gard version that produced this attestation
    pub gard_version: String,

    /// When the checks ran
    pub issued_at: DateTime<Utc>,

    /// When this attestation stops being acceptable
    pub expires_at: DateTime<Utc>,

    /// Whether the machine passed preflight at issuance
    pub preflight_passing: bool,

    /// Finding counts at issuance
    pub summary: ReportSummary,

    /// Check ids that produced blocking findings (empty when passing)
    pub blocking_check_ids: Vec<String>,

    /// Signer public key (hex), attached at signing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Ed25519 signature (hex) over the unsigned attestation JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Attestation {
    pub fn new(
        ceremony_id: String,
        signer_name: String,
        summary: ReportSummary,
        blocking_check_ids: Vec<String>,
        valid_for_minutes: i64,
    ) -> Self {
        let now = Utc::now();
        Attestation {
            version: "1.0".to_string(),
            ceremony_id,
            signer_name,
            hostname: sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string()),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            platform: current_platform(),
            gard_version: crate::VERSION.to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(valid_for_minutes),
            preflight_passing: summary.preflight_passing,
            summary,
            blocking_check_ids,
            public_key: None,
            signature: None,
        }
    }

    /// Sign this attestation with the local Gard identity key
    pub fn sign(&mut self, signer: &ReportSigner) -> Result<()> {
        self.signature = None;
        self.public_key = None;
        let canonical = serde_json::to_string(self).map_err(GardError::JsonError)?;
        let (signature, public_key) = signer.sign_bytes(canonical.as_bytes());
        self.signature = Some(signature);
        self.public_key = Some(public_key);
        Ok(())
    }
}

/// Result of verifying an attestation, one field per acceptance criterion
#[derive(Debug, Clone, Serialize)]
pub struct VerificationOutcome {
    /// Ed25519 signature verifies against the embedded public key
    pub signature_valid: bool,

    /// Issued in the past (within skew) and not yet expired
    pub fresh: bool,

    /// Bound to the expected ceremony (true when no ceremony was given)
    pub ceremony_match: bool,

    /// Machine passed preflight at issuance
    pub posture_passing: bool,

    /// Team member name whose registered key signed this, if any
    pub trusted_signer: Option<String>,
}

impl VerificationOutcome {
    /// Whether the attestation is acceptable. Trust matching is enforced
    /// by the caller depending on whether a team roster is configured.
    pub fn acceptable(&self, require_trusted: bool) -> bool {
        self.signature_valid
            && self.fresh
            && self.ceremony_match
            && self.posture_passing
            && (!require_trusted || self.trusted_signer.is_some())
    }
}

/// Verify an attestation's signature, freshness, ceremony binding, and
/// posture. `trusted` maps team member names to public key hex strings.
pub fn verify_attestation(
    attestation: &Attestation,
    expected_ceremony: Option<&str>,
    trusted: &[(String, String)],
) -> Result<VerificationOutcome> {
    let signature_valid = check_signature(attestation).unwrap_or(false);

    let now = Utc::now();
    let fresh = attestation.issued_at <= now + Duration::minutes(MAX_CLOCK_SKEW_MINUTES)
        && attestation.expires_at >= now;

    let ceremony_match = expected_ceremony
        .map(|c| c == attestation.ceremony_id)
        .unwrap_or(true);

    let trusted_signer = attestation.public_key.as_ref().and_then(|pk| {
        let pk_hex = pk.strip_prefix("ed25519 ").unwrap_or(pk);
        trusted
            .iter()
            .find(|(_, key)| key.eq_ignore_ascii_case(pk_hex))
            .map(|(name, _)| name.clone())
    });

    Ok(VerificationOutcome {
        signature_valid,
        fresh,
        ceremony_match,
        posture_passing: attestation.preflight_passing,
        trusted_signer,
    })
}

fn check_signature(attestation: &Attestation) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let signature_hex = attestation
        .signature
        .as_ref()
        .ok_or(GardError::SignatureVerificationFailed)?;
    let public_key_hex = attestation
        .public_key
        .as_ref()
        .ok_or(GardError::SignatureVerificationFailed)?;
    let public_key_hex = public_key_hex
        .strip_prefix("ed25519 ")
        .unwrap_or(public_key_hex);

    let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|_| GardError::SignatureVerificationFailed)?
        .try_into()
        .map_err(|_| GardError::SignatureVerificationFailed)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| GardError::SignatureVerificationFailed)?;

    let signature_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(|_| GardError::SignatureVerificationFailed)?
        .try_into()
        .map_err(|_| GardError::SignatureVerificationFailed)?;
    let signature = Signature::from_bytes(&signature_bytes);

    let mut unsigned = attestation.clone();
    unsigned.signature = None;
    unsigned.public_key = None;
    let canonical = serde_json::to_string(&unsigned).map_err(GardError::JsonError)?;

    Ok(verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signer() -> ReportSigner {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rand::Rng::gen(&mut rng);
        ReportSigner::from_signing_key(SigningKey::from_bytes(&seed))
    }

    fn passing_summary() -> ReportSummary {
        ReportSummary::from_findings(&[])
    }

    fn signed_attestation(ceremony: &str) -> Attestation {
        let mut attestation = Attestation::new(
            ceremony.to_string(),
            "alice".to_string(),
            passing_summary(),
            Vec::new(),
            30,
        );
        attestation.sign(&test_signer()).expect("signing succeeds");
        attestation
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let attestation = signed_attestation("ceremony-1");
        let outcome = verify_attestation(&attestation, Some("ceremony-1"), &[]).expect("verifies");
        assert!(outcome.signature_valid);
        assert!(outcome.fresh);
        assert!(outcome.ceremony_match);
        assert!(outcome.posture_passing);
        assert!(outcome.acceptable(false));
    }

    #[test]
    fn test_tampered_attestation_rejected() {
        let mut attestation = signed_attestation("ceremony-1");
        attestation.preflight_passing = true;
        attestation.ceremony_id = "ceremony-other".to_string();
        let outcome = verify_attestation(&attestation, None, &[]).expect("verifies");
        assert!(!outcome.signature_valid);
        assert!(!outcome.acceptable(false));
    }

    #[test]
    fn test_ceremony_mismatch_rejected() {
        let attestation = signed_attestation("ceremony-1");
        let outcome = verify_attestation(&attestation, Some("ceremony-2"), &[]).expect("verifies");
        assert!(outcome.signature_valid);
        assert!(!outcome.ceremony_match);
        assert!(!outcome.acceptable(false));
    }

    #[test]
    fn test_expired_attestation_rejected() {
        let mut attestation = Attestation::new(
            "ceremony-1".to_string(),
            "alice".to_string(),
            passing_summary(),
            Vec::new(),
            30,
        );
        attestation.issued_at = Utc::now() - Duration::hours(2);
        attestation.expires_at = Utc::now() - Duration::hours(1);
        attestation.sign(&test_signer()).expect("signing succeeds");

        let outcome = verify_attestation(&attestation, None, &[]).expect("verifies");
        assert!(outcome.signature_valid);
        assert!(!outcome.fresh);
        assert!(!outcome.acceptable(false));
    }

    #[test]
    fn test_trusted_signer_matching() {
        let signer = test_signer();
        let mut attestation = Attestation::new(
            "ceremony-1".to_string(),
            "alice".to_string(),
            passing_summary(),
            Vec::new(),
            30,
        );
        attestation.sign(&signer).expect("signing succeeds");

        let roster = vec![("alice".to_string(), signer.public_key_hex())];
        let outcome = verify_attestation(&attestation, None, &roster).expect("verifies");
        assert_eq!(outcome.trusted_signer.as_deref(), Some("alice"));
        assert!(outcome.acceptable(true));

        let wrong_roster = vec![("bob".to_string(), "ab".repeat(32))];
        let outcome = verify_attestation(&attestation, None, &wrong_roster).expect("verifies");
        assert!(outcome.trusted_signer.is_none());
        assert!(!outcome.acceptable(true));
    }
}
