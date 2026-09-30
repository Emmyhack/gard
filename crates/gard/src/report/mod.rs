//! Report signing and verification using Ed25519

use crate::error::Result;
use crate::types::Report;
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct ReportSigner {
    signing_key: SigningKey,
}

impl ReportSigner {
    /// Create a new report signer with the local keypair
    pub fn new() -> Result<Self> {
        let signing_key = Self::load_or_create_signing_key()?;
        Ok(ReportSigner { signing_key })
    }

    /// Build a signer from an explicit key (used by tests and tooling)
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        ReportSigner { signing_key }
    }

    /// Sign arbitrary bytes; returns (signature_hex, public_key_hex)
    pub fn sign_bytes(&self, data: &[u8]) -> (String, String) {
        let signature = self.signing_key.sign(data);
        (
            hex::encode(signature.to_bytes()),
            hex::encode(self.signing_key.verifying_key().as_bytes()),
        )
    }

    /// Load existing keypair or create new one
    fn load_or_create_signing_key() -> Result<SigningKey> {
        let key_path = Self::private_key_path()?;
        let key_dir = key_path.parent().unwrap();

        if !key_dir.exists() {
            fs::create_dir_all(key_dir).map_err(crate::error::GardError::IoError)?;
            // Set directory permissions to 0700 (owner read/write/execute only)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o700);
                fs::set_permissions(key_dir, permissions)
                    .map_err(crate::error::GardError::IoError)?;
            }
        }

        if key_path.exists() {
            let key_bytes = fs::read(&key_path).map_err(crate::error::GardError::IoError)?;
            if key_bytes.len() != 32 {
                return Err(crate::error::GardError::Internal(
                    "Invalid keypair file".to_string(),
                ));
            }
            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&key_bytes);
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            // Zeroize the temporary bytes used for key loading
            secret_bytes.zeroize();
            Ok(signing_key)
        } else {
            // Generate new keypair
            let mut rng = rand::thread_rng();
            let seed: [u8; 32] = rng.gen();
            let signing_key = SigningKey::from_bytes(&seed);

            // Save private key with restricted permissions
            fs::write(&key_path, signing_key.to_bytes())
                .map_err(crate::error::GardError::IoError)?;

            // Set file permissions to 0600 (owner read/write only)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o600);
                fs::set_permissions(&key_path, permissions)
                    .map_err(crate::error::GardError::IoError)?;
            }

            // Save public key in OpenSSH format
            let pub_key_path = Self::public_key_path()?;
            let verifying_key = signing_key.verifying_key();
            let pub_key_str = format!("ssh-ed25519 {}", hex::encode(verifying_key.as_bytes()));
            fs::write(&pub_key_path, pub_key_str).map_err(crate::error::GardError::IoError)?;

            // Set public key file permissions to 0644 (readable by all, writable by owner)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o644);
                fs::set_permissions(&pub_key_path, permissions)
                    .map_err(crate::error::GardError::IoError)?;
            }

            Ok(signing_key)
        }
    }

    /// Sign a report
    pub fn sign_report(&self, report: &mut Report) -> Result<()> {
        let report_json =
            serde_json::to_string(&report).map_err(crate::error::GardError::JsonError)?;

        let signature = self.signing_key.sign(report_json.as_bytes());
        let verifying_key = self.signing_key.verifying_key();

        report.metadata.signature = Some(hex::encode(signature.to_bytes()));
        report.metadata.public_key =
            Some(format!("ed25519 {}", hex::encode(verifying_key.as_bytes())));
        report.metadata.signed = true;

        Ok(())
    }

    /// Get the public key
    pub fn public_key_hex(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        hex::encode(verifying_key.as_bytes())
    }

    /// Get private key path
    fn private_key_path() -> Result<PathBuf> {
        let gard_dir = dirs::home_dir()
            .ok_or_else(|| {
                crate::error::GardError::Internal("Could not determine home directory".to_string())
            })?
            .join(".gard");

        Ok(gard_dir.join("keys").join("ed25519"))
    }

    /// Get public key path
    fn public_key_path() -> Result<PathBuf> {
        let gard_dir = dirs::home_dir()
            .ok_or_else(|| {
                crate::error::GardError::Internal("Could not determine home directory".to_string())
            })?
            .join(".gard");

        Ok(gard_dir.join("keys").join("ed25519.pub"))
    }
}

/// Verify a signed report's Ed25519 signature.
///
/// The signature covers the report serialized before signing metadata was
/// attached (signed=false, no signature/public_key), so verification
/// reconstructs that canonical form.
pub fn verify_report(report: &Report) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if !report.metadata.signed {
        return Ok(false);
    }

    let signature_hex = report
        .metadata
        .signature
        .as_ref()
        .ok_or(crate::error::GardError::SignatureVerificationFailed)?;

    let public_key_field = report
        .metadata
        .public_key
        .as_ref()
        .ok_or(crate::error::GardError::SignatureVerificationFailed)?;

    // Public key is stored as "ed25519 <hex>"
    let public_key_hex = public_key_field
        .strip_prefix("ed25519 ")
        .unwrap_or(public_key_field);

    let public_key_bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|_| crate::error::GardError::SignatureVerificationFailed)?
        .try_into()
        .map_err(|_| crate::error::GardError::SignatureVerificationFailed)?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| crate::error::GardError::SignatureVerificationFailed)?;

    let signature_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(|_| crate::error::GardError::SignatureVerificationFailed)?
        .try_into()
        .map_err(|_| crate::error::GardError::SignatureVerificationFailed)?;
    let signature = Signature::from_bytes(&signature_bytes);

    // Reconstruct the report as it was when signed
    let mut unsigned = report.clone();
    unsigned.metadata.signature = None;
    unsigned.metadata.public_key = None;
    unsigned.metadata.signed = false;
    let canonical = serde_json::to_string(&unsigned).map_err(crate::error::GardError::JsonError)?;

    Ok(verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_ok())
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    fn test_report() -> Report {
        Report {
            metadata: crate::types::ReportMetadata {
                version: "1.0".to_string(),
                gard_version: "0.1.0".to_string(),
                timestamp: chrono::Utc::now(),
                hostname: "test-host".to_string(),
                username: "test-user".to_string(),
                platform: crate::types::current_platform(),
                platform_version: "test".to_string(),
                scan_duration_ms: 1,
                signed: false,
                signature: None,
                public_key: None,
            },
            summary: crate::types::ReportSummary::from_findings(&[]),
            findings: Vec::new(),
        }
    }

    #[test]
    fn test_sign_verify_round_trip() {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rand::Rng::gen(&mut rng);
        let signer = ReportSigner {
            signing_key: SigningKey::from_bytes(&seed),
        };

        let mut report = test_report();
        signer.sign_report(&mut report).expect("signing succeeds");
        assert!(report.metadata.signed);

        assert!(verify_report(&report).expect("verification runs"));
    }

    #[test]
    fn test_tampered_report_fails_verification() {
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rand::Rng::gen(&mut rng);
        let signer = ReportSigner {
            signing_key: SigningKey::from_bytes(&seed),
        };

        let mut report = test_report();
        signer.sign_report(&mut report).expect("signing succeeds");

        report.metadata.hostname = "attacker-host".to_string();
        assert!(!verify_report(&report).expect("verification runs"));
    }

    #[test]
    fn test_unsigned_report_fails_verification() {
        let report = test_report();
        assert!(!verify_report(&report).expect("verification runs"));
    }
}
