/// Report signing and verification using Ed25519

use crate::error::Result;
use crate::types::Report;
use ed25519_dalek::{SigningKey, Signer};
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

    /// Load existing keypair or create new one
    fn load_or_create_signing_key() -> Result<SigningKey> {
        let key_path = Self::private_key_path()?;
        let key_dir = key_path.parent().unwrap();

        if !key_dir.exists() {
            fs::create_dir_all(key_dir).map_err(|e| crate::error::GardError::IoError(e))?;
            // Set directory permissions to 0700 (owner read/write/execute only)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o700);
                fs::set_permissions(key_dir, permissions)
                    .map_err(|e| crate::error::GardError::IoError(e))?;
            }
        }

        if key_path.exists() {
            let key_bytes = fs::read(&key_path)
                .map_err(|e| crate::error::GardError::IoError(e))?;
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
            fs::write(&key_path, &signing_key.to_bytes())
                .map_err(|e| crate::error::GardError::IoError(e))?;
            
            // Set file permissions to 0600 (owner read/write only)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o600);
                fs::set_permissions(&key_path, permissions)
                    .map_err(|e| crate::error::GardError::IoError(e))?;
            }

            // Save public key in OpenSSH format
            let pub_key_path = Self::public_key_path()?;
            let verifying_key = signing_key.verifying_key();
            let pub_key_str = format!("ssh-ed25519 {}", hex::encode(verifying_key.as_bytes()));
            fs::write(&pub_key_path, pub_key_str)
                .map_err(|e| crate::error::GardError::IoError(e))?;
            
            // Set public key file permissions to 0644 (readable by all, writable by owner)
            #[cfg(unix)]
            {
                let permissions = std::fs::Permissions::from_mode(0o644);
                fs::set_permissions(&pub_key_path, permissions)
                    .map_err(|e| crate::error::GardError::IoError(e))?;
            }

            Ok(signing_key)
        }
    }

    /// Sign a report
    pub fn sign_report(&self, report: &mut Report) -> Result<()> {
        let report_json = serde_json::to_string(&report)
            .map_err(|e| crate::error::GardError::JsonError(e))?;

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
            .ok_or_else(|| crate::error::GardError::Internal(
                "Could not determine home directory".to_string(),
            ))?
            .join(".gard");

        Ok(gard_dir.join("keys").join("ed25519"))
    }

    /// Get public key path
    fn public_key_path() -> Result<PathBuf> {
        let gard_dir = dirs::home_dir()
            .ok_or_else(|| crate::error::GardError::Internal(
                "Could not determine home directory".to_string(),
            ))?
            .join(".gard");

        Ok(gard_dir.join("keys").join("ed25519.pub"))
    }
}

/// Verify a signed report - simplified stub for now
pub fn verify_report(report: &Report) -> Result<bool> {
    if !report.metadata.signed {
        return Ok(false);
    }

    // Verify that signature and public key are present
    let _signature_hex = report
        .metadata
        .signature
        .as_ref()
        .ok_or_else(|| crate::error::GardError::SignatureVerificationFailed)?;

    let _public_key_hex = report
        .metadata
        .public_key
        .as_ref()
        .ok_or_else(|| crate::error::GardError::SignatureVerificationFailed)?;

    // Signature verification requires the report in its signed state
    // This is a simplified implementation
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_report_signer_creation() {
        // This test would require setting up a temporary directory
        // Skipped for now
    }
}
