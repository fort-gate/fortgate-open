use crate::hw_trust::backends::HwTrustBackend;
use crate::hw_trust::error::HwTrustError;
use crate::hw_trust::types::HwBackend;
use crate::types::SecurityTier;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};

const KEY_FILE: &str = "key.pem";

/// Simula Secure Enclave en desktop — **DEV ONLY**, tier `Medium`.
#[derive(Debug, Clone)]
pub struct SoftwarePocBackend {
    key_dir: PathBuf,
}

impl Default for SoftwarePocBackend {
    fn default() -> Self {
        Self {
            key_dir: default_key_dir(),
        }
    }
}

impl SoftwarePocBackend {
    pub fn new(key_dir: impl Into<PathBuf>) -> Self {
        Self {
            key_dir: key_dir.into(),
        }
    }

    pub fn key_dir(&self) -> &Path {
        &self.key_dir
    }

    pub fn key_path(&self) -> PathBuf {
        self.key_dir.join(KEY_FILE)
    }

    /// Genera par P-256 y persiste PKCS#8 PEM en `key_dir/key.pem`.
    pub fn keygen(&self) -> Result<VerifyingKey, HwTrustError> {
        fs::create_dir_all(&self.key_dir)?;
        let signing_key = SigningKey::random(&mut OsRng);
        let pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| HwTrustError::Crypto(e.to_string()))?;
        fs::write(self.key_path(), pem.as_bytes())?;
        Ok(*signing_key.verifying_key())
    }

    fn load_signing_key(&self) -> Result<SigningKey, HwTrustError> {
        let path = self.key_path();
        if !path.exists() {
            return Err(HwTrustError::KeyNotFound(path.display().to_string()));
        }
        let pem = fs::read_to_string(&path)?;
        SigningKey::from_pkcs8_pem(&pem).map_err(|e| HwTrustError::Crypto(e.to_string()))
    }
}

impl HwTrustBackend for SoftwarePocBackend {
    fn backend_id(&self) -> HwBackend {
        HwBackend::SoftwarePoc
    }

    fn detect_tier(&self) -> SecurityTier {
        SecurityTier::Medium
    }

    fn pubkey_spki_der(&self) -> Result<Vec<u8>, HwTrustError> {
        let sk = self.load_signing_key()?;
        let vk = sk.verifying_key();
        let doc = vk
            .to_public_key_der()
            .map_err(|e| HwTrustError::Crypto(e.to_string()))?;
        Ok(doc.as_bytes().to_vec())
    }

    fn sign_challenge_hash(&self, challenge_hash: &[u8; 32]) -> Result<Vec<u8>, HwTrustError> {
        let sk = self.load_signing_key()?;
        let sig: p256::ecdsa::Signature = sk
            .sign_prehash(challenge_hash)
            .map_err(|e| HwTrustError::Crypto(e.to_string()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

pub fn default_key_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fortgate")
        .join("poc_hw")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw_trust::m_hw::MHw;
    use crate::hw_trust::{sign_challenge_with_backend, verify_handshake_local};
    use crate::hw_trust::verify::VerifyStatus;
    use tempfile::tempdir;

    #[test]
    fn software_poc_sign_verify_roundtrip() {
        let dir = tempdir().unwrap();
        let backend = SoftwarePocBackend::new(dir.path());
        backend.keygen().unwrap();
        let spki = backend.pubkey_spki_der().unwrap();
        let m_hw = MHw::new_challenge(
            HwBackend::SoftwarePoc,
            SecurityTier::Medium,
            &spki,
            None,
        )
        .unwrap();
        let hs = sign_challenge_with_backend(&backend, &m_hw).unwrap();
        let res = verify_handshake_local(&hs).unwrap();
        assert_eq!(res.status, VerifyStatus::Green);
    }
}
