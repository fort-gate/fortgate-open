use crate::hw_trust::error::HwTrustError;
use crate::hw_trust::types::HwBackend;
use crate::types::SecurityTier;

pub trait HwTrustBackend {
    fn backend_id(&self) -> HwBackend;
    fn detect_tier(&self) -> SecurityTier;
    fn pubkey_spki_der(&self) -> Result<Vec<u8>, HwTrustError>;
    fn sign_challenge_hash(&self, challenge_hash: &[u8; 32]) -> Result<Vec<u8>, HwTrustError>;
    fn attestation_chain(&self) -> Option<Vec<Vec<u8>>> {
        None
    }
}

pub mod software_poc;

pub use software_poc::SoftwarePocBackend;
