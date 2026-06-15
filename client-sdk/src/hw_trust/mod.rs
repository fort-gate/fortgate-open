mod commitment;
mod error;
mod handshake;
mod m_hw;
mod types;
mod verify;

pub mod backends;

pub use commitment::{hw_nullifier_hex, pubkey_commitment_bytes, pubkey_commitment_hex};
pub use error::HwTrustError;
pub use handshake::HwHandshake;
pub use m_hw::{m_hw_challenge_hash, MHw, CHALLENGE_TTL_SECS, HW_PURPOSE_POC};
pub use types::{HwBackend, HW_HANDSHAKE_PACKAGE_VERSION};
pub use verify::{verify_handshake_local, LocalVerifyResult, VerifyStatus};

use crate::hw_trust::backends::HwTrustBackend;

pub fn default_software_backend() -> backends::SoftwarePocBackend {
    backends::SoftwarePocBackend::default()
}

pub fn sign_challenge_with_backend<B: HwTrustBackend>(
    backend: &B,
    m_hw: &MHw,
) -> Result<HwHandshake, HwTrustError> {
    let spki = backend.pubkey_spki_der()?;
    let challenge_hash = m_hw.challenge_hash()?;
    let signature_der = backend.sign_challenge_hash(&challenge_hash)?;
    let pk_commit = pubkey_commitment_bytes(&spki);
    let tier = backend.detect_tier();
    let hw_backend = backend.backend_id();

    let attestation_chain_der = backend
        .attestation_chain()
        .map(|certs| certs.into_iter().map(hex::encode).collect())
        .unwrap_or_default();

    Ok(HwHandshake {
        package_version: HW_HANDSHAKE_PACKAGE_VERSION.to_string(),
        m_hw: m_hw.clone(),
        challenge_hash: hex::encode(challenge_hash),
        pubkey_spki_der: hex::encode(&spki),
        pubkey_commitment: pubkey_commitment_hex(&spki),
        signature_der: hex::encode(&signature_der),
        tier: m_hw::tier_to_str(tier).to_string(),
        backend: hw_backend.as_str().to_string(),
        signed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        attestation_chain_der,
        hw_nullifier: hw_nullifier_hex(&pk_commit)?,
    })
}
