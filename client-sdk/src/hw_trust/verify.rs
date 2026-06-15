use crate::hw_trust::commitment::{pubkey_commitment_bytes, pubkey_commitment_hex};
use crate::hw_trust::error::HwTrustError;
use crate::hw_trust::handshake::HwHandshake;
use crate::hw_trust::m_hw::{m_hw_challenge_hash, parse_tier, validate_tier_backend};
use crate::hw_trust::types::HwBackend;
use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyStatus {
    Green,
    Red,
}

pub struct LocalVerifyResult {
    pub status: VerifyStatus,
    pub message: String,
}

pub fn verify_handshake_local(hs: &HwHandshake) -> Result<LocalVerifyResult, HwTrustError> {
    if hs.m_hw.is_expired() {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "challenge expired".into(),
        });
    }

    let backend = HwBackend::parse(&hs.backend)
        .ok_or_else(|| HwTrustError::Crypto(format!("unknown backend: {}", hs.backend)))?;
    let tier = parse_tier(&hs.tier)
        .ok_or_else(|| HwTrustError::Crypto(format!("unknown tier: {}", hs.tier)))?;
    validate_tier_backend(backend, tier)?;

    let spki = hex::decode(hs.pubkey_spki_der.trim())
        .map_err(|e| HwTrustError::Hex(e.to_string()))?;

    let expected_commitment = pubkey_commitment_hex(&spki);
    if expected_commitment != hs.pubkey_commitment {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "pubkey commitment mismatch".into(),
        });
    }

    if hs.pubkey_commitment != hs.m_hw.pubkey_commitment {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "m_hw pubkey commitment mismatch".into(),
        });
    }

    let challenge_hash = m_hw_challenge_hash(&hs.m_hw)?;
    let expected_hash_hex = hex::encode(challenge_hash);
    if expected_hash_hex != hs.challenge_hash {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "challenge hash mismatch".into(),
        });
    }

    let sig_bytes = hex::decode(hs.signature_der.trim())
        .map_err(|e| HwTrustError::Hex(e.to_string()))?;
    let signature = Signature::from_der(&sig_bytes)
        .map_err(|e| HwTrustError::Crypto(e.to_string()))?;
    let vk = VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| HwTrustError::Crypto(format!("invalid SPKI DER: {e}")))?;

    if vk.verify_prehash(&challenge_hash, &signature).is_err() {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "ECDSA signature invalid".into(),
        });
    }

    let pk_commit = pubkey_commitment_bytes(&spki);
    let expected_nullifier = crate::hw_trust::commitment::hw_nullifier_hex(&pk_commit)?;
    if expected_nullifier != hs.hw_nullifier {
        return Ok(LocalVerifyResult {
            status: VerifyStatus::Red,
            message: "hw_nullifier mismatch".into(),
        });
    }

    Ok(LocalVerifyResult {
        status: VerifyStatus::Green,
        message: "local crypto OK (hw-trust-v1, no ZK yet)".into(),
    })
}
