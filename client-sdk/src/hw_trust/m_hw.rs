use crate::hw_trust::commitment::pubkey_commitment_hex;
use crate::hw_trust::error::HwTrustError;
use crate::hw_trust::types::HwBackend;
use crate::types::SecurityTier;
use chrono::{Duration, Utc};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const HW_BIND_VERSION: &str = "1.0.0";
pub const HW_SCHEMA_ID: &str = "urn:fortgate:hw-bind:v1";
pub const HW_PURPOSE_POC: &str = "fortgate_hw_trust_poc";
pub const CHALLENGE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MHw {
    pub hw_bind_version: String,
    pub hw_schema_id: String,
    pub purpose: String,
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub tier_claimed: String,
    pub backend: String,
    pub pubkey_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_nullifier: Option<String>,
}

impl MHw {
    pub fn new_challenge(
        backend: HwBackend,
        tier: SecurityTier,
        pubkey_spki_der: &[u8],
        verifier_id: Option<String>,
    ) -> Result<Self, HwTrustError> {
        let tier_claimed = tier_to_str(tier);
        validate_tier_backend(backend, tier)?;

        let now = Utc::now();
        let expires = now + Duration::seconds(CHALLENGE_TTL_SECS);
        let mut nonce_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut nonce_bytes);

        Ok(Self {
            hw_bind_version: HW_BIND_VERSION.to_string(),
            hw_schema_id: HW_SCHEMA_ID.to_string(),
            purpose: HW_PURPOSE_POC.to_string(),
            challenge_id: Uuid::new_v4().to_string(),
            nonce: hex::encode(nonce_bytes),
            issued_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            tier_claimed: tier_claimed.to_string(),
            backend: backend.as_str().to_string(),
            pubkey_commitment: pubkey_commitment_hex(pubkey_spki_der),
            verifier_id,
            session_id: None,
            identity_nullifier: None,
        })
    }

    pub fn challenge_hash(&self) -> Result<[u8; 32], HwTrustError> {
        m_hw_challenge_hash(self)
    }

    pub fn is_expired(&self) -> bool {
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|exp| exp < Utc::now())
            .unwrap_or(true)
    }
}

pub fn m_hw_challenge_hash(m_hw: &MHw) -> Result<[u8; 32], HwTrustError> {
    let value = serde_json::to_value(m_hw).map_err(HwTrustError::Json)?;
    let canonical = serde_jcs::to_string(&value).map_err(|e| HwTrustError::Jcs(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().into())
}

pub fn tier_to_str(tier: SecurityTier) -> &'static str {
    match tier {
        SecurityTier::Maximum => "Maximum",
        SecurityTier::High => "High",
        SecurityTier::Medium => "Medium",
    }
}

pub fn parse_tier(s: &str) -> Option<SecurityTier> {
    match s {
        "Maximum" => Some(SecurityTier::Maximum),
        "High" => Some(SecurityTier::High),
        "Medium" => Some(SecurityTier::Medium),
        _ => None,
    }
}

pub fn validate_tier_backend(backend: HwBackend, tier: SecurityTier) -> Result<(), HwTrustError> {
    match backend {
        HwBackend::SoftwarePoc if tier != SecurityTier::Medium => Err(HwTrustError::TierBackendMismatch),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_hash_deterministic() {
        let m = MHw {
            hw_bind_version: HW_BIND_VERSION.to_string(),
            hw_schema_id: HW_SCHEMA_ID.to_string(),
            purpose: HW_PURPOSE_POC.to_string(),
            challenge_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            nonce: "aa".repeat(32),
            issued_at: "2026-06-01T18:00:00Z".to_string(),
            expires_at: "2026-06-01T18:05:00Z".to_string(),
            tier_claimed: "Medium".to_string(),
            backend: "software_poc".to_string(),
            pubkey_commitment: "bb".repeat(32),
            verifier_id: None,
            session_id: None,
            identity_nullifier: None,
        };
        let h1 = m.challenge_hash().unwrap();
        let h2 = m.challenge_hash().unwrap();
        assert_eq!(h1, h2);
    }
}
