//! Tipos y paquetes ZK compartidos.

use serde::{Deserialize, Serialize};

pub const HW_CIRCUIT_VERSION: &str = "hw-trust-v1";
pub const DOC_CIRCUIT_VERSION: &str = "doc-bind-v1";
pub const GEO_CIRCUIT_VERSION: &str = "geo-range-v1";
pub const PROOF_PROVIDER_ID: &str = "midnight";
pub const PACKAGE_VERSION: &str = "1.0.0";

/// Alias histórico H2.
pub const CIRCUIT_VERSION: &str = HW_CIRCUIT_VERSION;

/// SPKI DER fijo para P-256 en software_poc / Keystore PoC (91 bytes).
pub const SPKI_LEN: usize = 91;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwTrustCircuitInstance {
    pub challenge_hash: [u8; 32],
    pub pubkey_commitment: [u8; 32],
    pub hw_nullifier: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HwTrustPublicInputs {
    pub challenge_hash: [u8; 32],
    pub pubkey_commitment: [u8; 32],
    pub hw_nullifier: [u8; 32],
    pub tier: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocBindPublicInputs {
    pub pdf_sha256: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub bundle_hash: [u8; 32],
    pub hw_nullifier: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoRangePublicInputs {
    pub center_lat_e6: i32,
    pub center_lon_e6: i32,
    pub radius_meters: u32,
    pub inside_range: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HwProofPackage {
    pub package_version: String,
    pub proof_provider_id: String,
    pub circuit_version: String,
    pub public_inputs: HwTrustPublicInputs,
    #[serde(with = "base64_bytes")]
    pub proof_bytes: Vec<u8>,
    pub verifying_key_ref: String,
    pub proving_time_ms: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocProofPackage {
    pub package_version: String,
    pub proof_provider_id: String,
    pub circuit_version: String,
    pub public_inputs: DocBindPublicInputs,
    #[serde(with = "base64_bytes")]
    pub proof_bytes: Vec<u8>,
    pub verifying_key_ref: String,
    pub proving_time_ms: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoProofPackage {
    pub package_version: String,
    pub proof_provider_id: String,
    pub circuit_version: String,
    pub public_inputs: GeoRangePublicInputs,
    #[serde(with = "base64_bytes")]
    pub proof_bytes: Vec<u8>,
    pub verifying_key_ref: String,
    pub proving_time_ms: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditSignEvidencePackage {
    pub package_version: String,
    pub hw_trust: HwProofPackage,
    pub doc_bind: DocProofPackage,
    pub geo_range: GeoProofPackage,
    pub total_proving_time_ms: u64,
    pub created_at: String,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        b64.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let b64 = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(serde::de::Error::custom)
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
