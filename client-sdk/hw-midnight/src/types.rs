use serde::{Deserialize, Serialize};

pub const CIRCUIT_VERSION: &str = "hw-trust-v1";
pub const PROOF_PROVIDER_ID: &str = "midnight";
pub const PACKAGE_VERSION: &str = "1.0.0";

/// SPKI DER fijo para P-256 en software_poc / Keystore PoC (91 bytes).
pub const SPKI_LEN: usize = 91;

/// Entradas públicas del circuito (tier se valida off-circuit).
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
    /// `0=Medium`, `1=High`, `2=Maximum`
    pub tier: u8,
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
