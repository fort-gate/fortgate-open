use crate::hw_trust::m_hw::MHw;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HwHandshake {
    pub package_version: String,
    pub m_hw: MHw,
    pub challenge_hash: String,
    pub pubkey_spki_der: String,
    pub pubkey_commitment: String,
    pub signature_der: String,
    pub tier: String,
    pub backend: String,
    pub signed_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestation_chain_der: Vec<String>,
    pub hw_nullifier: String,
}

impl HwHandshake {
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
