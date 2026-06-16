//! Manifiesto de firma de crédito (`CreditSignManifest`).

use crate::error::HwMidnightError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST_VERSION: &str = "1.0.0";
pub const MANIFEST_SCHEMA_ID: &str = "urn:fortgate:credit-sign-manifest:v1";
pub const MAX_MANIFEST_JCS_LEN: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DomicileRef {
    pub center_lat: f64,
    pub center_lon: f64,
    pub radius_meters: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreditSignManifest {
    pub manifest_version: String,
    pub manifest_schema_id: String,
    pub application_id: String,
    pub product_type: String,
    pub applicant_mock_id: String,
    pub terms_version: String,
    pub accepted_at: String,
    pub pdf_sha256: String,
    pub domicile_ref: DomicileRef,
    pub form_fields: serde_json::Value,
}

impl CreditSignManifest {
    pub fn demo_pyme(application_id: &str, pdf_sha256: &str, domicile: DomicileRef) -> Self {
        Self {
            manifest_version: MANIFEST_VERSION.to_string(),
            manifest_schema_id: MANIFEST_SCHEMA_ID.to_string(),
            application_id: application_id.to_string(),
            product_type: "credit".into(),
            applicant_mock_id: "mock-pyme-001".into(),
            terms_version: "2026-06-01".into(),
            accepted_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            pdf_sha256: pdf_sha256.to_string(),
            domicile_ref: domicile,
            form_fields: serde_json::json!({
                "amountMxn": 500000,
                "termMonths": 36
            }),
        }
    }
}

pub fn manifest_jcs_bytes(manifest: &CreditSignManifest) -> Result<Vec<u8>, HwMidnightError> {
    let value = serde_json::to_value(manifest).map_err(HwMidnightError::Json)?;
    let canonical = serde_jcs::to_string(&value).map_err(|e| HwMidnightError::Jcs(e.to_string()))?;
    if canonical.len() > MAX_MANIFEST_JCS_LEN {
        return Err(HwMidnightError::Manifest(format!(
            "JCS demasiado largo: {} > {MAX_MANIFEST_JCS_LEN}",
            canonical.len()
        )));
    }
    Ok(canonical.into_bytes())
}

pub fn manifest_hash_bytes(jcs_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(jcs_bytes);
    h.finalize().into()
}

pub fn manifest_hash_hex(jcs_bytes: &[u8]) -> String {
    hex::encode(manifest_hash_bytes(jcs_bytes))
}

pub fn bundle_hash_bytes(pdf_sha256: &[u8; 32], manifest_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pdf_sha256);
    h.update(manifest_hash);
    h.finalize().into()
}

pub fn hex_fixed32(s: &str) -> Result<[u8; 32], HwMidnightError> {
    let v = hex::decode(s.trim()).map_err(|e| HwMidnightError::Hex(e.to_string()))?;
    if v.len() != 32 {
        return Err(HwMidnightError::Hex(format!("expected 32 bytes, got {}", v.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn pad_manifest_jcs(jcs: &[u8]) -> Result<[u8; MAX_MANIFEST_JCS_LEN], HwMidnightError> {
    if jcs.len() > MAX_MANIFEST_JCS_LEN {
        return Err(HwMidnightError::Manifest("manifest JCS too long".into()));
    }
    let mut out = [0u8; MAX_MANIFEST_JCS_LEN];
    out[..jcs.len()].copy_from_slice(jcs);
    Ok(out)
}
