//! Tipos HTTP para la API Enterprise de verificación de firma de crédito (H4).

use crate::doc_bind_provider::DocBindRecord;
use crate::types::CreditSignEvidencePackage;
use base64::Engine;
use fortgate_id::hw_trust::HwHandshake;
use serde::{Deserialize, Serialize};

pub const MAX_PROOF_BYTES: usize = 64 * 1024;
pub const MAX_DEVICE_EVIDENCE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityMock {
    pub subject_id: String,
    pub kyc_status: String,
}

impl Default for IdentityMock {
    fn default() -> Self {
        Self {
            subject_id: "mock-user-001".into(),
            kyc_status: "approved".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceEvidence {
    pub os: String,
    pub model: String,
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedGeoArchive {
    pub ciphertext_b64: String,
    pub key_id: String,
    pub algorithm: String,
    pub plaintext_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditSignVerifyRequest {
    pub evidence: CreditSignEvidencePackage,
    pub handshake: HwHandshake,
    pub doc_bind_record: DocBindRecord,
    pub device_evidence: DeviceEvidence,
    pub sealed_geo_archive: SealedGeoArchive,
    #[serde(default)]
    pub identity_mock: IdentityMock,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyChecks {
    pub zk_hw_trust: CheckStatus,
    pub zk_doc_bind: CheckStatus,
    pub zk_geo_range: CheckStatus,
    pub min_tier: CheckStatus,
    pub manifest_binding: CheckStatus,
    pub kyc_mock_gate: CheckStatus,
    pub sealed_geo_present: CheckStatus,
}

impl VerifyChecks {
    pub fn all_zk_pass(&self) -> bool {
        self.zk_hw_trust == CheckStatus::Pass
            && self.zk_doc_bind == CheckStatus::Pass
            && self.zk_geo_range == CheckStatus::Pass
    }

    pub fn all_mandatory_pass(&self) -> bool {
        self.all_zk_pass()
            && self.min_tier == CheckStatus::Pass
            && self.manifest_binding == CheckStatus::Pass
            && self.kyc_mock_gate == CheckStatus::Pass
            && self.sealed_geo_present == CheckStatus::Pass
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifyStatus {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSummary {
    pub inside_declared_domicile: bool,
    pub hardware_tier: String,
    pub pdf_sha256: String,
    pub manifest_sha256: String,
    pub hw_nullifier: String,
    pub radius_meters: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySuccessResponse {
    pub status: VerifyStatus,
    pub attestation_id: String,
    pub verified_at: String,
    pub checks: VerifyChecks,
    pub public_summary: PublicSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifyErrorCode {
    InvalidRequest,
    ProofTooLarge,
    ZkHwTrustFailed,
    ZkDocBindFailed,
    ZkGeoRangeFailed,
    TierInsufficient,
    ManifestBindingFailed,
    KycMockRejected,
    SealedGeoMissing,
    SealedGeoKeyRejected,
    PolicyRejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyErrorResponse {
    pub status: VerifyStatus,
    pub error_code: VerifyErrorCode,
    pub message: String,
    pub checks: VerifyChecks,
}

#[derive(Debug, Clone)]
pub enum VerifyResponse {
    Green(VerifySuccessResponse),
    Yellow(VerifySuccessResponse),
    Red(VerifyErrorResponse),
}

/// Cifra coords para PoC: base64(JSON) — sustituto de XChaCha20 hasta integrar clave banco.
pub fn seal_geo_archive_poc(
    actual_lat: f64,
    actual_lon: f64,
    key_id: &str,
) -> SealedGeoArchive {
    let payload = serde_json::json!({
        "actualLat": actual_lat,
        "actualLon": actual_lon,
        "capturedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(payload.to_string());
    SealedGeoArchive {
        ciphertext_b64,
        key_id: key_id.to_string(),
        algorithm: "fortgate-poc-sealed-v1".into(),
        plaintext_fields: vec![
            "actualLat".into(),
            "actualLon".into(),
            "capturedAt".into(),
        ],
    }
}

pub fn device_evidence_from_handshake(hs: &HwHandshake) -> DeviceEvidence {
    DeviceEvidence {
        os: std::env::consts::OS.into(),
        model: "desktop-poc".into(),
        tier: hs.tier.clone(),
        attestation_ref: None,
    }
}

pub fn build_verify_request(
    evidence: CreditSignEvidencePackage,
    handshake: HwHandshake,
    doc_bind_record: DocBindRecord,
    actual_lat: f64,
    actual_lon: f64,
) -> CreditSignVerifyRequest {
    CreditSignVerifyRequest {
        evidence,
        handshake: handshake.clone(),
        doc_bind_record: doc_bind_record.clone(),
        device_evidence: device_evidence_from_handshake(&handshake),
        sealed_geo_archive: seal_geo_archive_poc(
            actual_lat,
            actual_lon,
            "bank-archive-key-v1",
        ),
        identity_mock: IdentityMock::default(),
        policy_id: Some("credit-sign-mx-poc".into()),
    }
}
