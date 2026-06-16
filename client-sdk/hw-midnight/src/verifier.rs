//! Verificador Enterprise para `CreditSignVerifyRequest` (H4).

use crate::api_types::{
    CheckStatus, CreditSignVerifyRequest, IdentityMock, PublicSummary, SealedGeoArchive,
    VerifyChecks, VerifyErrorCode, VerifyErrorResponse, VerifyResponse, VerifyStatus,
    VerifySuccessResponse, MAX_DEVICE_EVIDENCE_BYTES, MAX_PROOF_BYTES,
};
use crate::doc_bind_provider::MidnightDocBindProvider;
use crate::geo::deg_to_e6;
use crate::geo_range_provider::MidnightGeoRangeProvider;
use crate::orchestrator::CreditSignProver;
use crate::provider::MidnightHwTrustProvider;
use crate::types::now_rfc3339;
use fortgate_id::hw_trust::parse_tier;
use fortgate_id::types::SecurityTier;
use std::sync::atomic::{AtomicU64, Ordering};

static ATTESTATION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct InstitutionPolicy {
    pub policy_id: String,
    pub min_tier: SecurityTier,
    pub location_tolerance_meters: u32,
    pub allow_software_poc: bool,
    pub require_kyc_mock_approved: bool,
    pub allowed_sealed_geo_key_ids: Vec<String>,
}

impl InstitutionPolicy {
    pub fn poc_default() -> Self {
        Self {
            policy_id: "credit-sign-mx-poc".into(),
            min_tier: SecurityTier::Medium,
            location_tolerance_meters: 200,
            allow_software_poc: true,
            require_kyc_mock_approved: true,
            allowed_sealed_geo_key_ids: vec!["bank-archive-key-v1".into()],
        }
    }

    pub fn production_strict() -> Self {
        Self {
            policy_id: "credit-sign-mx-v1".into(),
            min_tier: SecurityTier::High,
            location_tolerance_meters: 200,
            allow_software_poc: false,
            require_kyc_mock_approved: true,
            allowed_sealed_geo_key_ids: vec!["bank-archive-key-v1".into()],
        }
    }

    pub fn resolve(policy_id: Option<&str>) -> Self {
        match policy_id {
            Some("credit-sign-mx-v1") => Self::production_strict(),
            _ => Self::poc_default(),
        }
    }
}

pub struct CreditSignVerifier {
    prover: CreditSignProver,
}

impl Default for CreditSignVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CreditSignVerifier {
    pub fn new() -> Self {
        Self {
            prover: CreditSignProver::new(),
        }
    }

    pub fn verify_request(
        &self,
        request: &CreditSignVerifyRequest,
        policy: &InstitutionPolicy,
    ) -> VerifyResponse {
        let mut checks = VerifyChecks {
            zk_hw_trust: CheckStatus::Fail,
            zk_doc_bind: CheckStatus::Fail,
            zk_geo_range: CheckStatus::Fail,
            min_tier: CheckStatus::Fail,
            manifest_binding: CheckStatus::Fail,
            kyc_mock_gate: CheckStatus::Fail,
            sealed_geo_present: CheckStatus::Fail,
        };

        if let Err(msg) = validate_request_limits(request) {
            return red_response(&checks, VerifyErrorCode::InvalidRequest, msg);
        }

        if request.policy_id.as_deref() == Some(&policy.policy_id)
            || request.policy_id.is_none()
        {
            // ok
        } else if policy.policy_id != InstitutionPolicy::poc_default().policy_id {
            return red_response(
                &checks,
                VerifyErrorCode::PolicyRejected,
                format!("policy_id no reconocida: {:?}", request.policy_id),
            );
        }

        checks.sealed_geo_present = check_sealed_geo(&request.sealed_geo_archive, policy);
        checks.kyc_mock_gate = check_kyc_mock(&request.identity_mock, policy);

        checks.manifest_binding = check_manifest_binding(request);

        checks.zk_hw_trust = if MidnightHwTrustProvider::new()
            .verify_against_handshake(&request.evidence.hw_trust, &request.handshake)
            .is_ok()
        {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        checks.zk_doc_bind = if MidnightDocBindProvider::new()
            .verify(&request.evidence.doc_bind, &request.doc_bind_record)
            .is_ok()
        {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        checks.zk_geo_range = if MidnightGeoRangeProvider::new()
            .verify(&request.evidence.geo_range)
            .is_ok()
        {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        };

        checks.min_tier = check_min_tier(request, policy);

        if !checks.all_zk_pass() {
            let code = if checks.zk_hw_trust != CheckStatus::Pass {
                VerifyErrorCode::ZkHwTrustFailed
            } else if checks.zk_doc_bind != CheckStatus::Pass {
                VerifyErrorCode::ZkDocBindFailed
            } else {
                VerifyErrorCode::ZkGeoRangeFailed
            };
            return red_response(&checks, code, "ZK proof verification failed".into());
        }

        if checks.manifest_binding != CheckStatus::Pass {
            return red_response(
                &checks,
                VerifyErrorCode::ManifestBindingFailed,
                "manifest binding check failed".into(),
            );
        }

        if checks.kyc_mock_gate != CheckStatus::Pass {
            return red_response(
                &checks,
                VerifyErrorCode::KycMockRejected,
                "KYC mock gate rejected".into(),
            );
        }

        if checks.sealed_geo_present != CheckStatus::Pass {
            let code = if request.sealed_geo_archive.ciphertext_b64.is_empty() {
                VerifyErrorCode::SealedGeoMissing
            } else {
                VerifyErrorCode::SealedGeoKeyRejected
            };
            return red_response(&checks, code, "sealedGeoArchive invalid".into());
        }

        if checks.min_tier != CheckStatus::Pass {
            return red_response(
                &checks,
                VerifyErrorCode::TierInsufficient,
                "hardware tier below institution policy".into(),
            );
        }

        let weak_device = request.handshake.backend == "software_poc" && !policy.allow_software_poc;
        let status = if weak_device {
            VerifyStatus::Yellow
        } else {
            VerifyStatus::Green
        };

        let public_summary = PublicSummary {
            inside_declared_domicile: request.evidence.geo_range.public_inputs.inside_range,
            hardware_tier: request.handshake.tier.clone(),
            pdf_sha256: request.doc_bind_record.pdf_sha256.clone(),
            manifest_sha256: request.doc_bind_record.manifest_hash.clone(),
            hw_nullifier: request.handshake.hw_nullifier.clone(),
            radius_meters: request.evidence.geo_range.public_inputs.radius_meters,
        };

        let body = VerifySuccessResponse {
            status,
            attestation_id: next_attestation_id(),
            verified_at: now_rfc3339(),
            checks,
            public_summary,
        };

        if status == VerifyStatus::Yellow {
            VerifyResponse::Yellow(body)
        } else {
            VerifyResponse::Green(body)
        }
    }

    pub fn verify_all_local(
        &self,
        request: &CreditSignVerifyRequest,
    ) -> Result<(), crate::error::HwMidnightError> {
        self.prover.verify_all(
            &request.evidence,
            &request.handshake,
            &request.doc_bind_record,
        )
    }
}

fn validate_request_limits(request: &CreditSignVerifyRequest) -> Result<(), String> {
    for proof in [
        &request.evidence.hw_trust.proof_bytes,
        &request.evidence.doc_bind.proof_bytes,
        &request.evidence.geo_range.proof_bytes,
    ] {
        if proof.len() > MAX_PROOF_BYTES {
            return Err(format!("proofBytes exceeds {MAX_PROOF_BYTES} bytes"));
        }
    }
    let device_len = serde_json::to_string(&request.device_evidence)
        .map_err(|e| e.to_string())?
        .len();
    if device_len > MAX_DEVICE_EVIDENCE_BYTES {
        return Err(format!(
            "deviceEvidence exceeds {MAX_DEVICE_EVIDENCE_BYTES} bytes"
        ));
    }
    Ok(())
}

fn check_sealed_geo(archive: &SealedGeoArchive, policy: &InstitutionPolicy) -> CheckStatus {
    if archive.ciphertext_b64.is_empty() {
        return CheckStatus::Fail;
    }
    if !policy
        .allowed_sealed_geo_key_ids
        .iter()
        .any(|k| k == &archive.key_id)
    {
        return CheckStatus::Fail;
    }
    if archive.plaintext_fields.is_empty() {
        return CheckStatus::Fail;
    }
    CheckStatus::Pass
}

fn check_kyc_mock(identity: &IdentityMock, policy: &InstitutionPolicy) -> CheckStatus {
    if !policy.require_kyc_mock_approved {
        return CheckStatus::Pass;
    }
    if identity.kyc_status.eq_ignore_ascii_case("approved") && !identity.subject_id.is_empty() {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}

fn check_manifest_binding(request: &CreditSignVerifyRequest) -> CheckStatus {
    let record = &request.doc_bind_record;
    let doc_pi = &request.evidence.doc_bind.public_inputs;
    let geo_pi = &request.evidence.geo_range.public_inputs;
    let dom = &record.manifest.domicile_ref;

    let pdf_ok = record.pdf_sha256 == hex::encode(doc_pi.pdf_sha256);
    let manifest_ok = record.manifest_hash == hex::encode(doc_pi.manifest_hash);
    let bundle_ok = record.bundle_hash == hex::encode(doc_pi.bundle_hash);
    let nullifier_ok = record.hw_nullifier == hex::encode(doc_pi.hw_nullifier)
        && record.hw_nullifier == request.handshake.hw_nullifier;

    let center_lat_ok = geo_pi.center_lat_e6 == deg_to_e6(dom.center_lat);
    let center_lon_ok = geo_pi.center_lon_e6 == deg_to_e6(dom.center_lon);
    let radius_ok = geo_pi.radius_meters == dom.radius_meters
        && geo_pi.radius_meters <= policy_max_radius();

    if pdf_ok
        && manifest_ok
        && bundle_ok
        && nullifier_ok
        && center_lat_ok
        && center_lon_ok
        && radius_ok
        && geo_pi.inside_range
    {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}

fn policy_max_radius() -> u32 {
    InstitutionPolicy::poc_default().location_tolerance_meters
}

fn tier_rank(tier: SecurityTier) -> u8 {
    match tier {
        SecurityTier::Medium => 0,
        SecurityTier::High => 1,
        SecurityTier::Maximum => 2,
    }
}

fn check_min_tier(request: &CreditSignVerifyRequest, policy: &InstitutionPolicy) -> CheckStatus {
    if request.handshake.backend == "software_poc" && !policy.allow_software_poc {
        // ZK puede pasar; el servidor emitirá YELLOW, no RED por tier.
        return CheckStatus::Pass;
    }

    let hs_tier = parse_tier(&request.handshake.tier);
    let dev_tier = parse_tier(&request.device_evidence.tier);
    let min_rank = tier_rank(policy.min_tier);

    let tiers_ok = hs_tier
        .map(|t| tier_rank(t) >= min_rank)
        .unwrap_or(false)
        && dev_tier
            .map(|t| tier_rank(t) >= min_rank)
            .unwrap_or(false);

    if tiers_ok {
        CheckStatus::Pass
    } else {
        CheckStatus::Fail
    }
}

fn next_attestation_id() -> String {
    let n = ATTESTATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("att_cs_{n:012}")
}

fn red_response(
    checks: &VerifyChecks,
    error_code: VerifyErrorCode,
    message: String,
) -> VerifyResponse {
    VerifyResponse::Red(VerifyErrorResponse {
        status: VerifyStatus::Red,
        error_code,
        message,
        checks: checks.clone(),
    })
}
