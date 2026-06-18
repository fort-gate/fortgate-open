//! Orquestador del happy path completo para demo web / CTO.

use crate::api_types::{build_verify_request, CreditSignVerifyRequest};
use crate::doc_bind_provider::{DocBindRecord, MidnightDocBindProvider};
use crate::error::HwMidnightError;
use crate::geo_range_provider::MidnightGeoRangeProvider;
use crate::manifest::CreditSignManifest;
use crate::orchestrator::{demo_manifest, sign_doc_manifest, CreditSignProver};
use crate::provider::MidnightHwTrustProvider;
use crate::types::CreditSignEvidencePackage;
use fortgate_id::hw_trust::backends::{software_poc::SoftwarePocBackend, HwTrustBackend};
use fortgate_id::hw_trust::{
    sign_challenge_with_backend, verify_handshake_local, HwBackend, MHw, VerifyStatus,
};
use fortgate_id::types::SecurityTier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DemoPhase {
    Starting,
    Keygen,
    Challenge,
    SignHandshake,
    VerifyLocalCrypto,
    SignDocument,
    SetupKeys,
    ProveHwTrust,
    ProveDocBind,
    ProveGeoRange,
    VerifyProofsLocal,
    BuildVerifyRequest,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoProgress {
    pub phase: DemoPhase,
    pub message: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoTimings {
    pub keygen_ms: u64,
    pub sign_ms: u64,
    pub prove_hw_ms: u64,
    pub prove_doc_ms: u64,
    pub prove_geo_ms: u64,
    pub verify_local_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditSignDemoArtifacts {
    pub work_dir: String,
    pub backend: String,
    pub tier: String,
    pub handshake_json: String,
    pub doc_bind_record_json: String,
    pub evidence_json: String,
    pub verify_request_json: String,
    pub pubkey_commitment: String,
    pub hw_nullifier: String,
    pub pdf_sha256: String,
    pub manifest_hash: String,
    pub timings: DemoTimings,
    pub local_crypto_ok: bool,
}

#[derive(Debug, Clone)]
pub struct CreditSignDemoConfig {
    pub work_dir: PathBuf,
    pub actual_lat: f64,
    pub actual_lon: f64,
}

impl Default for CreditSignDemoConfig {
    fn default() -> Self {
        Self {
            work_dir: PathBuf::from("/tmp/fg-credit-sign-web"),
            actual_lat: 19.4326,
            actual_lon: -99.1332,
        }
    }
}

pub fn run_credit_sign_demo(
    config: &CreditSignDemoConfig,
    mut on_progress: impl FnMut(DemoProgress),
) -> Result<CreditSignDemoArtifacts, HwMidnightError> {
    let started = Instant::now();
    let work_dir = &config.work_dir;

    let mut progress = |phase: DemoPhase, message: &str| {
        on_progress(DemoProgress {
            phase,
            message: message.to_string(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    };

    progress(DemoPhase::Starting, "Starting credit-sign demo");
    std::fs::create_dir_all(work_dir)?;

    progress(DemoPhase::Keygen, "Generating software_poc key (Medium tier)");
    let keygen_start = Instant::now();
    let backend = SoftwarePocBackend::new(work_dir);
    backend.keygen()?;
    let spki = backend.pubkey_spki_der()?;
    let keygen_ms = keygen_start.elapsed().as_millis() as u64;

    progress(DemoPhase::Challenge, "Issuing M_hw");
    let m_hw = MHw::new_challenge(
        HwBackend::SoftwarePoc,
        SecurityTier::Medium,
        &spki,
        Some("fortgate-web-demo".into()),
    )?;

    progress(DemoPhase::SignHandshake, "Signing challenge with hardware PoC");
    let sign_start = Instant::now();
    let handshake = sign_challenge_with_backend(&backend, &m_hw)?;
    let sign_ms = sign_start.elapsed().as_millis() as u64;

    progress(DemoPhase::VerifyLocalCrypto, "Local cryptographic verification");
    let local_crypto_ok = match verify_handshake_local(&handshake)? {
        r if r.status == VerifyStatus::Green => true,
        _ => false,
    };

    let mut h = Sha256::new();
    h.update(b"fortgate-poc-credit-pdf-v1");
    let pdf_sha256 = hex::encode(h.finalize());
    let manifest: CreditSignManifest = demo_manifest(&pdf_sha256);

    progress(DemoPhase::SignDocument, "Signing credit manifest");
    let doc_record = sign_doc_manifest(&backend, &manifest, &handshake.hw_nullifier)?;

    let prover = CreditSignProver::new();
    progress(DemoPhase::SetupKeys, "Loading Midnight verifying keys");
    prover.setup_all_keys()?;

    progress(DemoPhase::ProveHwTrust, "Generating hw-trust-v1 proof (~7 s)");
    let prove_hw_start = Instant::now();
    let hw_pkg = MidnightHwTrustProvider::new().prove_handshake(&handshake)?;
    let prove_hw_ms = prove_hw_start.elapsed().as_millis() as u64;

    progress(DemoPhase::ProveDocBind, "Generating doc-bind-v1 proof (~8 s)");
    let prove_doc_start = Instant::now();
    let doc_pkg = MidnightDocBindProvider::new().prove(&doc_record, &handshake)?;
    let prove_doc_ms = prove_doc_start.elapsed().as_millis() as u64;

    progress(DemoPhase::ProveGeoRange, "Generating geo-range-v1 proof");
    let prove_geo_start = Instant::now();
    let dom = &doc_record.manifest.domicile_ref;
    let geo_pkg = MidnightGeoRangeProvider::new().prove_coords(
        dom.center_lat,
        dom.center_lon,
        config.actual_lat,
        config.actual_lon,
        dom.radius_meters,
    )?;
    let prove_geo_ms = prove_geo_start.elapsed().as_millis() as u64;

    let evidence = CreditSignEvidencePackage {
        package_version: hw_pkg.package_version.clone(),
        hw_trust: hw_pkg,
        doc_bind: doc_pkg,
        geo_range: geo_pkg,
        total_proving_time_ms: prove_hw_ms + prove_doc_ms + prove_geo_ms,
        created_at: crate::types::now_rfc3339(),
    };

    progress(DemoPhase::VerifyProofsLocal, "Verifying 3 proofs locally");
    let verify_start = Instant::now();
    prover.verify_all(&evidence, &handshake, &doc_record)?;
    let verify_local_ms = verify_start.elapsed().as_millis() as u64;

    progress(DemoPhase::BuildVerifyRequest, "Building bank API package");
    let verify_request = build_verify_request(
        evidence.clone(),
        handshake.clone(),
        doc_record.clone(),
        config.actual_lat,
        config.actual_lon,
    );

    write_artifacts(work_dir, &handshake, &doc_record, &evidence, &verify_request)?;

    let timings = DemoTimings {
        keygen_ms,
        sign_ms,
        prove_hw_ms,
        prove_doc_ms,
        prove_geo_ms,
        verify_local_ms,
        total_ms: started.elapsed().as_millis() as u64,
    };

    progress(DemoPhase::Done, "Demo complete");

    Ok(CreditSignDemoArtifacts {
        work_dir: work_dir.display().to_string(),
        backend: handshake.backend.clone(),
        tier: handshake.tier.clone(),
        handshake_json: handshake.to_json_pretty()?,
        doc_bind_record_json: serde_json::to_string_pretty(&doc_record)?,
        evidence_json: serde_json::to_string_pretty(&evidence)?,
        verify_request_json: serde_json::to_string_pretty(&verify_request)?,
        pubkey_commitment: handshake.pubkey_commitment.clone(),
        hw_nullifier: handshake.hw_nullifier.clone(),
        pdf_sha256: doc_record.pdf_sha256.clone(),
        manifest_hash: doc_record.manifest_hash.clone(),
        timings,
        local_crypto_ok,
    })
}

fn write_artifacts(
    work_dir: &Path,
    handshake: &fortgate_id::hw_trust::HwHandshake,
    doc_record: &DocBindRecord,
    evidence: &CreditSignEvidencePackage,
    verify_request: &CreditSignVerifyRequest,
) -> Result<(), HwMidnightError> {
    std::fs::write(work_dir.join("handshake.json"), handshake.to_json_pretty()?)?;
    std::fs::write(
        work_dir.join("doc_bind_record.json"),
        serde_json::to_string_pretty(doc_record)?,
    )?;
    std::fs::write(
        work_dir.join("evidence_package.json"),
        serde_json::to_string_pretty(evidence)?,
    )?;
    std::fs::write(
        work_dir.join("verify_request.json"),
        serde_json::to_string_pretty(verify_request)?,
    )?;
    Ok(())
}
