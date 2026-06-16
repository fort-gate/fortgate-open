//! Orquestador: hw-trust + doc-bind + geo-range.

use crate::doc_bind_provider::{DocBindRecord, MidnightDocBindProvider};
use crate::error::HwMidnightError;
use crate::geo_range_provider::MidnightGeoRangeProvider;
use crate::manifest::{CreditSignManifest, DomicileRef};
use crate::provider::MidnightHwTrustProvider;
use crate::types::{CreditSignEvidencePackage, PACKAGE_VERSION, now_rfc3339};
use fortgate_id::hw_trust::backends::software_poc::SoftwarePocBackend;
use fortgate_id::hw_trust::HwHandshake;
use std::path::Path;
use std::time::Instant;

pub struct CreditSignProver {
    hw: MidnightHwTrustProvider,
    doc: MidnightDocBindProvider,
    geo: MidnightGeoRangeProvider,
}

impl Default for CreditSignProver {
    fn default() -> Self {
        Self {
            hw: MidnightHwTrustProvider::new(),
            doc: MidnightDocBindProvider::new(),
            geo: MidnightGeoRangeProvider::new(),
        }
    }
}

impl CreditSignProver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn setup_all_keys(&self) -> Result<(), HwMidnightError> {
        self.hw.setup_keys()?;
        self.doc.setup_keys()?;
        self.geo.setup_keys()?;
        Ok(())
    }

    pub fn prove_all(
        &self,
        handshake: &HwHandshake,
        doc_record: &DocBindRecord,
        actual_lat: f64,
        actual_lon: f64,
    ) -> Result<CreditSignEvidencePackage, HwMidnightError> {
        let start = Instant::now();

        let hw_trust = self.hw.prove_handshake(handshake)?;
        let doc_bind = self.doc.prove(doc_record, handshake)?;
        let dom = &doc_record.manifest.domicile_ref;
        let geo_range = self.geo.prove_coords(
            dom.center_lat,
            dom.center_lon,
            actual_lat,
            actual_lon,
            dom.radius_meters,
        )?;

        Ok(CreditSignEvidencePackage {
            package_version: PACKAGE_VERSION.to_string(),
            hw_trust,
            doc_bind,
            geo_range,
            total_proving_time_ms: start.elapsed().as_millis() as u64,
            created_at: now_rfc3339(),
        })
    }

    pub fn verify_all(
        &self,
        evidence: &CreditSignEvidencePackage,
        handshake: &HwHandshake,
        doc_record: &DocBindRecord,
    ) -> Result<(), HwMidnightError> {
        self.hw.verify_against_handshake(&evidence.hw_trust, handshake)?;
        self.doc.verify(&evidence.doc_bind, doc_record)?;
        self.geo.verify(&evidence.geo_range)?;
        Ok(())
    }

    pub fn write_evidence(
        path: &Path,
        evidence: &CreditSignEvidencePackage,
    ) -> Result<(), HwMidnightError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(evidence)?)?;
        Ok(())
    }

    pub fn read_evidence(path: &Path) -> Result<CreditSignEvidencePackage, HwMidnightError> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

pub fn sign_doc_manifest(
    backend: &SoftwarePocBackend,
    manifest: &CreditSignManifest,
    hw_nullifier: &str,
) -> Result<DocBindRecord, HwMidnightError> {
    MidnightDocBindProvider::sign_manifest(backend, manifest, hw_nullifier)
}

pub fn demo_manifest(pdf_sha256: &str) -> CreditSignManifest {
    let domicile = DomicileRef {
        center_lat: 19.4320,
        center_lon: -99.1330,
        radius_meters: 200,
        label: Some("CDMX PoC".into()),
    };
    CreditSignManifest::demo_pyme("app-poc-001", pdf_sha256, domicile)
}
