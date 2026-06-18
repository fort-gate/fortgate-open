//! Midnight ZK para hardware trust y firma de crédito PoC.
//!
//! Circuitos: `hw-trust-v1`, `doc-bind-v1`, `geo-range-v1`.
//!
//! **Disclaimer:** `midnight-zk-stdlib` no está auditado para producción.
//! El nullifier Poseidon BN254 (dominio `0x4648`) se valida off-circuit hasta
//! alinear chips Poseidon con `field_encoding.rs`.

mod api_types;
mod circuit_util;
mod demo_runner;
mod doc_bind;
mod doc_bind_provider;
mod error;
mod geo;
mod geo_range;
mod geo_range_provider;
mod manifest;
mod midnight_provider;
mod orchestrator;
mod provider;
mod relation;
mod srs;
mod types;
mod verifier;
mod witness;

pub use api_types::{
    build_verify_request, device_evidence_from_handshake, seal_geo_archive_poc,
    CheckStatus, CreditSignVerifyRequest, DeviceEvidence, IdentityMock, PublicSummary,
    SealedGeoArchive, VerifyChecks, VerifyErrorCode, VerifyErrorResponse, VerifyResponse,
    VerifyStatus, VerifySuccessResponse,
};

pub use demo_runner::{
    run_credit_sign_demo, CreditSignDemoArtifacts, CreditSignDemoConfig, DemoPhase, DemoProgress,
    DemoTimings,
};
pub use doc_bind::{DocBindCircuitInstance, DocBindRelationV1, DocBindWitness};
pub use doc_bind_provider::{DocBindRecord, MidnightDocBindProvider};
pub use error::HwMidnightError;
pub use geo::{deg_to_e6, haversine_meters, validate_inside_range, MAX_RADIUS_METERS};
pub use geo_range::{GeoRangeCircuitInstance, GeoRangeRelationV1, GeoRangeWitness};
pub use geo_range_provider::MidnightGeoRangeProvider;
pub use manifest::{bundle_hash_bytes, CreditSignManifest, DomicileRef, MANIFEST_VERSION};
pub use midnight_provider::MidnightCircuitProvider;
pub use orchestrator::{demo_manifest, sign_doc_manifest, CreditSignProver};
pub use provider::MidnightHwTrustProvider;
pub use relation::{HwTrustRelationV1, HwTrustWitness, P256EcdsaSig};
pub use verifier::{CreditSignVerifier, InstitutionPolicy};
pub use types::{
    CreditSignEvidencePackage, DocBindPublicInputs, DocProofPackage, GeoProofPackage,
    GeoRangePublicInputs, HwProofPackage, HwTrustCircuitInstance, HwTrustPublicInputs,
    CIRCUIT_VERSION, DOC_CIRCUIT_VERSION, GEO_CIRCUIT_VERSION, HW_CIRCUIT_VERSION, PACKAGE_VERSION,
    PROOF_PROVIDER_ID, SPKI_LEN,
};
pub use witness::{public_inputs_from_handshake, witness_from_handshake};
