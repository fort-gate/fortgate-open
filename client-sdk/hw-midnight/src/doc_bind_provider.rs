//! Registro de firma documental y construcción de witness.

use crate::doc_bind::{DocBindCircuitInstance, DocBindRelationV1, DocBindWitness};
use crate::error::HwMidnightError;
use crate::manifest::{
    bundle_hash_bytes, hex_fixed32, manifest_hash_bytes, manifest_jcs_bytes,
    CreditSignManifest,
};
use crate::midnight_provider::MidnightCircuitProvider;
use crate::types::{
    DocBindPublicInputs, DocProofPackage, DOC_CIRCUIT_VERSION, PACKAGE_VERSION, PROOF_PROVIDER_ID,
    now_rfc3339,
};
use crate::witness::witness_from_handshake;
use fortgate_id::hw_trust::backends::{software_poc::SoftwarePocBackend, HwTrustBackend};
use fortgate_id::hw_trust::HwHandshake;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocBindRecord {
    pub package_version: String,
    pub manifest: CreditSignManifest,
    pub manifest_hash: String,
    pub pdf_sha256: String,
    pub bundle_hash: String,
    pub signature_der: String,
    pub hw_nullifier: String,
    pub pubkey_spki_der: String,
}

pub struct MidnightDocBindProvider {
    inner: MidnightCircuitProvider<DocBindRelationV1>,
}

impl Default for MidnightDocBindProvider {
    fn default() -> Self {
        Self {
            inner: MidnightCircuitProvider::new(DocBindRelationV1, DOC_CIRCUIT_VERSION),
        }
    }
}

impl MidnightDocBindProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn setup_keys(&self) -> Result<(), HwMidnightError> {
        self.inner.setup_keys()
    }

    pub fn sign_manifest(
        backend: &SoftwarePocBackend,
        manifest: &CreditSignManifest,
        hw_nullifier: &str,
    ) -> Result<DocBindRecord, HwMidnightError> {
        let jcs = manifest_jcs_bytes(manifest)?;
        let m_hash = manifest_hash_bytes(&jcs);
        let pdf = hex_fixed32(&manifest.pdf_sha256)?;
        let bundle = bundle_hash_bytes(&pdf, &m_hash);

        let sig_der = backend
            .sign_challenge_hash(&bundle)
            .map_err(|e| HwMidnightError::Doc(e.to_string()))?;
        let spki = backend.pubkey_spki_der().map_err(|e| HwMidnightError::Doc(e.to_string()))?;

        Ok(DocBindRecord {
            package_version: PACKAGE_VERSION.to_string(),
            manifest: manifest.clone(),
            manifest_hash: hex::encode(m_hash),
            pdf_sha256: manifest.pdf_sha256.clone(),
            bundle_hash: hex::encode(bundle),
            signature_der: hex::encode(sig_der),
            hw_nullifier: hw_nullifier.to_string(),
            pubkey_spki_der: hex::encode(spki),
        })
    }

    pub fn prove(
        &self,
        record: &DocBindRecord,
        handshake: &HwHandshake,
    ) -> Result<DocProofPackage, HwMidnightError> {
        let jcs = manifest_jcs_bytes(&record.manifest)?;
        let pdf = hex_fixed32(&record.pdf_sha256)?;
        let manifest_hash = hex_fixed32(&record.manifest_hash)?;
        let recomputed_hash = manifest_hash_bytes(&jcs);
        if recomputed_hash != manifest_hash {
            return Err(HwMidnightError::Doc("manifest_hash no coincide con JCS".into()));
        }
        let hw_wit = witness_from_handshake(handshake)?;

        let bundle = hex_fixed32(&record.bundle_hash)?;
        let hw_nullifier = hex_fixed32(&record.hw_nullifier)?;

        let sig_der = hex::decode(record.signature_der.trim())
            .map_err(|e| HwMidnightError::Hex(e.to_string()))?;
        let signature = crate::witness::p256_ecdsa_sig_from_der(&sig_der)?;

        let public_inputs = DocBindPublicInputs {
            pdf_sha256: pdf,
            manifest_hash,
            bundle_hash: bundle,
            hw_nullifier,
        };

        if record.hw_nullifier != handshake.hw_nullifier {
            return Err(HwMidnightError::Doc(
                "hw_nullifier no coincide con handshake".into(),
            ));
        }

        let instance = DocBindCircuitInstance {
            pdf_sha256: pdf,
            manifest_hash,
            bundle_hash: bundle,
            hw_nullifier,
        };
        let witness = DocBindWitness {
            hw: hw_wit,
            signature,
        };

        let (proof_bytes, proving_time_ms) = self.inner.prove(&instance, witness)?;

        Ok(DocProofPackage {
            package_version: PACKAGE_VERSION.to_string(),
            proof_provider_id: PROOF_PROVIDER_ID.to_string(),
            circuit_version: DOC_CIRCUIT_VERSION.to_string(),
            public_inputs,
            proof_bytes,
            verifying_key_ref: self.inner.verifying_key_ref(),
            proving_time_ms,
            created_at: now_rfc3339(),
        })
    }

    pub fn verify(&self, package: &DocProofPackage, record: &DocBindRecord) -> Result<(), HwMidnightError> {
        if package.circuit_version != DOC_CIRCUIT_VERSION {
            return Err(HwMidnightError::Verify("circuit_version doc-bind mismatch".into()));
        }
        let expected = DocBindPublicInputs {
            pdf_sha256: hex_fixed32(&record.pdf_sha256)?,
            manifest_hash: hex_fixed32(&record.manifest_hash)?,
            bundle_hash: hex_fixed32(&record.bundle_hash)?,
            hw_nullifier: hex_fixed32(&record.hw_nullifier)?,
        };
        if package.public_inputs != expected {
            return Err(HwMidnightError::Verify("public_inputs doc no coinciden".into()));
        }
        let jcs = manifest_jcs_bytes(&record.manifest)?;
        if manifest_hash_bytes(&jcs) != expected.manifest_hash {
            return Err(HwMidnightError::Verify(
                "manifest_hash off-circuit no coincide".into(),
            ));
        }
        let instance = DocBindCircuitInstance {
            pdf_sha256: expected.pdf_sha256,
            manifest_hash: expected.manifest_hash,
            bundle_hash: expected.bundle_hash,
            hw_nullifier: expected.hw_nullifier,
        };
        self.inner.verify(&instance, &package.proof_bytes)
    }

    pub fn write_package(path: &std::path::Path, package: &DocProofPackage) -> Result<(), HwMidnightError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(package)?)?;
        Ok(())
    }

    pub fn read_package(path: &std::path::Path) -> Result<DocProofPackage, HwMidnightError> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}
