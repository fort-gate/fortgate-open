use crate::error::HwMidnightError;
use crate::key_cache::{key_or_init, KeyKind};
use crate::relation::HwTrustRelationV1;
use crate::srs::{ensure_parent, load_srs_for_relation, pk_path, vk_path, VK_SERDE};
use crate::types::{
    HwProofPackage, HwTrustCircuitInstance, HwTrustPublicInputs, PACKAGE_VERSION, PROOF_PROVIDER_ID,
    CIRCUIT_VERSION,
};
use crate::witness::{public_inputs_from_handshake, witness_from_handshake};
use fortgate_id::hw_trust::HwHandshake;
use midnight_zk_stdlib::{prove, verify, MidnightPK, MidnightVK};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub struct MidnightHwTrustProvider {
    relation: HwTrustRelationV1,
}

impl Default for MidnightHwTrustProvider {
    fn default() -> Self {
        Self {
            relation: HwTrustRelationV1,
        }
    }
}

impl MidnightHwTrustProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn relation(&self) -> &HwTrustRelationV1 {
        &self.relation
    }

    /// Genera vk/pk y los persiste en `hw-midnight/vkeys/` (trusted setup dev).
    pub fn setup_keys(&self) -> Result<(), HwMidnightError> {
        crate::key_cache::invalidate_circuit(CIRCUIT_VERSION);
        let srs = load_srs_for_relation(&self.relation)?;
        let vk = midnight_zk_stdlib::setup_vk(&srs, &self.relation);
        let pk = midnight_zk_stdlib::setup_pk(&self.relation, &vk);

        ensure_parent(&vk_path())?;
        ensure_parent(&pk_path())?;

        let mut vk_file = BufWriter::new(File::create(vk_path())?);
        vk.write(&mut vk_file, VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(e.to_string()))?;

        let mut pk_file = BufWriter::new(File::create(pk_path())?);
        pk.write(&mut pk_file, VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(e.to_string()))?;

        Ok(())
    }

    /// Circuit verifying key, read from disk once per process.
    pub fn load_vk(&self) -> Result<Arc<MidnightVK>, HwMidnightError> {
        key_or_init(CIRCUIT_VERSION, KeyKind::Verifying, || {
            let path = vk_path();
            if !path.exists() {
                self.setup_keys()?;
            }
            let f = File::open(path)?;
            MidnightVK::read(&mut BufReader::new(f), VK_SERDE)
                .map_err(|e| HwMidnightError::Prove(format!("leer vk: {e}")))
        })
    }

    /// Circuit proving key, read from disk once per process.
    pub fn load_pk(&self) -> Result<Arc<MidnightPK<HwTrustRelationV1>>, HwMidnightError> {
        key_or_init(CIRCUIT_VERSION, KeyKind::Proving, || {
            let path = pk_path();
            if !path.exists() {
                self.setup_keys()?;
            }
            let f = File::open(path)?;
            MidnightPK::read(&mut BufReader::new(f), VK_SERDE)
                .map_err(|e| HwMidnightError::Prove(format!("leer pk: {e}")))
        })
    }

    pub fn prove_handshake(&self, hs: &HwHandshake) -> Result<HwProofPackage, HwMidnightError> {
        let public_inputs = public_inputs_from_handshake(hs)?;
        let witness = witness_from_handshake(hs)?;
        self.prove(&public_inputs, witness)
    }

    pub fn prove(
        &self,
        public_inputs: &HwTrustPublicInputs,
        witness: crate::relation::HwTrustWitness,
    ) -> Result<HwProofPackage, HwMidnightError> {
        let circuit_instance = HwTrustCircuitInstance {
            challenge_hash: public_inputs.challenge_hash,
            pubkey_commitment: public_inputs.pubkey_commitment,
            hw_nullifier: public_inputs.hw_nullifier,
        };
        let srs = load_srs_for_relation(&self.relation)?;
        let pk = self.load_pk()?;

        let start = Instant::now();
        let proof = prove::<HwTrustRelationV1, blake2b_simd::State>(
            &srs,
            &pk,
            &self.relation,
            &circuit_instance,
            witness,
            OsRng,
        )
        .map_err(|e| HwMidnightError::Prove(e.to_string()))?;
        let proving_time_ms = start.elapsed().as_millis() as u64;

        Ok(HwProofPackage {
            package_version: PACKAGE_VERSION.to_string(),
            proof_provider_id: PROOF_PROVIDER_ID.to_string(),
            circuit_version: CIRCUIT_VERSION.to_string(),
            public_inputs: *public_inputs,
            proof_bytes: proof,
            verifying_key_ref: "vkeys/hw-trust-v1.vk".to_string(),
            proving_time_ms,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    }

    pub fn verify_package(&self, package: &HwProofPackage) -> Result<(), HwMidnightError> {
        if package.circuit_version != CIRCUIT_VERSION {
            return Err(HwMidnightError::Verify(format!(
                "circuit_version esperado {CIRCUIT_VERSION}, got {}",
                package.circuit_version
            )));
        }
        let srs = load_srs_for_relation(&self.relation)?;
        let vk = self.load_vk()?;
        let circuit_instance = HwTrustCircuitInstance {
            challenge_hash: package.public_inputs.challenge_hash,
            pubkey_commitment: package.public_inputs.pubkey_commitment,
            hw_nullifier: package.public_inputs.hw_nullifier,
        };
        verify::<HwTrustRelationV1, blake2b_simd::State>(
            &srs.verifier_params(),
            &vk,
            &circuit_instance,
            None,
            &package.proof_bytes,
        )
        .map_err(|e| HwMidnightError::Verify(e.to_string()))
    }

    pub fn verify_against_handshake(
        &self,
        package: &HwProofPackage,
        hs: &HwHandshake,
    ) -> Result<(), HwMidnightError> {
        let expected = public_inputs_from_handshake(hs)?;
        if package.public_inputs != expected {
            return Err(HwMidnightError::Verify(
                "public_inputs no coinciden con handshake".into(),
            ));
        }
        self.verify_nullifier_binding(hs)?;
        self.verify_package(package)
    }

    /// Poseidon BN254 (`hw_nullifier`) se valida off-circuit (dominio FH 0x4648).
    fn verify_nullifier_binding(&self, hs: &HwHandshake) -> Result<(), HwMidnightError> {
        let spki = hex::decode(hs.pubkey_spki_der.trim())
            .map_err(|e| HwMidnightError::Hex(e.to_string()))?;
        let expected =
            fortgate_id::hw_trust::hw_nullifier_hex(&fortgate_id::hw_trust::pubkey_commitment_bytes(
                &spki,
            ))
            .map_err(|e| HwMidnightError::Verify(e.to_string()))?;
        if expected != hs.hw_nullifier {
            return Err(HwMidnightError::Verify("hw_nullifier no coincide".into()));
        }
        Ok(())
    }

    pub fn write_package(path: &Path, package: &HwProofPackage) -> Result<(), HwMidnightError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(package)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn read_package(path: &Path) -> Result<HwProofPackage, HwMidnightError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
}
