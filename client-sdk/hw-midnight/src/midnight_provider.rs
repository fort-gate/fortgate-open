use crate::error::HwMidnightError;
use midnight_zk_stdlib::{prove, verify, MidnightPK, MidnightVK, Relation};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::time::Instant;

use crate::srs::{ensure_parent, load_srs_for_relation, vkeys_dir, VK_SERDE};

pub struct MidnightCircuitProvider<R> {
    relation: R,
    circuit_id: &'static str,
}

impl<R> MidnightCircuitProvider<R>
where
    R: Relation + Clone + Default,
    <R as Relation>::Error: std::fmt::Debug,
{
    pub fn new(relation: R, circuit_id: &'static str) -> Self {
        Self {
            relation,
            circuit_id,
        }
    }

    pub fn relation(&self) -> &R {
        &self.relation
    }

    pub fn circuit_id(&self) -> &'static str {
        self.circuit_id
    }

    fn vk_path(&self) -> PathBuf {
        vkeys_dir().join(format!("{}.vk", self.circuit_id))
    }

    fn pk_path(&self) -> PathBuf {
        vkeys_dir().join(format!("{}.pk", self.circuit_id))
    }

    pub fn setup_keys(&self) -> Result<(), HwMidnightError> {
        let srs = load_srs_for_relation(&self.relation)?;
        let vk = midnight_zk_stdlib::setup_vk(&srs, &self.relation);
        let pk = midnight_zk_stdlib::setup_pk(&self.relation, &vk);

        ensure_parent(&self.vk_path())?;
        ensure_parent(&self.pk_path())?;

        let mut vk_file = BufWriter::new(File::create(self.vk_path())?);
        vk.write(&mut vk_file, VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(format!("{e:?}")))?;

        let mut pk_file = BufWriter::new(File::create(self.pk_path())?);
        pk.write(&mut pk_file, VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(format!("{e:?}")))?;

        Ok(())
    }

    pub fn load_vk(&self) -> Result<MidnightVK, HwMidnightError> {
        let path = self.vk_path();
        if !path.exists() {
            self.setup_keys()?;
        }
        let f = File::open(path)?;
        MidnightVK::read(&mut BufReader::new(f), VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(format!("leer vk: {e}")))
    }

    pub fn load_pk(&self) -> Result<MidnightPK<R>, HwMidnightError> {
        let path = self.pk_path();
        if !path.exists() {
            self.setup_keys()?;
        }
        let f = File::open(path)?;
        MidnightPK::read(&mut BufReader::new(f), VK_SERDE)
            .map_err(|e| HwMidnightError::Prove(format!("leer pk: {e}")))
    }

    pub fn prove(
        &self,
        instance: &R::Instance,
        witness: R::Witness,
    ) -> Result<(Vec<u8>, u64), HwMidnightError> {
        let srs = load_srs_for_relation(&self.relation)?;
        let pk = self.load_pk()?;
        let start = Instant::now();
        let proof = prove::<R, blake2b_simd::State>(
            &srs,
            &pk,
            &self.relation,
            instance,
            witness,
            OsRng,
        )
        .map_err(|e| HwMidnightError::Prove(format!("{e:?}")))?;
        Ok((proof, start.elapsed().as_millis() as u64))
    }

    pub fn verify(
        &self,
        instance: &R::Instance,
        proof_bytes: &[u8],
    ) -> Result<(), HwMidnightError> {
        let srs = load_srs_for_relation(&self.relation)?;
        let vk = self.load_vk()?;
        verify::<R, blake2b_simd::State>(
            &srs.verifier_params(),
            &vk,
            instance,
            None,
            proof_bytes,
        )
        .map_err(|e| HwMidnightError::Verify(format!("{e:?}")))
    }

    pub fn verifying_key_ref(&self) -> String {
        format!("vkeys/{}.vk", self.circuit_id)
    }
}
