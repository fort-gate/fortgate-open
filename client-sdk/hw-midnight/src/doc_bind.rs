//! Circuito Midnight `doc-bind-v1`: bundle_hash + firma ECDSA P-256.
//!
//! El hash JCS del manifiesto se valida off-circuit en verify (PoC v1).

use crate::circuit_util::{assign_public_bytes, hw_signing_material, verify_ecdsa_p256_prehash};
use crate::relation::{HwTrustWitness, P256EcdsaSig};
use midnight_circuits::instructions::AssertionInstructions;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocBindCircuitInstance {
    pub pdf_sha256: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub bundle_hash: [u8; 32],
    pub hw_nullifier: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct DocBindWitness {
    pub hw: HwTrustWitness,
    pub signature: P256EcdsaSig,
}

#[derive(Clone, Default)]
pub struct DocBindRelationV1;

impl Relation for DocBindRelationV1 {
    type Instance = DocBindCircuitInstance;
    type Witness = DocBindWitness;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        assign_public_bytes_format(instance)
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let pdf = instance.map(|i| i.pdf_sha256);
        let manifest_hash = instance.map(|i| i.manifest_hash);
        let bundle_hash = instance.map(|i| i.bundle_hash);
        let hw_nullifier = instance.map(|i| i.hw_nullifier);

        let assigned_pdf = assign_public_bytes(std_lib, layouter, pdf)?;
        let assigned_manifest_hash = assign_public_bytes(std_lib, layouter, manifest_hash)?;
        let assigned_bundle = assign_public_bytes(std_lib, layouter, bundle_hash)?;
        let _assigned_nullifier = assign_public_bytes(std_lib, layouter, hw_nullifier)?;

        let hw_wit = witness.clone().map(|w| w.hw);
        let doc_sig = witness.map(|w| w.signature);

        let mut preimage = assigned_pdf;
        preimage.extend_from_slice(&assigned_manifest_hash);
        let computed_bundle = std_lib.sha2_256(layouter, &preimage)?;
        for (a, b) in computed_bundle.iter().zip(assigned_bundle.iter()) {
            std_lib.assert_equal(layouter, a, b)?;
        }

        let (_spki, pk, _hw_sig) = hw_signing_material(hw_wit);
        verify_ecdsa_p256_prehash(std_lib, layouter, pk, &assigned_bundle, doc_sig)?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            sha2_256: true,
            p256: true,
            nr_pow2range_cols: 3,
            ..ZkStdLibArch::default()
        }
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.used_chips().write(writer)
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let _ = ZkStdLibArch::read(reader)?;
        Ok(Self)
    }
}

fn assign_public_bytes_format(instance: &DocBindCircuitInstance) -> Result<Vec<F>, Error> {
    use midnight_circuits::types::{AssignedByte, Instantiable};
    let mut out = Vec::with_capacity(32 * 4);
    out.extend(
        instance
            .pdf_sha256
            .iter()
            .flat_map(AssignedByte::<F>::as_public_input),
    );
    out.extend(
        instance
            .manifest_hash
            .iter()
            .flat_map(AssignedByte::<F>::as_public_input),
    );
    out.extend(
        instance
            .bundle_hash
            .iter()
            .flat_map(AssignedByte::<F>::as_public_input),
    );
    out.extend(
        instance
            .hw_nullifier
            .iter()
            .flat_map(AssignedByte::<F>::as_public_input),
    );
    Ok(out)
}
