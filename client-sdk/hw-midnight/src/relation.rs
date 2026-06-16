//! Circuito Midnight `hw-trust-v1`: SHA-256(SPKI) + ECDSA P-256 prehash.

use crate::circuit_util::{assign_public_bytes, verify_ecdsa_p256_prehash};
use crate::types::{HwTrustCircuitInstance, SPKI_LEN};
use midnight_circuits::instructions::{AssertionInstructions, AssignmentInstructions};
use midnight_circuits::types::{AssignedByte, Instantiable};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::{Relation, ZkStdLib, ZkStdLibArch};

type F = midnight_curves::Fq;

/// Firma ECDSA P-256 en formato del circuito (`r` LE, `s` escalar).
#[derive(Clone, Copy, Debug)]
pub struct P256EcdsaSig {
    pub r_le: [u8; 32],
    pub s: midnight_curves::p256::Fq,
}

/// Witness del circuito.
#[derive(Clone, Debug)]
pub struct HwTrustWitness {
    pub spki_der: [u8; SPKI_LEN],
    pub signature: P256EcdsaSig,
    pub pubkey: midnight_curves::p256::P256,
}

#[derive(Clone, Default)]
pub struct HwTrustRelationV1;

impl Relation for HwTrustRelationV1 {
    type Instance = HwTrustCircuitInstance;
    type Witness = HwTrustWitness;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        let mut out = Vec::with_capacity(32 * 4);
        out.extend(
            instance
                .challenge_hash
                .iter()
                .flat_map(AssignedByte::<F>::as_public_input),
        );
        out.extend(
            instance
                .pubkey_commitment
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

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let challenge_hash = instance.map(|i| i.challenge_hash);
        let pubkey_commitment = instance.map(|i| i.pubkey_commitment);
        let hw_nullifier = instance.map(|i| i.hw_nullifier);

        let assigned_challenge = assign_public_bytes(std_lib, layouter, challenge_hash)?;
        let assigned_commitment = assign_public_bytes(std_lib, layouter, pubkey_commitment)?;
        let _assigned_nullifier = assign_public_bytes(std_lib, layouter, hw_nullifier)?;

        let spki = witness.clone().map(|w| w.spki_der);
        let sig = witness.clone().map(|w| w.signature);
        let pk = witness.map(|w| w.pubkey);

        let assigned_spki: Vec<_> =
            std_lib.assign_many(layouter, &spki.transpose_array())?;
        let hash_bytes = std_lib.sha2_256(layouter, &assigned_spki)?;
        for (computed, expected) in hash_bytes.iter().zip(assigned_commitment.iter()) {
            std_lib.assert_equal(layouter, computed, expected)?;
        }

        verify_ecdsa_p256_prehash(
            std_lib,
            layouter,
            pk,
            &assigned_challenge,
            sig,
        )?;

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
