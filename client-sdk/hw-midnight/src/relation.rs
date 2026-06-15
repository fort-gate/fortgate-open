//! Circuito Midnight `hw-trust-v1`: SHA-256(SPKI) + ECDSA P-256 prehash.

use crate::types::{HwTrustCircuitInstance, SPKI_LEN};
use group::Group;
use midnight_circuits::{
    field::foreign::{params::MultiEmulationParams, AssignedField},
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, DecompositionInstructions,
        EccInstructions, PublicInputInstructions,
    },
    types::{AssignedByte, Instantiable},
};
use midnight_curves::p256::{Fq as P256Scalar, P256};
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
    pub s: P256Scalar,
}

/// Witness del circuito.
#[derive(Clone, Debug)]
pub struct HwTrustWitness {
    pub spki_der: [u8; SPKI_LEN],
    pub signature: P256EcdsaSig,
    pub pubkey: P256,
}

#[derive(Clone, Default)]
pub struct HwTrustRelationV1;

impl Relation for HwTrustRelationV1 {
    type Instance = HwTrustCircuitInstance;
    type Witness = HwTrustWitness;
    type Error = Error;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        let mut out = Vec::with_capacity(32 * 3 + 1);
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

        let assigned_challenge: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &challenge_hash.transpose_array())?;
        assigned_challenge
            .iter()
            .try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))?;

        let assigned_commitment: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &pubkey_commitment.transpose_array())?;
        assigned_commitment
            .iter()
            .try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))?;

        let assigned_nullifier: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &hw_nullifier.transpose_array())?;
        assigned_nullifier
            .iter()
            .try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))?;

        let spki = witness.clone().map(|w| w.spki_der);
        let sig = witness.clone().map(|w| w.signature);
        let pk = witness.map(|w| w.pubkey);

        let assigned_spki: Vec<AssignedByte<F>> =
            std_lib.assign_many(layouter, &spki.transpose_array())?;
        let hash_bytes = std_lib.sha2_256(layouter, &assigned_spki)?;
        for (computed, expected) in hash_bytes.iter().zip(assigned_commitment.iter()) {
            std_lib.assert_equal(layouter, computed, expected)?;
        }

        Self::verify_ecdsa_p256_prehash(
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

impl HwTrustRelationV1 {
    /// ECDSA P-256 sobre `challenge_hash` ya hasheado (prehash / IEEE P1363).
    fn verify_ecdsa_p256_prehash(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        pk: Value<P256>,
        challenge_hash: &[AssignedByte<F>],
        sig: Value<P256EcdsaSig>,
    ) -> Result<(), Error> {
        let curve = std_lib.p256();
        let scalar_chip = curve.scalar_field_chip();
        let base_chip = curve.base_field_chip();

        let pk_point = curve.assign(layouter, pk)?;

        let msg_hash: AssignedField<_, P256Scalar, MultiEmulationParams> =
            scalar_chip.assigned_from_be_bytes(layouter, challenge_hash)?;

        let r_value = sig.map(|s| s.r_le);
        let r_le_bytes = std_lib.assign_many(layouter, &r_value.transpose_array())?;
        let s = scalar_chip.assign(layouter, sig.map(|s| s.s))?;

        let r_as_scalar = scalar_chip.assigned_from_le_bytes(layouter, &r_le_bytes)?;
        let r_as_base = base_chip.assigned_from_le_bytes(layouter, &r_le_bytes)?;

        let r_over_s = scalar_chip.div(layouter, &r_as_scalar, &s)?;
        let m_over_s = scalar_chip.div(layouter, &msg_hash, &s)?;

        let gen = curve.assign_fixed(layouter, P256::generator())?;
        let lhs = curve.msm(layouter, &[m_over_s, r_over_s], &[gen, pk_point])?;
        let lhs_x = curve.x_coordinate(&lhs);

        base_chip.assert_equal(layouter, &lhs_x, &r_as_base)
    }
}
