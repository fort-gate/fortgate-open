//! Utilidades compartidas entre circuitos Midnight.

use crate::relation::{HwTrustWitness, P256EcdsaSig};
use group::Group;
use midnight_circuits::{
    field::foreign::{params::MultiEmulationParams, AssignedField},
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, DecompositionInstructions,
        EccInstructions, PublicInputInstructions,
    },
    types::{AssignedByte, AssignedNative},
};
use midnight_curves::p256::{Fq as P256Scalar, P256};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib::ZkStdLib;

type F = midnight_curves::Fq;

pub fn assign_public_bytes<const N: usize>(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    bytes: Value<[u8; N]>,
) -> Result<Vec<AssignedByte<F>>, Error> {
    let assigned: Vec<AssignedByte<F>> = std_lib.assign_many(layouter, &bytes.transpose_array())?;
    assigned
        .iter()
        .try_for_each(|b| std_lib.constrain_as_public_input(layouter, b))?;
    Ok(assigned)
}

pub fn assign_public_scalar(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    value: Value<F>,
) -> Result<AssignedNative<F>, Error> {
    let assigned = std_lib.assign(layouter, value)?;
    std_lib.constrain_as_public_input(layouter, &assigned)?;
    Ok(assigned)
}

pub fn verify_ecdsa_p256_prehash(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    pk: Value<P256>,
    prehash: &[AssignedByte<F>],
    sig: Value<P256EcdsaSig>,
) -> Result<(), Error> {
    let curve = std_lib.p256();
    let scalar_chip = curve.scalar_field_chip();
    let base_chip = curve.base_field_chip();

    let pk_point = curve.assign(layouter, pk)?;

    let msg_hash: AssignedField<_, P256Scalar, MultiEmulationParams> =
        scalar_chip.assigned_from_be_bytes(layouter, prehash)?;

    let r_value = sig.map(|s| s.r_le);
    let r_le_bytes = std_lib.assign_many(layouter, &r_value.transpose_array())?;
    let s = scalar_chip.assign(layouter, sig.map(|s| s.s))?;

    let r_as_scalar = scalar_chip.assigned_from_le_bytes(layouter, &r_le_bytes)?;
    let r_as_base = base_chip.assigned_from_le_bytes(layouter, &r_le_bytes)?;

    // A single inversion of `s` instead of two divisions. `div(x, s)` is internally an
    // inversion plus a multiplication, so doing it twice over the same divisor inverts
    // `s` twice in the foreign field, which is the expensive operation.
    //
    // Soundness: algebraically identical, `x/s == x * s^{-1}`. This uses `inv` and not
    // `inv0`, so `s = 0` still leaves the circuit unsatisfiable, just as `div` did.
    let s_inv = scalar_chip.inv(layouter, &s)?;
    let r_over_s = scalar_chip.mul(layouter, &r_as_scalar, &s_inv, None)?;
    let m_over_s = scalar_chip.mul(layouter, &msg_hash, &s_inv, None)?;

    let gen = curve.assign_fixed(layouter, P256::generator())?;
    let lhs = curve.msm(layouter, &[m_over_s, r_over_s], &[gen, pk_point])?;
    let lhs_x = curve.x_coordinate(&lhs);

    base_chip.assert_equal(layouter, &lhs_x, &r_as_base)
}

pub fn hw_signing_material(
    witness: Value<HwTrustWitness>,
) -> (Value<[u8; crate::types::SPKI_LEN]>, Value<P256>, Value<P256EcdsaSig>) {
    let spki = witness.clone().map(|w| w.spki_der);
    let sig = witness.clone().map(|w| w.signature);
    let pk = witness.map(|w| w.pubkey);
    (spki, pk, sig)
}
