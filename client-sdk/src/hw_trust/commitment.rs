use crate::hw_trust::error::HwTrustError;
use midnight_circuits::hash::poseidon::PoseidonChip;
use midnight_circuits::instructions::hash::HashCPU;
use midnight_curves::Fq as MidnightScalar;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Dominio hardware "FH" = 0x4648 (distinto del nullifier de identidad FG 0x4647
/// en `field_encoding::domain_separator_fr`, que sigue sobre BN254 y no cambia).
pub const HW_NULLIFIER_DOMAIN: u64 = 0x4648;

/// Orden del campo escalar BLS12-381 (campo nativo del circuito Midnight),
/// big-endian. r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const BLS12_381_SCALAR_MODULUS_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

pub fn hw_domain_separator() -> MidnightScalar {
    MidnightScalar::from(HW_NULLIFIER_DOMAIN)
}

pub fn pubkey_commitment_bytes(spki_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(spki_der);
    h.finalize().into()
}

pub fn pubkey_commitment_hex(spki_der: &[u8]) -> String {
    hex::encode(pubkey_commitment_bytes(spki_der))
}

/// Reduce 32 bytes big-endian mod el orden del campo escalar BLS12-381. Debe
/// coincidir EXACTAMENTE con lo que hace el circuito: `assigned_from_be_bytes`
/// interpreta los bytes como una suma posicional `sum_i 256^i * byte_i`
/// evaluada en aritmética nativa (mod r), es decir, la misma reducción.
fn be_bytes_to_midnight_scalar(bytes: &[u8; 32]) -> MidnightScalar {
    let modulus = BigUint::from_bytes_be(&BLS12_381_SCALAR_MODULUS_BE);
    let value = BigUint::from_bytes_be(bytes) % modulus;
    let reduced = value.to_bytes_be();
    let mut be32 = [0u8; 32];
    be32[32 - reduced.len()..].copy_from_slice(&reduced);
    Option::from(MidnightScalar::from_bytes_be(&be32))
        .expect("reduced value is < modulus by construction, must be canonical")
}

/// `hw_nullifier = Poseidon_2(pubkey_commitment mod r, 0x4648)` sobre el campo
/// nativo del circuito Midnight (BLS12-381 Fr) usando `PoseidonChip`, la MISMA
/// función que `std_lib.poseidon()` usa on-circuit en `HwTrustRelationV1`.
pub fn hw_nullifier_hex(pubkey_commitment: &[u8; 32]) -> Result<String, HwTrustError> {
    let pk_scalar = be_bytes_to_midnight_scalar(pubkey_commitment);
    let nullifier = PoseidonChip::<MidnightScalar>::hash(&[pk_scalar, hw_domain_separator()]);
    Ok(hex::encode(nullifier.to_bytes_be()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_nullifier_differs_from_fg_domain() {
        let pk = [7u8; 32];
        let hw = hw_nullifier_hex(&pk).unwrap();
        let pk_scalar = be_bytes_to_midnight_scalar(&pk);
        let fg = PoseidonChip::<MidnightScalar>::hash(&[pk_scalar, MidnightScalar::from(0x4647u64)]);
        assert_ne!(hw, hex::encode(fg.to_bytes_be()));
    }
}
