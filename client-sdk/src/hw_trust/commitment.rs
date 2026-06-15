use crate::field_encoding::{fr_to_canonical_hex, salt_bytes_to_fr};
use crate::hw_trust::error::HwTrustError;
use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

/// Dominio hardware "FH" = 0x4648 (distinto del nullifier FG 0x4647).
pub fn hw_domain_separator_fr() -> Fr {
    Fr::from(0x4648u64)
}

pub fn pubkey_commitment_bytes(spki_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(spki_der);
    h.finalize().into()
}

pub fn pubkey_commitment_hex(spki_der: &[u8]) -> String {
    hex::encode(pubkey_commitment_bytes(spki_der))
}

pub fn hw_nullifier_hex(pubkey_commitment: &[u8; 32]) -> Result<String, HwTrustError> {
    let mut hasher = Poseidon::<Fr>::new_circom(2).map_err(|e| HwTrustError::Crypto(e.to_string()))?;
    let pk_fr = salt_bytes_to_fr(pubkey_commitment);
    let nullifier_fr = hasher
        .hash(&[pk_fr, hw_domain_separator_fr()])
        .map_err(|e| HwTrustError::Crypto(e.to_string()))?;
    Ok(fr_to_canonical_hex(&nullifier_fr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_encoding::domain_separator_fr;

    #[test]
    fn hw_nullifier_differs_from_fg_domain() {
        let pk = [7u8; 32];
        let hw = hw_nullifier_hex(&pk).unwrap();
        let fg_sep = domain_separator_fr();
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
        let fg = hasher
            .hash(&[salt_bytes_to_fr(&pk), fg_sep])
            .unwrap();
        assert_ne!(hw, fr_to_canonical_hex(&fg));
    }
}
