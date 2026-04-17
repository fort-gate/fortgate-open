use crate::field_encoding::{
    domain_separator_fr, fr_to_canonical_hex, rfc_utf8_to_fr, salt_bytes_to_fr,
};
use light_poseidon::{Poseidon, PoseidonHasher};
use rand::{thread_rng, RngCore};

#[derive(Debug)]
pub struct BlindedWitnessInternal {
    pub rfc_commitment: String,
    pub salt: String,
    pub nullifier_hash: String,
    pub modulus_limbs: [u32; 64],
    pub exponent: u32,
}

pub struct BlindedWitnessGenerator {
    hasher: Poseidon<ark_bn254::Fr>,
}

impl Default for BlindedWitnessGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BlindedWitnessGenerator {
    pub fn new() -> Self {
        let hasher = Poseidon::<ark_bn254::Fr>::new_circom(2).expect("poseidon init");
        Self { hasher }
    }

    /// RFC: UTF-8 → SHA-256 → Fr; salt: 32 bytes → Fr. Debe coincidir con `open/proto/src/main.nr`.
    pub fn generate_package(
        &mut self,
        rfc: &str,
        modulus_limbs: [u32; 64],
        exponent: u32,
    ) -> anyhow::Result<BlindedWitnessInternal> {
        let mut salt_bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut salt_bytes);
        let salt_fr = salt_bytes_to_fr(&salt_bytes);
        let rfc_fr = rfc_utf8_to_fr(rfc);

        let commitment_fr = self.hasher.hash(&[rfc_fr, salt_fr])?;
        let nullifier_fr = self.hasher.hash(&[rfc_fr, domain_separator_fr()])?;

        Ok(BlindedWitnessInternal {
            rfc_commitment: fr_to_canonical_hex(&commitment_fr),
            salt: hex::encode(salt_bytes),
            nullifier_hash: fr_to_canonical_hex(&nullifier_fr),
            modulus_limbs,
            exponent,
        })
    }

    /// Mismo pipeline Poseidon que `main.nr` (hash_2 RFC+salt, hash_2 RFC+dominio). Sin RNG; para tests y vectores versionados.
    pub fn commitment_nullifier_hex(
        rfc: &str,
        salt: &[u8; 32],
    ) -> Result<(String, String), anyhow::Error> {
        let mut hasher = Poseidon::<ark_bn254::Fr>::new_circom(2).expect("poseidon init");
        let rfc_fr = rfc_utf8_to_fr(rfc);
        let salt_fr = salt_bytes_to_fr(salt);
        let commitment_fr = hasher.hash(&[rfc_fr, salt_fr])?;
        let nullifier_fr = hasher.hash(&[rfc_fr, domain_separator_fr()])?;
        Ok((
            fr_to_canonical_hex(&commitment_fr),
            fr_to_canonical_hex(&nullifier_fr),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::field_encoding::rfc_utf8_to_field_bytes;

    #[test]
    fn rfc_field_bytes_stable() {
        let b = rfc_utf8_to_field_bytes("TESTRFC123456789");
        assert_eq!(b.len(), 32);
    }

}
