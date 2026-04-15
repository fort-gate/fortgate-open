use sha2::{Sha256, Digest};
use crate::types::BlindedWitness;

pub fn generate_blinded_witness(cert_data: &[u8], randomness: [u8; 32]) -> BlindedWitness {
    let mut hasher = Sha256::new();
    hasher.update(cert_data);
    hasher.update(randomness);
    let hash = hasher.finalize();

    let mut blinded_hash = [0u8; 32];
    blinded_hash.copy_from_slice(&hash);

    BlindedWitness {
        blinded_hash,
        cert_data: cert_data.to_vec(),
        randomness,
    }
}
