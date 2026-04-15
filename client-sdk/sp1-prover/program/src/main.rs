#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::{RsaPublicKey, PaddingScheme, PublicKey};
use sha2::Sha256;
use num_bigint::BigUint;

pub fn main() {
    // 1. LEER INPUTS (Proporcionados por el Host)
    let modulus_limbs: [u32; 64] = sp1_zkvm::io::read();
    let signature_limbs: [u32; 64] = sp1_zkvm::io::read();
    let hashed_message: [u8; 32] = sp1_zkvm::io::read();
    let rfc_commitment: [u8; 32] = sp1_zkvm::io::read();

    // 2. RECONSTRUIR RSA DESDE LIMBS (Little Endian as per SDK)
    let n = limbs_to_bigint(modulus_limbs);
    let s = limbs_to_bigint(signature_limbs);
    
    // 3. VERIFICACIÓN CRIPTOGRÁFICA
    let pub_key = RsaPublicKey::new(n, BigUint::from(65537u32))
        .expect("Invalid RSA Modulus");
    
    pub_key.verify(
        PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
        &hashed_message,
        &s.to_bytes_be()
    ).expect("RSA Verification Failed");

    // 4. ATATESTACIÓN DE RESULTADO
    sp1_zkvm::io::commit(&rfc_commitment);
}

/// Helper para convertir los limbs de 32-bits de vuelta a un BigInt de 2048-bits
fn limbs_to_bigint(limbs: [u32; 64]) -> BigUint {
    let mut digits = Vec::with_capacity(64);
    for limb in limbs.iter() {
        digits.push(*limb);
    }
    BigUint::from_slice(&digits)
}
