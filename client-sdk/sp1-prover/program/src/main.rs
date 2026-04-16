#![no_main]
sp1_zkvm::entrypoint!(main);

use fortgate_sp1_shared::Limbs64;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::BigUint;
use rsa::RsaPublicKey;
use rsa::sha2::Sha256;

pub fn main() {
    let Limbs64(modulus_limbs) = sp1_zkvm::io::read();
    let exponent: u32 = sp1_zkvm::io::read();
    let Limbs64(signature_limbs) = sp1_zkvm::io::read();
    let hashed_message: [u8; 32] = sp1_zkvm::io::read();
    let rfc_commitment: [u8; 32] = sp1_zkvm::io::read();

    let n = limbs_to_biguint(modulus_limbs);
    let e = BigUint::from(exponent);
    let pub_key = RsaPublicKey::new(n, e).expect("Invalid RSA public key");

    let verifying_key = VerifyingKey::<Sha256>::new(pub_key);
    let sig_int = limbs_to_biguint(signature_limbs);
    let sig_bytes = sig_int.to_bytes_be();
    let sig = Signature::try_from(sig_bytes.as_slice()).expect("invalid signature encoding");

    verifying_key
        .verify_prehash(&hashed_message, &sig)
        .expect("RSA verification failed");

    sp1_zkvm::io::commit(&rfc_commitment);
}

fn limbs_to_biguint(limbs: [u32; 64]) -> BigUint {
    let mut buf = [0u8; 256];
    for (i, limb) in limbs.iter().enumerate() {
        buf[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&buf)
}
