//! Fortgate ID — verificación RSA-2048 (PKCS#1 v1.5 + SHA-256) y binding Poseidon BN254.
//!
//! Codificación de `Field` (debe coincidir con `open/client-sdk/src/field_encoding.rs`):
//! - **RFC**: `SHA256(UTF8(RFC_string))` interpretado como entero big-endian módulo el orden del campo.
//! - **Salt**: 32 bytes aleatorios, misma regla.
//! - **Nullifier (dominio)**: escalar `0x4647` ("FG").
//!
//! Los valores `rfc` y `salt` aquí son los **escalares** `Fr` usados en Poseidon, no la cadena RFC en claro.

use dep::std;
use dep::rsa;

fn main(
    modulus: [u32; 64],
    exponent: u32,
    hashed_message: [u8; 32],
    rfc_commitment: pub Field,

    signature: [u32; 64],
    rfc: Field,
    salt: Field
) -> pub Field {
    let is_valid = rsa::verify_sha256_pkcs1v15(modulus, exponent, signature, hashed_message);
    assert(is_valid == true);

    let computed_commitment = std::hash::poseidon::bn254::hash_2([rfc, salt]);
    assert(computed_commitment == rfc_commitment);

    let domain_separator = 0x4647;
    let nullifier = std::hash::poseidon::bn254::hash_2([rfc, domain_separator]);

    nullifier
}
