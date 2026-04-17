//! Smoke test de Poseidon BN254 (`hash_2`) con el mismo pipeline conceptual que Rust (`sha256` → `bytes32_to_field`, luego `hash_2`).
//! La **igualdad byte a byte** con `fr_to_canonical_hex` / `serialize_compressed` en Ark está en [`open/client-sdk/tests/poseidon_vectors.rs`](../../client-sdk/tests/poseidon_vectors.rs) + `poseidon_vectors.json` (formato comprimido distinto a `Field::to_be_bytes` en Noir).
//!
//! Ejecutar con **Nargo 0.31.x**: `nargo test`

use std::hash::poseidon::bn254::hash_2;
use std::hash::sha256;

#[test]
fn poseidon_vectors_smoke_distinct_outputs() {
    let utf8_rfc: [u8; 18] = [
        0x56, 0x45, 0x43, 0x54, 0x4f, 0x52, 0x5f, 0x52, 0x46, 0x43, 0x5f, 0x44, 0x45, 0x4d, 0x4f,
        0x5f, 0x30, 0x31,
    ];
    let rfc_hash: [u8; 32] = sha256(utf8_rfc);
    let rfc_fr = std::field::bytes32_to_field(rfc_hash);

    let mut salt: [u8; 32] = [0; 32];
    salt[0] = 0x01;
    salt[31] = 0xab;
    let salt_fr = std::field::bytes32_to_field(salt);

    let commitment = hash_2([rfc_fr, salt_fr]);
    let domain_sep = 0x4647;
    let nullifier = hash_2([rfc_fr, domain_sep]);

    assert(commitment != nullifier);
}
