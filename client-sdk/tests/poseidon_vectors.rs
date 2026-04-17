//! Vectores Poseidon alineados con `open/proto/src/main.nr` (hash_2 RFC+salt, hash_2 RFC+dominio).

use fortgate_id::BlindedWitnessGenerator;

#[test]
fn poseidon_vectors_json_matches_rust() {
    let raw = include_str!("fixtures/poseidon_vectors.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("parse poseidon_vectors.json");
    let rfc = v["rfc"].as_str().expect("rfc");
    let salt_hex = v["salt_hex"].as_str().expect("salt_hex");
    let exp_c = v["expected_rfc_commitment_hex"].as_str().expect("commitment");
    let exp_n = v["expected_nullifier_hex"].as_str().expect("nullifier");

    let salt_bytes = hex::decode(salt_hex.trim_start_matches("0x")).expect("salt hex");
    assert_eq!(salt_bytes.len(), 32, "salt must be 32 bytes");
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_bytes);

    let (c, n) =
        BlindedWitnessGenerator::commitment_nullifier_hex(rfc, &salt).expect("poseidon");
    assert_eq!(c, exp_c, "rfc_commitment mismatch");
    assert_eq!(n, exp_n, "nullifier mismatch");
}
