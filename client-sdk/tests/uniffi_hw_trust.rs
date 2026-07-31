//! Round-trip FFI de hw-trust con `software_poc`, sin SRS ni prove.
//!
//! keygen -> build_hw_challenge -> sign_hw_challenge -> verify_handshake_local.

use fortgate_id::types::SecurityTier;
use fortgate_id::{
    build_hw_challenge, hw_software_keygen, sign_hw_challenge, verify_handshake_local,
    HwVerifyStatus,
};
use tempfile::tempdir;

#[test]
fn hw_trust_ffi_round_trip_software_poc() {
    let dir = tempdir().unwrap();
    let key_dir = dir.path().to_str().unwrap().to_string();

    // keygen -> SPKI DER hex (91 bytes P-256 => 182 hex chars).
    let spki_hex = hw_software_keygen(key_dir.clone()).expect("keygen");
    assert_eq!(spki_hex.len(), 182, "SPKI P-256 debe ser 91 bytes");

    // build challenge (JSON de M_HW).
    let challenge_json =
        build_hw_challenge(key_dir.clone(), SecurityTier::Medium, None).expect("challenge");
    assert!(challenge_json.contains("challengeId"));
    assert!(challenge_json.contains("software_poc"));

    // sign -> handshake JSON.
    let handshake_json = sign_hw_challenge(challenge_json, key_dir).expect("sign");
    assert!(handshake_json.contains("hwNullifier"));

    // verify local -> Green.
    let result = verify_handshake_local(handshake_json).expect("verify");
    assert_eq!(
        result.status,
        HwVerifyStatus::Green,
        "verify local no es Green: {}",
        result.message
    );
}

#[test]
fn verify_handshake_local_rejects_garbage() {
    let err = verify_handshake_local("{not valid handshake}".to_string());
    assert!(err.is_err(), "un handshake inválido debe fallar el parseo");
}
