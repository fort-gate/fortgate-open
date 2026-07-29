//! Golden fixtures para `hw-trust-v1` — checks rápidos y deterministas SIN SRS.
//!
//! Estos tests NO están `#[ignore]`: corren en `cargo test` normal y fallan si
//! el encoding de `public_inputs`, la derivación off-circuit del `hw_nullifier`
//! o la verificación local del handshake cambian ("drift").
//!
//! El path completo de prove/verify vive en `prove_verify.rs` detrás de
//! `#[ignore]` + SRS.
//!
//! ## Regenerar los fixtures
//!
//! ```bash
//! cargo test --test golden_fixtures regenerate_golden_fixtures -- --ignored --exact
//! ```
//!
//! Eso reescribe `tests/fixtures/hw_trust_handshake.json` y
//! `tests/fixtures/hw_trust_public_inputs.json` a partir del backend
//! `software_poc`. Commiteá los dos archivos resultantes.

use fortgate_hw_midnight::{public_inputs_from_handshake, HwTrustPublicInputs};
use fortgate_id::hw_trust::{
    backends::{software_poc::SoftwarePocBackend, HwTrustBackend},
    hw_nullifier_hex, pubkey_commitment_bytes, sign_challenge_with_backend, verify_handshake_local,
    HwBackend, HwHandshake, MHw, VerifyStatus,
};
use fortgate_id::types::SecurityTier;
use std::path::{Path, PathBuf};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn handshake_path() -> PathBuf {
    fixtures_dir().join("hw_trust_handshake.json")
}

fn public_inputs_path() -> PathBuf {
    fixtures_dir().join("hw_trust_public_inputs.json")
}

fn load_handshake() -> HwHandshake {
    let raw = std::fs::read_to_string(handshake_path()).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer {}: {e}. Regenerá con: \
             cargo test --test golden_fixtures regenerate_golden_fixtures -- --ignored --exact",
            handshake_path().display()
        )
    });
    serde_json::from_str(&raw).expect("handshake fixture inválido")
}

fn load_expected_public_inputs() -> HwTrustPublicInputs {
    let raw = std::fs::read_to_string(public_inputs_path()).unwrap_or_else(|e| {
        panic!(
            "no se pudo leer {}: {e}. Regenerá con: \
             cargo test --test golden_fixtures regenerate_golden_fixtures -- --ignored --exact",
            public_inputs_path().display()
        )
    });
    serde_json::from_str(&raw).expect("public_inputs fixture inválido")
}

/// Handshake `software_poc` reproducible para regenerar los fixtures.
fn software_handshake(dir: &Path) -> HwHandshake {
    let backend = SoftwarePocBackend::new(dir);
    backend.keygen().unwrap();
    let spki = backend.pubkey_spki_der().unwrap();
    let m_hw =
        MHw::new_challenge(HwBackend::SoftwarePoc, SecurityTier::Medium, &spki, None).unwrap();
    sign_challenge_with_backend(&backend, &m_hw).unwrap()
}

// ---------------------------------------------------------------------------
// Regenerador (ignored): produce los fixtures golden.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "regenera fixtures golden; correr a mano tras cambios de encoding"]
fn regenerate_golden_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let hs = software_handshake(dir.path());
    let public_inputs = public_inputs_from_handshake(&hs).expect("derivar public_inputs");

    std::fs::create_dir_all(fixtures_dir()).unwrap();

    let hs_json = serde_json::to_string_pretty(&hs).unwrap();
    std::fs::write(handshake_path(), format!("{hs_json}\n")).unwrap();

    let pi_json = serde_json::to_string_pretty(&public_inputs).unwrap();
    std::fs::write(public_inputs_path(), format!("{pi_json}\n")).unwrap();

    eprintln!("fixtures escritos en {}", fixtures_dir().display());
}

// ---------------------------------------------------------------------------
// Tests rápidos (no-ignored): guardan contra drift de encoding/binding.
// ---------------------------------------------------------------------------

/// Falla si la DERIVACIÓN de public_inputs desde el handshake cambia.
#[test]
fn public_inputs_derivation_matches_fixture() {
    let hs = load_handshake();
    let expected = load_expected_public_inputs();
    let derived = public_inputs_from_handshake(&hs).expect("derivar public_inputs");
    assert_eq!(
        derived, expected,
        "public_inputs derivados del handshake divergen del fixture golden"
    );
}

/// Falla si el ENCODING (serde/camelCase/orden de campos) de public_inputs cambia.
///
/// Compara los bytes canónicos serializados contra el fixture en disco, así que
/// un rename de campo, un cambio de tipo o de `rename_all` rompe el test.
#[test]
fn public_inputs_encoding_is_stable() {
    let expected = load_expected_public_inputs();
    let reserialized = serde_json::to_string_pretty(&expected).unwrap();
    let on_disk = std::fs::read_to_string(public_inputs_path()).unwrap();
    assert_eq!(
        format!("{reserialized}\n"),
        on_disk,
        "el encoding JSON de HwTrustPublicInputs cambió respecto al fixture golden"
    );
}

/// Falla si el binding off-circuit del `hw_nullifier` (Poseidon BN254, dominio
/// 0x4648) cambia.
#[test]
fn nullifier_binding_matches_fixture() {
    let hs = load_handshake();
    let spki = hex::decode(hs.pubkey_spki_der.trim()).expect("spki hex");
    let commitment = pubkey_commitment_bytes(&spki);
    let expected_nullifier = hw_nullifier_hex(&commitment).expect("nullifier");
    assert_eq!(
        expected_nullifier, hs.hw_nullifier,
        "hw_nullifier recomputado no coincide con el handshake golden"
    );
}

/// La verificación local del handshake (firma P-256, commitment) debe pasar sin SRS.
#[test]
fn handshake_local_verify_is_green() {
    let hs = load_handshake();
    let result = verify_handshake_local(&hs).expect("verify local");
    assert_eq!(
        result.status,
        VerifyStatus::Green,
        "verificación local del handshake golden no es Green: {}",
        result.message
    );
}
