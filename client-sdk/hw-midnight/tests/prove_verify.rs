//! Prove/verify E2E — requiere SRS Filecoin (`scripts/fetch_srs.sh`).

use fortgate_hw_midnight::{
    demo_manifest, sign_doc_manifest, CreditSignProver, MidnightHwTrustProvider,
};
use fortgate_id::hw_trust::{
    backends::{software_poc::SoftwarePocBackend, HwTrustBackend},
    sign_challenge_with_backend, HwBackend, MHw,
};
use fortgate_id::types::SecurityTier;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn software_handshake(dir: &std::path::Path) -> fortgate_id::hw_trust::HwHandshake {
    let backend = SoftwarePocBackend::new(dir);
    backend.keygen().unwrap();
    let spki = backend.pubkey_spki_der().unwrap();
    let m_hw =
        MHw::new_challenge(HwBackend::SoftwarePoc, SecurityTier::Medium, &spki, None).unwrap();
    sign_challenge_with_backend(&backend, &m_hw).unwrap()
}

#[test]
#[ignore = "requiere SRS: hw-midnight/scripts/fetch_srs.sh"]
fn midnight_prove_verify_roundtrip() {
    let dir = tempdir().unwrap();
    let hs = software_handshake(dir.path());

    let provider = MidnightHwTrustProvider::new();
    provider.setup_keys().expect("setup vk/pk");
    let package = provider.prove_handshake(&hs).expect("prove");
    provider
        .verify_against_handshake(&package, &hs)
        .expect("verify");
}

#[test]
#[ignore = "requiere SRS: hw-midnight/scripts/fetch_srs.sh"]
fn prove_all_three_circuits_roundtrip() {
    let dir = tempdir().unwrap();
    let backend = SoftwarePocBackend::new(dir.path());
    backend.keygen().unwrap();
    let spki = backend.pubkey_spki_der().unwrap();
    let m_hw =
        MHw::new_challenge(HwBackend::SoftwarePoc, SecurityTier::Medium, &spki, None).unwrap();
    let hs = sign_challenge_with_backend(&backend, &m_hw).unwrap();

    let pdf_hash = Sha256::digest(b"fortgate-hw-midnight-test-pdf");
    let manifest = demo_manifest(&hex::encode(pdf_hash));
    let doc_record = sign_doc_manifest(&backend, &manifest, &hs.hw_nullifier).unwrap();

    let prover = CreditSignProver::new();
    prover.setup_all_keys().expect("setup 3 vk/pk");
    let evidence = prover
        .prove_all(&hs, &doc_record, 19.4326, -99.1332)
        .expect("prove_all");
    prover
        .verify_all(&evidence, &hs, &doc_record)
        .expect("verify_all");
}

#[test]
#[ignore = "requiere SRS: hw-midnight/scripts/fetch_srs.sh"]
fn bank_verifier_green_roundtrip() {
    use fortgate_hw_midnight::{
        build_verify_request, CreditSignVerifier, InstitutionPolicy, VerifyResponse,
    };

    let dir = tempdir().unwrap();
    let backend = SoftwarePocBackend::new(dir.path());
    backend.keygen().unwrap();
    let spki = backend.pubkey_spki_der().unwrap();
    let m_hw =
        MHw::new_challenge(HwBackend::SoftwarePoc, SecurityTier::Medium, &spki, None).unwrap();
    let hs = sign_challenge_with_backend(&backend, &m_hw).unwrap();

    let pdf_hash = Sha256::digest(b"fortgate-bank-verify-test");
    let manifest = demo_manifest(&hex::encode(pdf_hash));
    let doc_record = sign_doc_manifest(&backend, &manifest, &hs.hw_nullifier).unwrap();

    let prover = CreditSignProver::new();
    prover.setup_all_keys().expect("setup keys");
    let evidence = prover
        .prove_all(&hs, &doc_record, 19.4326, -99.1332)
        .expect("prove_all");

    let request = build_verify_request(evidence, hs, doc_record, 19.4326, -99.1332);
    let policy = InstitutionPolicy::poc_default();
    let verifier = CreditSignVerifier::new();
    match verifier.verify_request(&request, &policy) {
        VerifyResponse::Green(_) => {}
        other => panic!("expected GREEN, got {other:?}"),
    }
}

#[test]
#[ignore = "requiere SRS: hw-midnight/scripts/fetch_srs.sh"]
fn tampered_hw_nullifier_fails() {
    let dir = tempdir().unwrap();
    let hs = software_handshake(dir.path());

    let provider = MidnightHwTrustProvider::new();
    provider.setup_keys().expect("setup vk/pk");

    let mut public_inputs =
        fortgate_hw_midnight::public_inputs_from_handshake(&hs).expect("public inputs");
    public_inputs.hw_nullifier[0] ^= 0xFF;
    let witness = fortgate_hw_midnight::witness_from_handshake(&hs).expect("witness");

    match provider.prove(&public_inputs, witness) {
        Err(_) => {} // circuit correctly rejected the tampered instance during proving
        Ok(package) => {
            // if proving didn't reject it outright, verification against the
            // tampered public input must still fail
            assert!(
                provider.verify_package(&package).is_err(),
                "verify no debe aceptar un hw_nullifier alterado"
            );
        }
    }
}
