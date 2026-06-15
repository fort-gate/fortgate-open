//! Prove/verify E2E — requiere SRS Filecoin (`scripts/fetch_srs.sh`).

use fortgate_hw_midnight::MidnightHwTrustProvider;
use fortgate_id::hw_trust::{
    backends::{software_poc::SoftwarePocBackend, HwTrustBackend},
    sign_challenge_with_backend, HwBackend, MHw,
};
use fortgate_id::types::SecurityTier;
use tempfile::tempdir;

#[test]
#[ignore = "requiere SRS: hw-midnight/scripts/fetch_srs.sh"]
fn midnight_prove_verify_roundtrip() {
    let dir = tempdir().unwrap();
    let backend = SoftwarePocBackend::new(dir.path());
    backend.keygen().unwrap();
    let spki = backend.pubkey_spki_der().unwrap();

    let m_hw = MHw::new_challenge(HwBackend::SoftwarePoc, SecurityTier::Medium, &spki, None).unwrap();
    let hs = sign_challenge_with_backend(&backend, &m_hw).unwrap();

    let provider = MidnightHwTrustProvider::new();
    provider.setup_keys().expect("setup vk/pk");
    let package = provider.prove_handshake(&hs).expect("prove");
    provider
        .verify_against_handshake(&package, &hs)
        .expect("verify");
}
