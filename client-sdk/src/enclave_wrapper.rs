//! Deprecated hardware-handshake stub.
//!
//! `EnclaveWrapper` / `HardwareHandshake` predate the real hardware-trust
//! integration and originally returned empty vectors for every field. The
//! authoritative implementation now lives in [`crate::hw_trust`] (see
//! `docs/HW_TRUST_POC_SPEC.md` § 3.1 and § 4): use
//! [`crate::hw_trust::backends::HwTrustBackend`] implementations together with
//! [`crate::hw_trust::sign_challenge_with_backend`] for new integrations.
//!
//! This module is kept only for source compatibility with existing callers.
//! On non-wasm32 targets it is a thin wrapper around `hw_trust`'s
//! `SoftwarePocBackend` rather than a no-op; on wasm32 (where `hw_trust` is
//! not yet built, see `client-sdk/src/lib.rs`) it still returns empty
//! vectors, since there is no backend to delegate to. New code should not
//! rely on either the empty-vector fallback or this module and should call
//! `hw_trust` directly.

use serde::{Deserialize, Serialize};

#[deprecated(
    since = "0.2.0",
    note = "Use `hw_trust::HwHandshake` instead; see docs/HW_TRUST_POC_SPEC.md"
)]
#[derive(Serialize, Deserialize, Debug)]
pub struct HardwareHandshake {
    pub challenge_signature: Vec<u8>,
    pub attestation_object: Vec<u8>, // El "bloque" crudo del chip
    pub public_key: Vec<u8>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `hw_trust::HwTrustBackend` (e.g. `hw_trust::default_software_backend()`) instead; see docs/HW_TRUST_POC_SPEC.md"
)]
pub struct EnclaveWrapper;

#[allow(deprecated)]
impl EnclaveWrapper {
    /// Solicita al chip de seguridad que firme un desafío.
    ///
    /// Deprecated: delegates to `hw_trust`'s software PoC backend on
    /// non-wasm32 targets instead of returning empty vectors. Prefer calling
    /// `hw_trust::sign_challenge_with_backend` directly, which returns a
    /// proper `Result` instead of silently falling back to empty fields.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn request_hardware_signature(challenge: &[u8]) -> HardwareHandshake {
        let backend = crate::hw_trust::default_software_backend();
        sign_via_software_poc(&backend, challenge)
    }

    /// wasm32 has no `hw_trust` backend to delegate to (see
    /// `client-sdk/src/lib.rs`), so the stub keeps its original empty-vector
    /// behavior here until a wasm-compatible backend exists.
    #[cfg(target_arch = "wasm32")]
    pub fn request_hardware_signature(_challenge: &[u8]) -> HardwareHandshake {
        HardwareHandshake {
            challenge_signature: vec![],
            attestation_object: vec![],
            public_key: vec![],
        }
    }
}

#[allow(deprecated)]
#[cfg(not(target_arch = "wasm32"))]
fn sign_via_software_poc(
    backend: &crate::hw_trust::backends::SoftwarePocBackend,
    challenge: &[u8],
) -> HardwareHandshake {
    use crate::hw_trust::backends::HwTrustBackend;
    use sha2::{Digest, Sha256};

    let empty = || HardwareHandshake {
        challenge_signature: vec![],
        attestation_object: vec![],
        public_key: vec![],
    };

    let spki = match backend.pubkey_spki_der() {
        Ok(spki) => spki,
        Err(_) => match backend.keygen() {
            Ok(_) => match backend.pubkey_spki_der() {
                Ok(spki) => spki,
                Err(_) => return empty(),
            },
            Err(_) => return empty(),
        },
    };

    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let challenge_hash: [u8; 32] = hasher.finalize().into();

    let challenge_signature = match backend.sign_challenge_hash(&challenge_hash) {
        Ok(sig) => sig,
        Err(_) => return empty(),
    };

    let attestation_object = backend
        .attestation_chain()
        .and_then(|chain| chain.into_iter().next())
        .unwrap_or_default();

    HardwareHandshake {
        challenge_signature,
        attestation_object,
        public_key: spki,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::hw_trust::backends::SoftwarePocBackend;
    use tempfile::tempdir;

    #[test]
    fn deprecated_wrapper_no_longer_returns_empty_vectors() {
        let dir = tempdir().unwrap();
        let backend = SoftwarePocBackend::new(dir.path());
        backend.keygen().unwrap();

        let handshake = sign_via_software_poc(&backend, b"test-challenge");

        assert!(!handshake.challenge_signature.is_empty());
        assert!(!handshake.public_key.is_empty());
    }

    #[test]
    fn deprecated_wrapper_auto_provisions_key_when_missing() {
        let dir = tempdir().unwrap();
        let backend = SoftwarePocBackend::new(dir.path());

        let handshake = sign_via_software_poc(&backend, b"test-challenge");

        assert!(!handshake.challenge_signature.is_empty());
        assert!(!handshake.public_key.is_empty());
    }
}
