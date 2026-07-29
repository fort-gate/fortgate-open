//! `android_keystore` backend for [`HwTrustBackend`].
//!
//! The Android Keystore calls live in Kotlin (see
//! `docs/HW_TRUST_ANDROID_BACKEND.md`) and reach this module through the
//! [`AndroidKeystore`] trait. Nothing here calls JNI or depends on
//! `target_os = "android"`, so it builds and is tested on the host.
//!
//! Exposing the trait over UniFFI so Kotlin can implement it is FFI
//! integration work, out of scope for this issue.

use crate::hw_trust::backends::HwTrustBackend;
use crate::hw_trust::error::HwTrustError;
use crate::hw_trust::types::HwBackend;
use crate::types::SecurityTier;
use asn1_rs::{Any, Enumerated, FromDer};
use x509_parser::prelude::X509Certificate;

/// OID of the Android key attestation extension.
const ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Android Keystore operations, implemented by the Android layer.
///
/// Every method returns empty on failure; the implementation logs the real
/// exception. An empty `cert_chain` means the device offers no attestation
/// (emulator, OEM without support), not that the key is hardware backed.
pub trait AndroidKeystore: Send + Sync {
    /// SPKI DER of the public key held under alias `fortgate_hw_poc`.
    fn spki_der(&self) -> Vec<u8>;
    /// DER-encoded ECDSA signature over an already computed digest.
    fn sign(&self, digest: Vec<u8>) -> Vec<u8>;
    /// Attestation certificate chain, leaf first.
    fn cert_chain(&self) -> Vec<Vec<u8>>;
}

pub struct AndroidKeystoreBackend {
    keystore: Box<dyn AndroidKeystore>,
}

impl AndroidKeystoreBackend {
    pub fn new(keystore: Box<dyn AndroidKeystore>) -> Self {
        Self { keystore }
    }
}

impl HwTrustBackend for AndroidKeystoreBackend {
    fn backend_id(&self) -> HwBackend {
        HwBackend::AndroidKeystore
    }

    /// Tier derived from the attestation `securityLevel`, never from the flag
    /// requested at key generation. With no readable attestation the tier
    /// falls back to `Medium`, with no implicit promotion.
    fn detect_tier(&self) -> SecurityTier {
        self.keystore
            .cert_chain()
            .first()
            .and_then(|leaf| attested_security_level(leaf))
            .map_or(SecurityTier::Medium, tier_from_security_level)
    }

    fn pubkey_spki_der(&self) -> Result<Vec<u8>, HwTrustError> {
        let spki = self.keystore.spki_der();
        if spki.is_empty() {
            return Err(HwTrustError::KeyNotFound(
                "android keystore alias fortgate_hw_poc".into(),
            ));
        }
        Ok(spki)
    }

    fn sign_challenge_hash(&self, challenge_hash: &[u8; 32]) -> Result<Vec<u8>, HwTrustError> {
        let sig = self.keystore.sign(challenge_hash.to_vec());
        if sig.is_empty() {
            return Err(HwTrustError::Crypto("android keystore sign failed".into()));
        }
        Ok(sig)
    }

    fn attestation_chain(&self) -> Option<Vec<Vec<u8>>> {
        let chain = self.keystore.cert_chain();
        (!chain.is_empty()).then_some(chain)
    }
}

/// `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1), StrongBox(2) }`
fn tier_from_security_level(level: u32) -> SecurityTier {
    match level {
        2 => SecurityTier::Maximum,
        1 => SecurityTier::High,
        _ => SecurityTier::Medium,
    }
}

/// Pulls the `securityLevel` out of the leaf certificate's attestation
/// extension.
fn attested_security_level(leaf_der: &[u8]) -> Option<u32> {
    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == ATTESTATION_OID)?;
    security_level_from_key_description(ext.value)
}

/// Reads `KeyDescription` and returns the LOWER of `attestationSecurityLevel`
/// (index 1) and `keyMintSecurityLevel` (index 3): a key cannot be stronger
/// than the attestation vouching for it.
///
/// ```text
/// KeyDescription ::= SEQUENCE {
///     attestationVersion       INTEGER,
///     attestationSecurityLevel SecurityLevel,
///     keyMintVersion           INTEGER,
///     keyMintSecurityLevel     SecurityLevel,
///     ... }
/// ```
fn security_level_from_key_description(der: &[u8]) -> Option<u32> {
    let (_, seq) = Any::from_der(der).ok()?;
    let mut rest = seq.data;
    let mut levels = Vec::with_capacity(2);
    for i in 0..4 {
        let (tail, item) = Any::from_der(rest).ok()?;
        rest = tail;
        if i == 1 || i == 3 {
            levels.push(Enumerated::try_from(item).ok()?.0);
        }
    }
    levels.into_iter().min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw_trust::m_hw::MHw;
    use crate::hw_trust::verify::VerifyStatus;
    use crate::hw_trust::{sign_challenge_with_backend, verify_handshake_local};
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    /// Minimal `KeyDescription`: the first four fields are all the tier needs.
    #[rustfmt::skip]
    fn key_description(attestation_level: u8, keymint_level: u8) -> Vec<u8> {
        let body = [
            0x02, 0x01, 0x03, // attestationVersion INTEGER 3
            0x0a, 0x01, attestation_level, // attestationSecurityLevel
            0x02, 0x01, 0x03, // keyMintVersion INTEGER 3
            0x0a, 0x01, keymint_level, // keyMintSecurityLevel
        ];
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        der
    }

    #[test]
    fn security_level_takes_the_weaker_of_the_two() {
        assert_eq!(
            security_level_from_key_description(&key_description(2, 2)),
            Some(2)
        );
        assert_eq!(
            security_level_from_key_description(&key_description(1, 1)),
            Some(1)
        );
        assert_eq!(
            security_level_from_key_description(&key_description(0, 0)),
            Some(0)
        );
        // StrongBox attestation over a key that lives in software: 0 wins.
        assert_eq!(
            security_level_from_key_description(&key_description(2, 0)),
            Some(0)
        );
        assert_eq!(
            security_level_from_key_description(&key_description(0, 2)),
            Some(0)
        );
    }

    #[test]
    fn security_level_rejects_garbage() {
        assert_eq!(security_level_from_key_description(&[]), None);
        assert_eq!(
            security_level_from_key_description(&[0x30, 0x01, 0x02]),
            None
        );
    }

    #[test]
    fn tier_mapping_matches_spec() {
        assert_eq!(tier_from_security_level(2), SecurityTier::Maximum);
        assert_eq!(tier_from_security_level(1), SecurityTier::High);
        assert_eq!(tier_from_security_level(0), SecurityTier::Medium);
        // An unknown value must not promote.
        assert_eq!(tier_from_security_level(99), SecurityTier::Medium);
    }

    /// Test keystore: software P-256, DER signatures just like Android.
    struct FakeKeystore {
        key: SigningKey,
        chain: Vec<Vec<u8>>,
    }

    impl AndroidKeystore for FakeKeystore {
        fn spki_der(&self) -> Vec<u8> {
            self.key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes()
                .to_vec()
        }

        fn sign(&self, digest: Vec<u8>) -> Vec<u8> {
            let hash: [u8; 32] = digest.try_into().unwrap();
            let sig: p256::ecdsa::Signature = self.key.sign_prehash(&hash).unwrap();
            sig.to_der().as_bytes().to_vec()
        }

        fn cert_chain(&self) -> Vec<Vec<u8>> {
            self.chain.clone()
        }
    }

    fn backend(chain: Vec<Vec<u8>>) -> AndroidKeystoreBackend {
        AndroidKeystoreBackend::new(Box::new(FakeKeystore {
            key: SigningKey::random(&mut rand::rngs::OsRng),
            chain,
        }))
    }

    #[test]
    fn no_attestation_means_medium_and_no_chain() {
        let b = backend(vec![]);
        assert_eq!(b.detect_tier(), SecurityTier::Medium);
        assert!(b.attestation_chain().is_none());
    }

    #[test]
    fn unparseable_leaf_does_not_promote() {
        let b = backend(vec![vec![0xde, 0xad, 0xbe, 0xef]]);
        assert_eq!(b.detect_tier(), SecurityTier::Medium);
        assert!(b.attestation_chain().is_some());
    }

    /// Android already emits DER, which is exactly what
    /// `verify_handshake_local` expects: no `r||s` conversion.
    #[test]
    fn handshake_roundtrip_is_green() {
        let b = backend(vec![]);
        let spki = b.pubkey_spki_der().unwrap();
        let m_hw = MHw::new_challenge(
            HwBackend::AndroidKeystore,
            SecurityTier::Medium,
            &spki,
            None,
        )
        .unwrap();
        let hs = sign_challenge_with_backend(&b, &m_hw).unwrap();
        assert_eq!(hs.backend, "android_keystore");
        assert_eq!(
            verify_handshake_local(&hs).unwrap().status,
            VerifyStatus::Green
        );
    }
}
