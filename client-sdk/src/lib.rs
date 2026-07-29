// UniFFI genera `fortgate_id.uniffi.rs` con doc comments que disparan este lint.
#![allow(clippy::empty_line_after_doc_comments)]

pub mod blinded_witness;
pub mod cert_parser;
pub mod enclave_wrapper;
pub mod field_encoding;
pub mod hardware;
#[cfg(not(target_arch = "wasm32"))]
pub mod hw_trust;
pub mod types;

#[cfg(target_arch = "wasm32")]
mod wasm;

use crate::cert_parser::parse_sat_certificate;
use crate::hardware::HardwareSensor;
use crate::types::SecurityTier;

pub use cert_parser::{parse_sp1_inputs, CertParseError, Sp1CertInputs};
pub use blinded_witness::BlindedWitnessGenerator;

uniffi::include_scaffolding!("fortgate_id");

#[derive(Debug, thiserror::Error)]
pub enum FortgateError {
    #[error("Error al parsear el certificado")]
    ParseError,
    #[error("Algoritmo no soportado")]
    InvalidAlgorithm,
    #[error("RFC no encontrado")]
    RfcNotFound,
    #[error("Error criptográfico")]
    CryptoError,
}

impl From<CertParseError> for FortgateError {
    fn from(e: CertParseError) -> Self {
        match e {
            CertParseError::RfcNotFound => FortgateError::RfcNotFound,
            CertParseError::UnsupportedKey | CertParseError::InvalidExponent => {
                FortgateError::InvalidAlgorithm
            }
            CertParseError::InvalidModulusBits(_) => FortgateError::InvalidAlgorithm,
            CertParseError::InvalidSignature | CertParseError::InvalidDer => FortgateError::ParseError,
        }
    }
}

#[derive(serde::Serialize)]
pub struct BlindedWitnessPackage {
    pub rfc_commitment: String,
    pub salt: String,
    pub nullifier_hash: String,
    pub modulus_limbs: Vec<u32>,
    pub exponent: u32,
    pub detected_tier: SecurityTier,
}

pub fn create_fortgate_witness(cert_der: &[u8]) -> Result<BlindedWitnessPackage, FortgateError> {
    let cert_data = parse_sat_certificate(cert_der)?;
    let detected_tier = HardwareSensor::detect_tier();
    let mut generator = BlindedWitnessGenerator::new();
    let package = generator
        .generate_package(&cert_data.rfc, cert_data.modulus_limbs, cert_data.exponent)
        .map_err(|_| FortgateError::CryptoError)?;

    Ok(BlindedWitnessPackage {
        rfc_commitment: package.rfc_commitment,
        salt: package.salt,
        nullifier_hash: package.nullifier_hash,
        modulus_limbs: package.modulus_limbs.to_vec(),
        exponent: package.exponent,
        detected_tier,
    })
}

pub fn get_hardware_enclave() -> String {
    "SecureEnclave/StrongBox".to_string()
}

// ---------------------------------------------------------------------------
// hw-trust FFI (UniFFI) — software_poc: keygen -> challenge -> sign -> verify.
//
// Los cruces del borde son JSON string (spec §8): las funciones (de)serializan
// `MHw`/`HwHandshake` con su serde existente y delegan en `hw_trust`, así que
// los invariantes cripto (JCS, commitment, dominio del nullifier) no cambian.
// El cuerpo va gated: `hw_trust` no existe en `wasm32`.
// ---------------------------------------------------------------------------

/// Estado de la verificación local del handshake, expuesto por FFI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HwVerifyStatus {
    Green,
    Red,
}

/// Resultado de `verify_handshake_local` para el borde FFI.
#[derive(Debug, Clone)]
pub struct HwLocalVerifyResult {
    pub status: HwVerifyStatus,
    pub message: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<crate::hw_trust::HwTrustError> for FortgateError {
    fn from(_: crate::hw_trust::HwTrustError) -> Self {
        FortgateError::CryptoError
    }
}

/// Genera un par de llaves `software_poc` en `key_dir` y devuelve el SPKI DER en hex.
pub fn hw_software_keygen(key_dir: String) -> Result<String, FortgateError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::hw_trust::backends::{HwTrustBackend, SoftwarePocBackend};
        let backend = SoftwarePocBackend::new(key_dir);
        backend.keygen()?;
        Ok(hex::encode(backend.pubkey_spki_der()?))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = key_dir;
        Err(FortgateError::CryptoError)
    }
}

/// Construye un challenge `M_HW` para la llave `software_poc` de `key_dir`.
/// Devuelve el challenge serializado como JSON.
pub fn build_hw_challenge(
    key_dir: String,
    tier: SecurityTier,
    verifier_id: Option<String>,
) -> Result<String, FortgateError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::hw_trust::backends::{HwTrustBackend, SoftwarePocBackend};
        use crate::hw_trust::{HwBackend, MHw};
        let backend = SoftwarePocBackend::new(key_dir);
        let spki = backend.pubkey_spki_der()?;
        let m_hw = MHw::new_challenge(HwBackend::SoftwarePoc, tier, &spki, verifier_id)?;
        serde_json::to_string(&m_hw).map_err(|_| FortgateError::CryptoError)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (key_dir, tier, verifier_id);
        Err(FortgateError::CryptoError)
    }
}

/// Firma un challenge JSON con la llave `software_poc` de `key_dir`.
/// Devuelve el `HwHandshake` serializado como JSON.
pub fn sign_hw_challenge(challenge_json: String, key_dir: String) -> Result<String, FortgateError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::hw_trust::backends::SoftwarePocBackend;
        use crate::hw_trust::{sign_challenge_with_backend, MHw};
        let m_hw: MHw =
            serde_json::from_str(&challenge_json).map_err(|_| FortgateError::ParseError)?;
        let backend = SoftwarePocBackend::new(key_dir);
        let handshake = sign_challenge_with_backend(&backend, &m_hw)?;
        serde_json::to_string(&handshake).map_err(|_| FortgateError::CryptoError)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (challenge_json, key_dir);
        Err(FortgateError::ParseError)
    }
}

/// Verifica localmente un `HwHandshake` JSON (firma P-256, commitment, expiración).
pub fn verify_handshake_local(
    handshake_json: String,
) -> Result<HwLocalVerifyResult, FortgateError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::hw_trust::{
            verify_handshake_local as core_verify_handshake_local, HwHandshake, VerifyStatus,
        };
        let handshake: HwHandshake =
            serde_json::from_str(&handshake_json).map_err(|_| FortgateError::ParseError)?;
        let result = core_verify_handshake_local(&handshake)?;
        let status = match result.status {
            VerifyStatus::Green => HwVerifyStatus::Green,
            VerifyStatus::Red => HwVerifyStatus::Red,
        };
        Ok(HwLocalVerifyResult {
            status,
            message: result.message,
        })
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = handshake_json;
        Err(FortgateError::ParseError)
    }
}
