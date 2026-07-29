// UniFFI genera `fortgate_id.uniffi.rs` con doc comments que disparan este lint.
#![allow(clippy::empty_line_after_doc_comments)]

pub mod blinded_witness;
pub mod cert_parser;
/// Deprecated hardware-handshake stub; see [`hw_trust`] for the current API.
pub mod enclave_wrapper;
pub mod field_encoding;
pub mod hardware;
/// Hardware-trust handshake: the recommended entrypoint for hardware
/// attestation/signing (see `docs/HW_TRUST_POC_SPEC.md`). Supersedes the
/// deprecated [`enclave_wrapper`] stub.
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

/// Recommended entrypoint for hardware attestation/signing; supersedes the
/// deprecated [`enclave_wrapper`] stub.
#[cfg(not(target_arch = "wasm32"))]
pub use hw_trust::{
    backends::HwTrustBackend, default_software_backend, sign_challenge_with_backend, HwHandshake,
};

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
