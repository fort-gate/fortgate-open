// UniFFI genera `fortgate_id.uniffi.rs` con doc comments que disparan este lint.
#![allow(clippy::empty_line_after_doc_comments)]

pub mod blinded_witness;
pub mod cert_parser;
pub mod enclave_wrapper;
pub mod field_encoding;
pub mod hardware;
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
