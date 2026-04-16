use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HardwareHandshake {
    pub challenge_signature: Vec<u8>,
    pub attestation_object: Vec<u8>, // El "bloque" crudo del chip
    pub public_key: Vec<u8>,
}

pub struct EnclaveWrapper;

impl EnclaveWrapper {
    /// Solicita al chip de seguridad que firme un desafío.
    /// Este método es ABIERTO para que el ecosistema pueda integrarse.
    pub fn request_hardware_signature(_challenge: &[u8]) -> HardwareHandshake {
        // En producción: llama a LocalAuthentication (iOS) o BiometricPrompt (Android)
        HardwareHandshake {
            challenge_signature: vec![], // Firmado por Secure Enclave
            attestation_object: vec![],  // Certificado de hardware
            public_key: vec![],
        }
    }
}
