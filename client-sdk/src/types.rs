use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, uniffi::Enum)]
pub enum SecurityTier {
    Maximum, // StrongBox / Secure Enclave
    High,    // TEE / Keystore
    Medium,  // Software / Obfuscation
}

#[derive(Serialize, Deserialize, Debug, Clone, uniffi::Record)]
pub struct LocationConfig {
    pub target_lat: f64,
    pub target_lon: f64,
    pub tolerance_meters: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, uniffi::Record)]
pub struct LocationResult {
    pub delta_meters: f32,
    pub is_within_range: bool,
    pub hardware_verified: bool,
}
