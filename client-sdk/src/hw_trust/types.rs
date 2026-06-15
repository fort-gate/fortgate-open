use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HwBackend {
    SoftwarePoc,
    AndroidKeystore,
    IosSecureEnclave,
}

impl HwBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SoftwarePoc => "software_poc",
            Self::AndroidKeystore => "android_keystore",
            Self::IosSecureEnclave => "ios_secure_enclave",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "software_poc" => Some(Self::SoftwarePoc),
            "android_keystore" => Some(Self::AndroidKeystore),
            "ios_secure_enclave" => Some(Self::IosSecureEnclave),
            _ => None,
        }
    }
}

pub const HW_HANDSHAKE_PACKAGE_VERSION: &str = "1.0.0";
