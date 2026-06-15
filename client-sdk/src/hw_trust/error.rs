use thiserror::Error;

#[derive(Debug, Error)]
pub enum HwTrustError {
    #[error("invalid hex: {0}")]
    Hex(String),
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("pubkey commitment mismatch")]
    PubkeyCommitmentMismatch,
    #[error("tier inconsistent with backend")]
    TierBackendMismatch,
    #[error("ECDSA verification failed")]
    SignatureInvalid,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JCS canonicalization failed: {0}")]
    Jcs(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("software_poc key not found at {0}; run keygen first")]
    KeyNotFound(String),
}
