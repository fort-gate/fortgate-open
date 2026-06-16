use thiserror::Error;

#[derive(Debug, Error)]
pub enum HwMidnightError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("witness: {0}")]
    Witness(String),
    #[error("prove: {0}")]
    Prove(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("srs: {0}")]
    Srs(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("jcs: {0}")]
    Jcs(String),
    #[error("geo: {0}")]
    Geo(String),
    #[error("doc: {0}")]
    Doc(String),
}
