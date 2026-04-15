use x509_parser::prelude::*;
use anyhow::{Result, anyhow};

pub struct CertData {
    pub common_name: String,
    pub serial_number: String,
    pub raw_bytes: Vec<u8>,
}

pub fn parse_certificate(cert_bytes: &[u8]) -> Result<CertData> {
    let (_, cert) = X509Certificate::from_der(cert_bytes)
        .map_err(|_| anyhow!("Failed to parse X.509 certificate"))?;

    let common_name = cert.subject().iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    Ok(CertData {
        common_name,
        serial_number: cert.serial().to_string(),
        raw_bytes: cert_bytes.to_vec(),
    })
}
