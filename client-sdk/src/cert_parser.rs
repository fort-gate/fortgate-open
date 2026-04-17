use num_bigint::BigUint;
use asn1_rs::oid;

/// RFC e.firma (SAT): 2.5.4.45 — usar `oid!` para evitar desajustes entre crates de OIDs.
const OID_X509_UNIQUE_IDENTIFIER: asn1_rs::Oid<'static> = oid!(2.5.4.45);

/// OpenSSL `uid=` (RFC 4519).
const OID_USERID: asn1_rs::Oid<'static> = oid!(0.9.2342.19200300.100.1.1);

/// OpenSSL `-subj "/uniqueIdentifier=..."` emite este OID (no es 2.5.4.45); hay que aceptarlo en fixtures.
const OID_OPENSSL_SUBJ_UNIQUE_IDENTIFIER: asn1_rs::Oid<'static> =
    oid!(0.9.2342.19200300.100.1.44);
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Error)]
pub enum CertParseError {
    #[error("invalid X.509 DER")]
    InvalidDer,
    #[error("not an RSA public key")]
    UnsupportedKey,
    #[error("RFC not found in subject (OIDs soportados: 2.5.4.45, uid, OpenSSL uniqueIdentifier)")]
    RfcNotFound,
    #[error("RSA modulus must be 2048 bits, got {0}")]
    InvalidModulusBits(usize),
    #[error("invalid RSA exponent")]
    InvalidExponent,
    #[error("invalid certificate signature")]
    InvalidSignature,
}

pub struct FortgateCertData {
    pub modulus_limbs: [u32; 64],
    pub exponent: u32,
    pub rfc: String,
}

/// Entradas para el guest SP1: mismo orden que el host escribe en `SP1Stdin`.
pub struct Sp1CertInputs {
    pub modulus_limbs: [u32; 64],
    pub exponent: u32,
    pub signature_limbs: [u32; 64],
    /// SHA-256 del DER de TBSCertificate (mensaje firmado RSA PKCS#1 v1.5 + SHA-256).
    pub tbs_sha256: [u8; 32],
}

pub fn parse_sat_certificate(cert_der: &[u8]) -> Result<FortgateCertData, CertParseError> {
    let cert = x509_from_der(cert_der)?;
    let (modulus_limbs, exponent, n_bits) = rsa_modulus_exponent(&cert)?;
    if n_bits != 2048 {
        return Err(CertParseError::InvalidModulusBits(n_bits));
    }
    let rfc = extract_rfc(&cert)?;
    Ok(FortgateCertData {
        modulus_limbs,
        exponent,
        rfc,
    })
}

pub fn parse_sp1_inputs(cert_der: &[u8]) -> Result<Sp1CertInputs, CertParseError> {
    let cert = x509_from_der(cert_der)?;
    let (modulus_limbs, exponent, n_bits) = rsa_modulus_exponent(&cert)?;
    if n_bits != 2048 {
        return Err(CertParseError::InvalidModulusBits(n_bits));
    }

    let mut hasher = Sha256::new();
    hasher.update(cert.tbs_certificate.as_ref());
    let tbs_sha256: [u8; 32] = hasher.finalize().into();

    let sig_bytes = cert.signature_value.data;
    if sig_bytes.is_empty() {
        return Err(CertParseError::InvalidSignature);
    }
    let s = BigUint::from_bytes_be(sig_bytes.as_ref());
    let signature_limbs = bigint_to_limbs(&s);

    Ok(Sp1CertInputs {
        modulus_limbs,
        exponent,
        signature_limbs,
        tbs_sha256,
    })
}

fn x509_from_der(cert_der: &[u8]) -> Result<X509Certificate<'_>, CertParseError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| CertParseError::InvalidDer)?;
    Ok(cert)
}

fn rsa_modulus_exponent(cert: &X509Certificate<'_>) -> Result<([u32; 64], u32, usize), CertParseError> {
    let pk = cert
        .public_key()
        .parsed()
        .map_err(|_| CertParseError::UnsupportedKey)?;
    let rsa = match pk {
        PublicKey::RSA(r) => r,
        _ => return Err(CertParseError::UnsupportedKey),
    };
    let n = BigUint::from_bytes_be(rsa.modulus);
    let exp = rsa
        .try_exponent()
        .map_err(|_| CertParseError::InvalidExponent)?;
    if exp > u64::from(u32::MAX) {
        return Err(CertParseError::InvalidExponent);
    }
    let exponent = exp as u32;
    let n_bits = n.bits() as usize;
    let modulus_limbs = bigint_to_limbs(&n);
    Ok((modulus_limbs, exponent, n_bits))
}

fn extract_rfc(cert: &X509Certificate<'_>) -> Result<String, CertParseError> {
    for attr in cert.subject().iter_attributes() {
        let t = attr.attr_type().as_bytes();
        if t == OID_X509_UNIQUE_IDENTIFIER.as_bytes()
            || t == OID_USERID.as_bytes()
            || t == OID_OPENSSL_SUBJ_UNIQUE_IDENTIFIER.as_bytes()
        {
            if let Ok(val) = attr.as_str() {
                return Ok(val.to_string());
            }
            if let Ok(val) = std::str::from_utf8(attr.as_slice()) {
                return Ok(val.to_string());
            }
        }
    }
    Err(CertParseError::RfcNotFound)
}

fn bigint_to_limbs(n: &BigUint) -> [u32; 64] {
    let mut limbs = [0u32; 64];
    let mask = BigUint::from(0xffffffffu32);
    let mut temp_n = n.clone();
    for limb in &mut limbs {
        let l = &temp_n & &mask;
        *limb = l.to_u32_digits().first().copied().unwrap_or(0);
        temp_n >>= 32;
    }
    limbs
}
