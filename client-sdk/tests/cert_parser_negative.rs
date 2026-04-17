use fortgate_id::cert_parser::{parse_sat_certificate, CertParseError};

#[test]
fn invalid_der_rejected() {
    match parse_sat_certificate(&[0xff, 0x00, 0x01]) {
        Err(e) => assert!(matches!(e, CertParseError::InvalidDer)),
        Ok(_) => panic!("expected InvalidDer"),
    }
}

#[test]
fn empty_der_rejected() {
    match parse_sat_certificate(&[]) {
        Err(e) => assert!(matches!(e, CertParseError::InvalidDer)),
        Ok(_) => panic!("expected InvalidDer"),
    }
}

#[test]
fn cert_without_rfc_fails() {
    let der = include_bytes!("fixtures/cert_no_rfc.der");
    match parse_sat_certificate(der) {
        Err(e) => assert!(matches!(e, CertParseError::RfcNotFound)),
        Ok(_) => panic!("expected RfcNotFound"),
    }
}

#[test]
fn rsa_1024_rejected() {
    let der = include_bytes!("fixtures/cert_rsa1024.der");
    match parse_sat_certificate(der) {
        Err(e) => assert!(matches!(e, CertParseError::InvalidModulusBits(1024))),
        Ok(_) => panic!("expected InvalidModulusBits(1024)"),
    }
}
