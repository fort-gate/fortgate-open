//! Certificado generado con OpenSSL (`uniqueIdentifier` 2.5.4.45).

use asn1_rs::FromDer;
use fortgate_id::cert_parser::parse_sat_certificate;
use x509_parser::certificate::X509Certificate;

#[test]
fn parse_mock_der_fixture() {
    let der = include_bytes!("../../../sdk-ts/tests/fixtures/mock.der");
    let (_, cert) = X509Certificate::from_der(der.as_slice()).expect("der");
    let mut found = false;
    for a in cert.subject().iter_attributes() {
        if a.as_str().ok() == Some("TESTRFC12345678901") {
            found = true;
        }
    }
    assert!(found, "expected uniqueIdentifier value in subject");
    let d = parse_sat_certificate(der).expect("parse SAT");
    assert_eq!(d.rfc, "TESTRFC12345678901");
    assert_eq!(d.modulus_limbs.len(), 64);
}
