use crate::error::HwMidnightError;
use crate::relation::{HwTrustWitness, P256EcdsaSig};
use crate::types::{HwTrustPublicInputs, SPKI_LEN};
use fortgate_id::hw_trust::{parse_tier, verify_handshake_local, HwHandshake, VerifyStatus};
use fortgate_id::types::SecurityTier;
use midnight_circuits::CircuitField;
use midnight_curves::p256::{Fq as P256Scalar, P256};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use p256::EncodedPoint;

pub fn public_inputs_from_handshake(hs: &HwHandshake) -> Result<HwTrustPublicInputs, HwMidnightError> {
    let challenge_hash = hex_fixed32(&hs.challenge_hash)?;
    let pubkey_commitment = hex_fixed32(&hs.pubkey_commitment)?;
    let hw_nullifier = hex_fixed32(&hs.hw_nullifier)?;
    let tier = parse_tier(&hs.tier)
        .ok_or_else(|| HwMidnightError::Handshake(format!("tier desconocido: {}", hs.tier)))?;
    Ok(HwTrustPublicInputs {
        challenge_hash,
        pubkey_commitment,
        hw_nullifier,
        tier: tier_to_u8(tier),
    })
}

pub fn witness_from_handshake(hs: &HwHandshake) -> Result<HwTrustWitness, HwMidnightError> {
    let local = verify_handshake_local(hs).map_err(|e| HwMidnightError::Handshake(e.to_string()))?;
    if local.status != VerifyStatus::Green {
        return Err(HwMidnightError::Witness(format!(
            "handshake inválido antes de prove: {}",
            local.message
        )));
    }

    let spki = hex::decode(hs.pubkey_spki_der.trim())
        .map_err(|e| HwMidnightError::Hex(e.to_string()))?;
    if spki.len() != SPKI_LEN {
        return Err(HwMidnightError::Witness(format!(
            "SPKI debe ser {SPKI_LEN} bytes (got {})",
            spki.len()
        )));
    }
    let mut spki_der = [0u8; SPKI_LEN];
    spki_der.copy_from_slice(&spki);

    let sig_der = hex::decode(hs.signature_der.trim())
        .map_err(|e| HwMidnightError::Hex(e.to_string()))?;
    let signature = p256_ecdsa_sig_from_der(&sig_der)?;

    let vk = VerifyingKey::from_public_key_der(&spki)
        .map_err(|e| HwMidnightError::Witness(format!("SPKI inválido: {e}")))?;
    let pubkey = encoded_point_to_p256(vk.to_encoded_point(false))?;

    Ok(HwTrustWitness {
        spki_der,
        signature,
        pubkey,
    })
}

pub(crate) fn p256_ecdsa_sig_from_der(der: &[u8]) -> Result<P256EcdsaSig, HwMidnightError> {
    let sig = Signature::from_der(der)
        .map_err(|e| HwMidnightError::Witness(format!("DER firma inválida: {e}")))?;
    let bytes = sig.to_bytes();
    let mut r_be = [0u8; 32];
    let mut s_be = [0u8; 32];
    r_be.copy_from_slice(&bytes[..32]);
    s_be.copy_from_slice(&bytes[32..]);

    let mut r_le = r_be;
    r_le.reverse();

    let s = P256Scalar::from_bytes_be(&s_be)
        .ok_or_else(|| HwMidnightError::Witness("escalar s inválido".into()))?;

    Ok(P256EcdsaSig { r_le, s })
}

fn encoded_point_to_p256(point: EncodedPoint) -> Result<P256, HwMidnightError> {
    let x_bytes = point
        .x()
        .ok_or_else(|| HwMidnightError::Witness("coordenada x ausente".into()))?;
    let y_bytes = point
        .y()
        .ok_or_else(|| HwMidnightError::Witness("coordenada y ausente".into()))?;

    let x = midnight_curves::p256::Fp::from_bytes_be(x_bytes)
        .ok_or_else(|| HwMidnightError::Witness("x inválida".into()))?;
    let y = midnight_curves::p256::Fp::from_bytes_be(y_bytes)
        .ok_or_else(|| HwMidnightError::Witness("y inválida".into()))?;

    midnight_curves::p256::affine_from_xy(x, y)
        .map(Into::into)
        .ok_or_else(|| HwMidnightError::Witness("punto fuera de curva".into()))
}

fn hex_fixed32(s: &str) -> Result<[u8; 32], HwMidnightError> {
    let v = hex::decode(s.trim()).map_err(|e| HwMidnightError::Hex(e.to_string()))?;
    if v.len() != 32 {
        return Err(HwMidnightError::Hex(format!("expected 32 bytes, got {}", v.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn tier_to_u8(tier: SecurityTier) -> u8 {
    match tier {
        SecurityTier::Medium => 0,
        SecurityTier::High => 1,
        SecurityTier::Maximum => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fortgate_id::hw_trust::{
        backends::software_poc::SoftwarePocBackend,
        backends::HwTrustBackend,
        sign_challenge_with_backend,
        MHw,
    };
    use tempfile::tempdir;

    #[test]
    fn witness_from_roundtrip_handshake() {
        let dir = tempdir().unwrap();
        let backend = SoftwarePocBackend::new(dir.path());
        backend.keygen().unwrap();
        let spki = backend.pubkey_spki_der().unwrap();
        assert_eq!(spki.len(), SPKI_LEN);

        let m_hw = MHw::new_challenge(
            fortgate_id::hw_trust::HwBackend::SoftwarePoc,
            SecurityTier::Medium,
            &spki,
            None,
        )
        .unwrap();
        let hs = sign_challenge_with_backend(&backend, &m_hw).unwrap();
        let wit = witness_from_handshake(&hs).unwrap();
        assert_eq!(wit.spki_der.as_slice(), spki.as_slice());
        let pi = public_inputs_from_handshake(&hs).unwrap();
        assert_eq!(pi.challenge_hash, m_hw.challenge_hash().unwrap());
    }
}
