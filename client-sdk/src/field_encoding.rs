//! Codificación de elementos BN254 (`Fr`) alineada con el circuito Noir (`Field`).
//!
//! Convención:
//! - **RFC** (cadena SAT): `UTF-8 → SHA-256 → 32 bytes → Fr` (big-endian `mod r`, igual que `ark_ff::PrimeField::from_be_bytes_mod_order`).
//! - **Salt**: 32 bytes aleatorios criptográficos → `Fr` con la misma regla.
//! - **Separador de dominio nullifier** (`0x4647`): entero pequeño → `Fr` (debe coincidir con `0x4647` en Noir).
//!
//! Los `commitment` y `nullifier` se expresan como **hex fijo de 64 caracteres** (32 bytes del campo en forma canónica comprimida).

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

/// SHA-256 del RFC en UTF-8; mismo valor que debe usarse como witness `rfc: Field` en Noir.
pub fn rfc_utf8_to_field_bytes(rfc: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rfc.as_bytes());
    hasher.finalize().into()
}

pub fn rfc_utf8_to_fr(rfc: &str) -> Fr {
    let b = rfc_utf8_to_field_bytes(rfc);
    Fr::from_be_bytes_mod_order(&b)
}

pub fn salt_bytes_to_fr(salt: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(salt)
}

pub fn domain_separator_fr() -> Fr {
    Fr::from(0x4647u64)
}

/// Serialización canónica (32 bytes comprimidos) para pruebas y SP1 `commit`.
pub fn fr_to_bytes32(fr: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut w = &mut out[..];
    fr.serialize_compressed(&mut w)
        .expect("serialize Fr");
    out
}

pub fn fr_to_canonical_hex(fr: &Fr) -> String {
    hex::encode(fr_to_bytes32(fr))
}

pub fn hex_decode_fr_bytes(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim_start_matches("0x")).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err("expected 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_serialize::CanonicalDeserialize;

    #[test]
    fn fr_hex_roundtrip() {
        let fr = rfc_utf8_to_fr("RFC-DEMO-123");
        let h = fr_to_canonical_hex(&fr);
        let bytes = hex_decode_fr_bytes(&h).expect("hex");
        let fr2 = Fr::deserialize_compressed(&mut &bytes[..]).expect("deserialize");
        assert_eq!(fr, fr2);
    }
}
