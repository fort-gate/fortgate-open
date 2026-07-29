use crate::error::HwMidnightError;
use crate::key_cache::{optimal_k_cached, srs_or_init};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::utils::SerdeFormat;
use midnight_zk_stdlib::utils::plonk_api::filecoin_srs;
use midnight_zk_stdlib::Relation;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn default_srs_dir() -> PathBuf {
    std::env::var("FORTGATE_SRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets"))
}

/// Loads the Filecoin SRS (BLS12-381) trimmed to the relation's optimal `k`.
///
/// The result is cached by `k`, so reading and trimming the SRS happens once per process
/// even when `prove_all` generates three proofs. Circuits sharing the same `k` (today
/// `hw-trust-v1` and `doc-bind-v1`, both at 16) also share the cache entry.
pub fn load_srs_for_relation<R: Relation + 'static>(
    relation: &R,
) -> Result<Arc<ParamsKZG<midnight_curves::Bls12>>, HwMidnightError> {
    let k = optimal_k_cached(relation);
    srs_or_init(k, || {
        let srs_dir = default_srs_dir();
        std::env::set_var("SRS_DIR", srs_dir.to_string_lossy().to_string());

        if !srs_dir.exists() {
            std::fs::create_dir_all(&srs_dir).map_err(HwMidnightError::Io)?;
        }

        let marker = srs_dir.join(format!("bls_filecoin_2p{k}"));
        let root = srs_dir.join("bls_filecoin_2p19");
        if !marker.exists() && !root.exists() {
            return Err(HwMidnightError::Srs(format!(
                "SRS no encontrado en {}. Ejecuta: open/client-sdk/hw-midnight/scripts/fetch_srs.sh",
                srs_dir.display()
            )));
        }

        Ok(filecoin_srs(k))
    })
}

pub fn vkeys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vkeys")
}

pub fn vk_path() -> PathBuf {
    vkeys_dir().join("hw-trust-v1.vk")
}

pub fn pk_path() -> PathBuf {
    vkeys_dir().join("hw-trust-v1.pk")
}

pub fn ensure_parent(path: &Path) -> Result<(), HwMidnightError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(HwMidnightError::Io)?;
    }
    Ok(())
}

pub const VK_SERDE: SerdeFormat = SerdeFormat::RawBytes;
