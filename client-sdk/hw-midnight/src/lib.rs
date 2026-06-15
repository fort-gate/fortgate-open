//! Midnight ZK para hardware trust (`hw-trust-v1`).
//!
//! **Disclaimer:** `midnight-zk-stdlib` no está auditado para producción.
//! El nullifier Poseidon BN254 (dominio `0x4648`) se valida off-circuit hasta
//! alinear chips Poseidon con `field_encoding.rs`.

mod error;
mod provider;
mod relation;
mod srs;
mod types;
mod witness;

pub use error::HwMidnightError;
pub use provider::MidnightHwTrustProvider;
pub use relation::{HwTrustRelationV1, HwTrustWitness, P256EcdsaSig};
pub use types::{
    HwProofPackage, HwTrustCircuitInstance, HwTrustPublicInputs, CIRCUIT_VERSION, PACKAGE_VERSION,
    PROOF_PROVIDER_ID, SPKI_LEN,
};
pub use witness::{public_inputs_from_handshake, witness_from_handshake};
