//! Tipos con `serde` para `SP1Stdin` / `sp1_zkvm::io::read` (bincode).
#![no_std]

extern crate alloc;

use serde::{Deserialize, Serialize};

/// Módulo o firma RSA como 64 limbs u32 little-endian (mismo layout que `fortgate-id-core`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Limbs64(#[serde(with = "serde_big_array::BigArray")] pub [u32; 64]);
