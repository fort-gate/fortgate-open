# SP1 — Fortgate ID (guest + host)

## Versiones

- `sp1-sdk` / `sp1-zkvm` / `sp1-build`: **1.2.x** (alineado con `Cargo.lock` del workspace).
- El host **debe** compilarse en **`--release`** (el SDK emite un panic en debug si `ProverClient::new()` se usa en modo debug).

## Guest

Orden de lectura en `program/src/main.rs`:

1. `modulus_limbs: [u32; 64]`
2. `exponent: u32`
3. `signature_limbs: [u32; 64]`
4. `hashed_message: [u8; 32]` (SHA-256 del DER de TBSCertificate)
5. `rfc_commitment: [u8; 32]` (bytes canónicos del campo `Fr` del commitment Poseidon)

## Host

El script `fortgate-id-script` lee un certificado DER (argumento o `FORTGATE_CERT_DER`), usa `fortgate-id-core` para `parse_sp1_inputs` y `create_fortgate_witness`, serializa `stdin` y escribe `sp1_output/proof.bin` y `sp1_output/vkey.json`.

## Build

```bash
cd open/client-sdk/sp1-prover
cargo build --release -p fortgate-id-script
```

El `build.rs` del script invoca `sp1_build` para compilar el guest RISC-V; requiere la toolchain SP1 / `cargo prove` instalada según la documentación de Succinct.

**CI / máquinas sin toolchain Succinct:** el repositorio incluye un ELF placeholder en `program/elf/riscv32im-succinct-zkvm-elf` para que `cargo check -p fortgate-id-script` pueda enlazar el binario. Para omitir la recompilación del guest y usar solo ese placeholder:

```bash
SP1_SKIP_PROGRAM_BUILD=true cargo check -p fortgate-id-script
```

Una build real de prueba debe **sin** `SP1_SKIP_PROGRAM_BUILD`, de modo que `sp1_build` genere el ELF RISC-V y sustituya el archivo anterior.

## Ejecución

```bash
./target/release/fortgate-id-script /ruta/al/cert.der
```

Variables de entorno opcionales: `FORTGATE_CERT_DER` (ruta al DER si no se pasa argumento).
