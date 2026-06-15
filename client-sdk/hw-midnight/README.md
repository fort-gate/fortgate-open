# fortgate-hw-midnight

Proveedor Midnight (`hw-trust-v1`) para el PoC de hardware trust.

**Disclaimer:** `midnight-zk-stdlib` no está auditado para producción.

## Circuito

Demuestra en ZK:

1. `SHA-256(pubkey_spki_der) == pubkey_commitment`
2. `ECDSA_P256_VERIFY(pubkey, challenge_hash, signature)` (prehash)

El `hw_nullifier` (Poseidon BN254, dominio `0x4648`) y el `tier` se validan **off-circuit** al verificar el paquete.

## Setup SRS (una vez)

```bash
chmod +x scripts/fetch_srs.sh
./scripts/fetch_srs.sh
# opcional: export FORTGATE_SRS_DIR=/ruta/a/assets
```

## CLI

```bash
cd open/client-sdk/hw-midnight
cargo run --bin fortgate-hw-poc -- demo --tmp /tmp/fg-hw-demo
```

Subcomandos: `keygen`, `challenge`, `sign`, `verify-local`, `prove`, `verify`, `demo`.

## Prove / verify programático

```rust
use fortgate_hw_midnight::MidnightHwTrustProvider;

let provider = MidnightHwTrustProvider::new();
provider.setup_keys()?;
let package = provider.prove_handshake(&handshake)?;
provider.verify_against_handshake(&package, &handshake)?;
```
